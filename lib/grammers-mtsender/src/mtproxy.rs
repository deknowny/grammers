use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use sha2::{Digest, Sha256};
use std::cmp;
use std::collections::VecDeque;
use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub(crate) enum MtProxyMode {
    Obfuscated,
    FakeTls { domain: String },
}

#[derive(Debug, Clone)]
pub(crate) struct MtProxyConfig {
    pub host: String,
    pub port: u16,
    pub secret: Vec<u8>,
    pub mode: MtProxyMode,
}

impl MtProxyConfig {
    pub fn parse(url: &str) -> Option<io::Result<Self>> {
        if url.starts_with("tg://proxy?") || url.starts_with("https://t.me/proxy?") {
            return Some(Self::parse_tg_proxy(url));
        }
        if url.starts_with("mtproxy://") {
            return Some(Self::parse_mtproxy(url));
        }
        None
    }

    fn parse_tg_proxy(url: &str) -> io::Result<Self> {
        let query = url
            .split_once('?')
            .map(|(_, query)| query)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "mtproxy query is missing"))?;
        let mut host = None;
        let mut port = None;
        let mut secret = None;
        for part in query.split('&') {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            match key {
                "server" => host = Some(percent_decode(value)),
                "port" => port = Some(parse_port(value)?),
                "secret" => secret = Some(percent_decode(value)),
                _ => {}
            }
        }
        Self::from_parts(
            host.ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "mtproxy host missing"))?,
            port.ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "mtproxy port missing"))?,
            &secret
                .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "mtproxy secret missing"))?,
        )
    }

    fn parse_mtproxy(url: &str) -> io::Result<Self> {
        let rest = url
            .strip_prefix("mtproxy://")
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid mtproxy url"))?;
        if let Some((authority, query)) = rest.split_once('?') {
            let mut host = None;
            let mut port = None;
            let mut secret = None;

            for part in query.split('&') {
                let Some((key, value)) = part.split_once('=') else {
                    continue;
                };
                match key {
                    "server" => host = Some(percent_decode(value)),
                    "port" => port = Some(parse_port(value)?),
                    "secret" | "s" => secret = Some(percent_decode(value)),
                    _ => {}
                }
            }

            let (host, port) = if authority.contains(':') {
                parse_host_port(authority)?
            } else {
                (
                    host.ok_or_else(|| {
                        io::Error::new(ErrorKind::InvalidData, "mtproxy host missing")
                    })?,
                    port.ok_or_else(|| {
                        io::Error::new(ErrorKind::InvalidData, "mtproxy port missing")
                    })?,
                )
            };
            let secret = secret
                .or_else(|| (!authority.contains(':')).then(|| authority.to_string()))
                .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "mtproxy secret missing"))?;
            return Self::from_parts(host, port, &secret);
        }

        let (endpoint, secret) = rest
            .split_once('/')
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "mtproxy secret missing"))?;
        let (host, port) = parse_host_port(endpoint)?;
        Self::from_parts(host, port, secret)
    }

    fn from_parts(host: String, port: u16, encoded_secret: &str) -> io::Result<Self> {
        let secret = decode_secret(encoded_secret)?;
        let mode = if secret.len() >= 18 && secret[0] == 0xee {
            let domain = String::from_utf8(secret[17..].to_vec())
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid mtproxy domain"))?;
            MtProxyMode::FakeTls { domain }
        } else {
            MtProxyMode::Obfuscated
        };
        Ok(Self {
            host,
            port,
            secret,
            mode,
        })
    }

    fn proxy_secret(&self) -> io::Result<[u8; 16]> {
        let slice = if self.secret.len() >= 17 {
            &self.secret[1..17]
        } else {
            &self.secret[..]
        };
        slice
            .try_into()
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid mtproxy secret length"))
    }
}

pub struct MtProxyStream {
    stream: TcpStream,
    read_cipher: AesCtr,
    write_cipher: AesCtr,
    strip_intermediate_init: bool,
    tls_mode: bool,
    tls_first_write: bool,
    tls_raw_read: Vec<u8>,
    tls_plain_read: VecDeque<u8>,
    initial_header: Vec<u8>,
    write_pending: Vec<u8>,
    write_pending_pos: usize,
    write_pending_original_len: usize,
}

impl MtProxyStream {
    pub(crate) async fn connect(
        addr: std::net::SocketAddr,
        config: &MtProxyConfig,
        dc_id: i16,
    ) -> io::Result<Self> {
        let mut stream = TcpStream::connect(addr).await?;
        let proxy_secret = config.proxy_secret()?;
        if let MtProxyMode::FakeTls { domain } = &config.mode {
            init_fake_tls(&mut stream, domain, &proxy_secret).await?;
        }
        let (header, read_cipher, write_cipher) = make_obfuscated_header(&proxy_secret, dc_id)?;
        let tls_mode = matches!(config.mode, MtProxyMode::FakeTls { .. });
        let initial_header = if tls_mode {
            header
        } else {
            tokio::io::AsyncWriteExt::write_all(&mut stream, &header).await?;
            Vec::new()
        };

        Ok(Self {
            stream,
            read_cipher,
            write_cipher,
            strip_intermediate_init: true,
            tls_mode,
            tls_first_write: true,
            tls_raw_read: Vec::new(),
            tls_plain_read: VecDeque::new(),
            initial_header,
            write_pending: Vec::new(),
            write_pending_pos: 0,
            write_pending_original_len: 0,
        })
    }

    pub fn split(&mut self) -> (MtProxyReadHalf<'_>, MtProxyWriteHalf<'_>) {
        let (read, write) = self.stream.split();
        (
            MtProxyReadHalf {
                inner: read,
                cipher: &mut self.read_cipher,
                tls_mode: self.tls_mode,
                tls_raw: &mut self.tls_raw_read,
                tls_plain: &mut self.tls_plain_read,
            },
            MtProxyWriteHalf {
                inner: write,
                cipher: &mut self.write_cipher,
                strip_intermediate_init: &mut self.strip_intermediate_init,
                tls_mode: self.tls_mode,
                tls_first_write: &mut self.tls_first_write,
                initial_header: &mut self.initial_header,
                pending: &mut self.write_pending,
                pending_pos: &mut self.write_pending_pos,
                pending_original_len: &mut self.write_pending_original_len,
            },
        )
    }

}

pub struct MtProxyReadHalf<'a> {
    inner: ReadHalf<'a>,
    cipher: &'a mut AesCtr,
    tls_mode: bool,
    tls_raw: &'a mut Vec<u8>,
    tls_plain: &'a mut VecDeque<u8>,
}

impl AsyncRead for MtProxyReadHalf<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.tls_mode {
            let before = buf.filled().len();
            let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
            if let Poll::Ready(Ok(())) = &poll {
                let after = buf.filled().len();
                if after > before {
                    self.cipher.apply(&mut buf.filled_mut()[before..after]);
                }
            }
            return poll;
        }

        if !self.tls_plain.is_empty() {
            drain_plain(self.tls_plain, buf);
            return Poll::Ready(Ok(()));
        }

        let mut tmp = [0u8; 8192];
        let mut tmp_buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Ready(Ok(())) => {
                if tmp_buf.filled().is_empty() {
                    return Poll::Ready(Ok(()));
                }
                self.tls_raw.extend_from_slice(tmp_buf.filled());
                let mut raw = std::mem::take(self.tls_raw);
                let mut plain = std::mem::take(self.tls_plain);
                let parsed = parse_tls_records(&mut raw, &mut plain, self.cipher);
                *self.tls_raw = raw;
                *self.tls_plain = plain;
                if let Err(err) = parsed {
                    return Poll::Ready(Err(err));
                }
                drain_plain(self.tls_plain, buf);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct MtProxyWriteHalf<'a> {
    inner: WriteHalf<'a>,
    cipher: &'a mut AesCtr,
    strip_intermediate_init: &'a mut bool,
    tls_mode: bool,
    tls_first_write: &'a mut bool,
    initial_header: &'a mut Vec<u8>,
    pending: &'a mut Vec<u8>,
    pending_pos: &'a mut usize,
    pending_original_len: &'a mut usize,
}

impl AsyncWrite for MtProxyWriteHalf<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.pending.is_empty() {
            return match self.flush_pending(cx) {
                Poll::Ready(Ok(written)) => {
                    if written > 0 && *self.strip_intermediate_init {
                        *self.strip_intermediate_init = false;
                    }
                    Poll::Ready(Ok(written))
                }
                other => other,
            };
        }

        let data =
            if *self.strip_intermediate_init && buf.starts_with(&0xee_ee_ee_ee_u32.to_le_bytes()) {
                &buf[4..]
            } else {
                buf
            };
        let mut encrypted = data.to_vec();
        self.cipher.apply(&mut encrypted);
        if !self.initial_header.is_empty() {
            let mut with_header = std::mem::take(self.initial_header);
            with_header.extend_from_slice(&encrypted);
            encrypted = with_header;
        }
        let transformed = if self.tls_mode {
            wrap_tls_records(&encrypted, self.tls_first_write)
        } else {
            encrypted
        };
        *self.pending = transformed;
        *self.pending_pos = 0;
        *self.pending_original_len = if data.len() != buf.len() {
            buf.len()
        } else {
            data.len()
        };

        match self.flush_pending(cx) {
            Poll::Ready(Ok(written)) => {
                if written > 0 && *self.strip_intermediate_init {
                    *self.strip_intermediate_init = false;
                }
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl MtProxyWriteHalf<'_> {
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        while *self.pending_pos < self.pending.len() {
            let chunk = &self.pending[*self.pending_pos..];
            match Pin::new(&mut self.inner).poll_write(cx, chunk) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::WriteZero,
                        "failed to write mtproxy frame",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    *self.pending_pos += written;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.pending.clear();
        *self.pending_pos = 0;
        let original_len = *self.pending_original_len;
        *self.pending_original_len = 0;
        Poll::Ready(Ok(original_len))
    }
}

struct AesCtr {
    cipher: Aes256,
    counter: [u8; 16],
    block: [u8; 16],
    offset: usize,
}

impl AesCtr {
    fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Aes256::new(GenericArray::from_slice(key)),
            counter: *iv,
            block: [0; 16],
            offset: 16,
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.offset == 16 {
                self.block = self.counter;
                self.cipher
                    .encrypt_block(GenericArray::from_mut_slice(&mut self.block));
                increment_be(&mut self.counter);
                self.offset = 0;
            }
            *byte ^= self.block[self.offset];
            self.offset += 1;
        }
    }
}

fn make_obfuscated_header(secret: &[u8; 16], dc_id: i16) -> io::Result<(Vec<u8>, AesCtr, AesCtr)> {
    let mut header = [0u8; 64];
    loop {
        getrandom::getrandom(&mut header)
            .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;
        if header[0] == 0xef {
            continue;
        }
        let first = u32::from_le_bytes(header[0..4].try_into().unwrap());
        if first == 0x4441_4548
            || first == 0x5453_4f50
            || first == 0x2054_4547
            || first == 0x4954_504f
            || first == 0xeeee_eeee
            || first == 0xdddd_dddd
        {
            continue;
        }
        if header[4..8] == [0; 4] {
            continue;
        }
        break;
    }

    header[56..60].copy_from_slice(&0xee_ee_ee_ee_u32.to_le_bytes());
    if dc_id != 0 {
        header[60..62].copy_from_slice(&dc_id.to_le_bytes());
    }

    let mut write_key = [0u8; 32];
    write_key.copy_from_slice(&header[8..40]);
    write_key = fixed_proxy_key(write_key, secret);
    let write_iv: [u8; 16] = header[40..56].try_into().unwrap();

    let mut reversed = [0u8; 64];
    for (dst, src) in reversed.iter_mut().zip(header.iter().rev()) {
        *dst = *src;
    }

    let mut read_key = [0u8; 32];
    read_key.copy_from_slice(&reversed[8..40]);
    read_key = fixed_proxy_key(read_key, secret);
    let read_iv: [u8; 16] = reversed[40..56].try_into().unwrap();

    let mut write_cipher = AesCtr::new(&write_key, &write_iv);
    let mut encrypted_header = header;
    write_cipher.apply(&mut encrypted_header);
    header[56..64].copy_from_slice(&encrypted_header[56..64]);

    Ok((
        header.to_vec(),
        AesCtr::new(&read_key, &read_iv),
        write_cipher,
    ))
}

fn fixed_proxy_key(key: [u8; 32], secret: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(secret);
    hasher.finalize().into()
}

fn drain_plain(plain: &mut VecDeque<u8>, buf: &mut ReadBuf<'_>) {
    let len = cmp::min(buf.remaining(), plain.len());
    if len == 0 {
        return;
    }
    let mut chunk = Vec::with_capacity(len);
    for _ in 0..len {
        if let Some(byte) = plain.pop_front() {
            chunk.push(byte);
        }
    }
    buf.put_slice(&chunk);
}

fn parse_tls_records(
    raw: &mut Vec<u8>,
    plain: &mut VecDeque<u8>,
    cipher: &mut AesCtr,
) -> io::Result<()> {
    loop {
        if raw.len() < 5 {
            return Ok(());
        }
        if raw[0..3] != [0x17, 0x03, 0x03] {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid mtproxy faketls record",
            ));
        }
        let len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
        if raw.len() < 5 + len {
            return Ok(());
        }
        let mut payload = raw[5..5 + len].to_vec();
        cipher.apply(&mut payload);
        plain.extend(payload);
        raw.drain(..5 + len);
    }
}

fn wrap_tls_records(data: &[u8], first_write: &mut bool) -> Vec<u8> {
    const MAX_TLS_PACKET_LENGTH: usize = 2878;

    let mut out = Vec::with_capacity(data.len() + data.len() / MAX_TLS_PACKET_LENGTH * 5 + 11);
    if *first_write {
        out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        *first_write = false;
    }

    for chunk in data.chunks(MAX_TLS_PACKET_LENGTH) {
        out.extend_from_slice(&[0x17, 0x03, 0x03]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

async fn init_fake_tls(stream: &mut TcpStream, domain: &str, secret: &[u8; 16]) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if domain.is_empty() || domain.len() > 182 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid mtproxy faketls domain",
        ));
    }

    let hello = make_tls_client_hello(domain, secret)?;
    let hello_rand = hello[11..43].to_vec();
    stream.write_all(&hello).await?;

    let mut response = Vec::with_capacity(1024);
    let consumed = loop {
        let mut tmp = [0u8; 1024];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "mtproxy faketls closed during hello",
            ));
        }
        response.extend_from_slice(&tmp[..n]);
        if let Some(consumed) = fake_tls_hello_response_len(&response)? {
            break consumed;
        }
    };

    let mut checked = response[..consumed].to_vec();
    if checked.len() < 43 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "mtproxy faketls response is too short",
        ));
    }
    let response_rand = checked[11..43].to_vec();
    checked[11..43].fill(0);

    let mut hmac_input = Vec::with_capacity(hello_rand.len() + checked.len());
    hmac_input.extend_from_slice(&hello_rand);
    hmac_input.extend_from_slice(&checked);
    if hmac_sha256(secret, &hmac_input) != response_rand.as_slice() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "mtproxy faketls response hash mismatch",
        ));
    }

    if consumed != response.len() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "mtproxy faketls response has unexpected trailing data",
        ));
    }

    Ok(())
}

fn fake_tls_hello_response_len(data: &[u8]) -> io::Result<Option<usize>> {
    let mut offset = 0usize;
    for prefix in [
        &b"\x16\x03\x03"[..],
        &b"\x14\x03\x03\x00\x01\x01\x17\x03\x03"[..],
    ] {
        if data.len() < offset + prefix.len() + 2 {
            return Ok(None);
        }
        if &data[offset..offset + prefix.len()] != prefix {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid mtproxy faketls hello response",
            ));
        }
        offset += prefix.len();
        let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if data.len() < offset + len {
            return Ok(None);
        }
        offset += len;
    }
    Ok(Some(offset))
}

fn make_tls_client_hello(domain: &str, secret: &[u8; 16]) -> io::Result<Vec<u8>> {
    const TLS_REQUEST_LENGTH: usize = 517;

    let mut greases = [0u8; 7];
    random_bytes(&mut greases)?;
    for grease in &mut greases {
        *grease = (*grease & 0xf0) + 0x0a;
    }
    for i in (1..greases.len()).step_by(2) {
        if greases[i] == greases[i - 1] {
            greases[i] ^= 0x10;
        }
    }

    let mut out = Vec::with_capacity(TLS_REQUEST_LENGTH);
    out.extend_from_slice(&[
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
    ]);
    push_random(&mut out, 32)?;
    out.push(0x20);
    push_random(&mut out, 32)?;
    out.extend_from_slice(&[0x00, 0x22]);
    push_grease_value(&mut out, greases[0]);
    out.extend_from_slice(&[
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc,
        0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
        0x00, 0x0a, 0x01, 0x00, 0x01, 0x91,
    ]);
    push_grease_value(&mut out, greases[2]);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    push_u16(&mut out, domain.len() + 5);
    push_u16(&mut out, domain.len() + 3);
    out.push(0);
    push_u16(&mut out, domain.len());
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(&[
        0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08,
    ]);
    push_grease_value(&mut out, greases[4]);
    out.extend_from_slice(&[
        0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p',
        b'/', b'1', b'.', b'1', 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d,
        0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05,
        0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x33, 0x00, 0x2b,
        0x00, 0x29,
    ]);
    push_grease_value(&mut out, greases[4]);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x20]);
    push_random(&mut out, 32)?;
    out.extend_from_slice(&[
        0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00, 0x0b, 0x0a,
    ]);
    push_grease_value(&mut out, greases[6]);
    out.extend_from_slice(&[
        0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x1b, 0x00, 0x03, 0x02, 0x00, 0x02,
    ]);
    push_grease_value(&mut out, greases[3]);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x15]);

    if out.len() + 2 > TLS_REQUEST_LENGTH {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "mtproxy faketls domain is too long",
        ));
    }
    let padding_length = TLS_REQUEST_LENGTH - 2 - out.len();
    push_u16(&mut out, padding_length);
    out.resize(TLS_REQUEST_LENGTH, 0);

    let mut hmac_input = out.clone();
    hmac_input[11..43].fill(0);
    let hash = hmac_sha256(secret, &hmac_input);
    out[11..43].copy_from_slice(&hash);
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let mut tail = u32::from_le_bytes(out[39..43].try_into().unwrap());
    tail ^= unix_time;
    out[39..43].copy_from_slice(&tail.to_le_bytes());

    Ok(out)
}

fn push_random(out: &mut Vec<u8>, len: usize) -> io::Result<()> {
    let offset = out.len();
    out.resize(offset + len, 0);
    random_bytes(&mut out[offset..])
}

fn push_u16(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u16).to_be_bytes());
}

fn push_grease_value(out: &mut Vec<u8>, grease: u8) {
    out.extend_from_slice(&[grease, grease]);
}

fn random_bytes(dest: &mut [u8]) -> io::Result<()> {
    getrandom::getrandom(dest).map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn increment_be(counter: &mut [u8; 16]) {
    for byte in counter.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

fn decode_secret(encoded_secret: &str) -> io::Result<Vec<u8>> {
    let encoded_secret = encoded_secret.trim();
    let secret = hex_decode(encoded_secret)
        .or_else(|| base64_url_decode(encoded_secret))
        .or_else(|| base64_standard_decode(encoded_secret))
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid mtproxy secret"))?;
    if secret.len() == 16
        || (secret.len() == 17 && secret[0] == 0xdd)
        || (secret.len() >= 18 && secret[0] == 0xee)
    {
        return Ok(secret);
    }
    Err(io::Error::new(
        ErrorKind::InvalidData,
        "unsupported mtproxy secret",
    ))
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let mut i = 0;
    while i < value.len() {
        let byte = u8::from_str_radix(&value[i..i + 2], 16).ok()?;
        out.push(byte);
        i += 2;
    }
    Some(out)
}

fn base64_url_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()
}

fn base64_standard_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(value).ok()
}

fn parse_host_port(endpoint: &str) -> io::Result<(String, u16)> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "proxy port missing"))?;
    Ok((host.to_string(), parse_port(port)?))
}

fn parse_port(value: &str) -> io::Result<u16> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid proxy port"))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_faketls_proxy_and_builds_sni_hello() {
        let config = MtProxyConfig::parse(
            "tg://proxy?server=white.mtproxy.pw&port=443&secret=ee3f8a91c2d7e04b6a9f12c5e8370bd4aa786170692e6f7a6f6e2e7275",
        )
        .expect("mtproxy url")
        .expect("valid mtproxy");

        assert_eq!(config.host, "white.mtproxy.pw");
        assert_eq!(config.port, 443);
        let MtProxyMode::FakeTls { domain } = &config.mode else {
            panic!("expected faketls");
        };
        assert_eq!(domain, "xapi.ozon.ru");

        let secret = config.proxy_secret().expect("proxy secret");
        let hello = make_tls_client_hello(domain, &secret).expect("client hello");

        assert_eq!(hello.len(), 517);
        assert!(hello.starts_with(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc]));
        assert_eq!(&hello[43..44], &[0x20]);
        assert_eq!(&hello[76..78], &[0x00, 0x22]);
        assert_eq!(hello[78], hello[79]);
        assert_eq!(hello[78] & 0x0f, 0x0a);
        assert!(hello
            .windows(domain.len())
            .any(|chunk| chunk == domain.as_bytes()));
        assert_ne!(&hello[11..43], &[0u8; 32]);

        let mut checked = hello.clone();
        let digest = checked[11..43].to_vec();
        checked[11..43].fill(0);
        let expected = hmac_sha256(&secret, &checked);
        assert_eq!(&digest[..28], &expected[..28]);
        let timestamp = u32::from_le_bytes([
            digest[28] ^ expected[28],
            digest[29] ^ expected[29],
            digest[30] ^ expected[30],
            digest[31] ^ expected[31],
        ]);
        assert!(timestamp > 1_700_000_000);
    }

    #[test]
    fn obfuscated_header_carries_dc_id() {
        let secret = [0x3f; 16];
        let (header, _, _) = make_obfuscated_header(&secret, 2).expect("obfuscated header");

        let mut key = [0u8; 32];
        key.copy_from_slice(&header[8..40]);
        key = fixed_proxy_key(key, &secret);
        let iv: [u8; 16] = header[40..56].try_into().unwrap();
        let mut cipher = AesCtr::new(&key, &iv);
        let mut prefix = [0u8; 56];
        cipher.apply(&mut prefix);
        let mut tail = header[56..64].to_vec();
        cipher.apply(&mut tail);

        assert_eq!(&tail[0..4], &0xee_ee_ee_ee_u32.to_le_bytes());
        assert_eq!(&tail[4..6], &2_i16.to_le_bytes());
    }
}
