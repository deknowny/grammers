// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(unsafe_code)]

mod errors;
mod mtproxy;
mod reconnection;

pub use crate::reconnection::*;
pub use errors::{AuthorizationError, InvocationError, ReadError, RpcError};

use bytes::{Buf as _, BytesMut};
use futures_util::future::{pending, select, Either};
use grammers_crypto::DequeBuffer;
use grammers_mtproto::mtp::{
    self, BadMessage, Deserialization, DeserializationFailure, Mtp, RpcResult, RpcResultError,
};
use grammers_mtproto::transport::{self, Transport};
use grammers_mtproto::{authentication, MsgId};
use grammers_tl_types::{self as tl, Deserializable, RemoteCall};
use log::{debug, error, info, trace, warn};
use std::io;
use std::io::Error;
use std::ops::ControlFlow;
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicI64, Ordering};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tl::Serializable;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::time::{sleep_until, Duration, Instant};

#[cfg(feature = "proxy")]
use {
    crate::mtproxy::{MtProxyConfig, MtProxyReadHalf, MtProxyStream, MtProxyWriteHalf},
    std::io::ErrorKind,
    std::net::{IpAddr, SocketAddr},
    tokio_socks::tcp::Socks5Stream,
    trust_dns_resolver::config::{ResolverConfig, ResolverOpts},
    trust_dns_resolver::AsyncResolver,
    url::Host,
};

/// Hard upper bound for how much we are willing to buffer in memory for a single connection.
/// This is NOT pre-allocated.
const MAXIMUM_DATA: usize = (1024 * 1024) + (8 * 1024);

/// How much leading space should be reserved in a buffer to avoid moving memory.
const LEADING_BUFFER_SPACE: usize = mtp::MAX_TRANSPORT_HEADER_LEN
    + mtp::ENCRYPTED_PACKET_HEADER_LEN
    + mtp::PLAIN_PACKET_HEADER_LEN
    + mtp::MESSAGE_CONTAINER_HEADER_LEN;

/// Every how often are pings sent?
const PING_DELAY: Duration = Duration::from_secs(60);

/// After how many seconds should the server close the connection when we send a ping?
const NO_PING_DISCONNECT: i32 = 75;

/// Read buffer starts small and grows as needed (no 1MB prealloc).
const READ_INITIAL_CAPACITY: usize = 16 * 1024;
/// If we had a one-off huge receive, drop capacity afterwards.
const READ_SHRINK_THRESHOLD: usize = 256 * 1024;

/// Write buffer also starts small (DequeBuffer grows automatically via Vec).
const WRITE_INITIAL_BACK_CAPACITY: usize = 64 * 1024;
/// If we just sent something huge, recreate the buffer to drop Vec capacity.
const WRITE_SHRINK_ON_SEND_OVER: usize = 256 * 1024;

/// Generate a "random" ping ID.
pub(crate) fn generate_random_id() -> i64 {
    static LAST_ID: AtomicI64 = AtomicI64::new(0);

    if LAST_ID.load(Ordering::SeqCst) == 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before epoch")
            .as_nanos() as i64;

        LAST_ID
            .compare_exchange(0, now, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap();
    }

    LAST_ID.fetch_add(1, Ordering::SeqCst)
}

pub enum NetStream {
    Tcp(TcpStream),
    #[cfg(feature = "proxy")]
    ProxySocks5(Socks5Stream<TcpStream>),
    #[cfg(feature = "proxy")]
    ProxyMtProxy(MtProxyStream),
}

impl NetStream {
    pub fn split(&mut self) -> (NetReadHalf<'_>, NetWriteHalf<'_>) {
        match self {
            Self::Tcp(stream) => {
                let (read, write) = stream.split();
                (NetReadHalf::Tcp(read), NetWriteHalf::Tcp(write))
            }
            #[cfg(feature = "proxy")]
            Self::ProxySocks5(stream) => {
                let (read, write) = stream.split();
                (NetReadHalf::Socks5(read), NetWriteHalf::Socks5(write))
            }
            #[cfg(feature = "proxy")]
            Self::ProxyMtProxy(stream) => {
                let (read, write) = stream.split();
                (NetReadHalf::MtProxy(read), NetWriteHalf::MtProxy(write))
            }
        }
    }
}

pub enum NetReadHalf<'a> {
    Tcp(ReadHalf<'a>),
    #[cfg(feature = "proxy")]
    Socks5(ReadHalf<'a>),
    #[cfg(feature = "proxy")]
    MtProxy(MtProxyReadHalf<'a>),
}

impl AsyncRead for NetReadHalf<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(read) => Pin::new(read).poll_read(cx, buf),
            #[cfg(feature = "proxy")]
            Self::Socks5(read) => Pin::new(read).poll_read(cx, buf),
            #[cfg(feature = "proxy")]
            Self::MtProxy(read) => Pin::new(read).poll_read(cx, buf),
        }
    }
}

pub enum NetWriteHalf<'a> {
    Tcp(WriteHalf<'a>),
    #[cfg(feature = "proxy")]
    Socks5(WriteHalf<'a>),
    #[cfg(feature = "proxy")]
    MtProxy(MtProxyWriteHalf<'a>),
}

impl AsyncWrite for NetWriteHalf<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Tcp(write) => Pin::new(write).poll_write(cx, buf),
            #[cfg(feature = "proxy")]
            Self::Socks5(write) => Pin::new(write).poll_write(cx, buf),
            #[cfg(feature = "proxy")]
            Self::MtProxy(write) => Pin::new(write).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(write) => Pin::new(write).poll_flush(cx),
            #[cfg(feature = "proxy")]
            Self::Socks5(write) => Pin::new(write).poll_flush(cx),
            #[cfg(feature = "proxy")]
            Self::MtProxy(write) => Pin::new(write).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Tcp(write) => Pin::new(write).poll_shutdown(cx),
            #[cfg(feature = "proxy")]
            Self::Socks5(write) => Pin::new(write).poll_shutdown(cx),
            #[cfg(feature = "proxy")]
            Self::MtProxy(write) => Pin::new(write).poll_shutdown(cx),
        }
    }
}

// Manages enqueuing requests, matching them to their response, and IO.

pub struct Sender<T: Transport, M: Mtp> {
    pub stream: NetStream,
    transport: T,
    mtp: M,
    addr: std::net::SocketAddr,

    #[cfg(feature = "proxy")]
    proxy_url: Option<String>,
    #[cfg(feature = "proxy")]
    proxy_dc_id: i16,

    pub requests: Vec<Request>,
    request_rx: mpsc::UnboundedReceiver<Request>,
    next_ping: Instant,
    reconnection_policy: &'static dyn ReconnectionPolicy,

    // READ: grow-on-demand, keep only unread tail, no prealloc of MAXIMUM_DATA.
    read_buf: BytesMut,

    // WRITE: grow-on-demand via Vec growth inside DequeBuffer, no prealloc of MAXIMUM_DATA.
    pub write_buffer: DequeBuffer<u8>,
    pub write_head: usize,
}

pub struct Request {
    body: Vec<u8>,
    state: RequestState,
    result: oneshot::Sender<Result<Vec<u8>, InvocationError>>,
}

#[derive(Clone, Copy, Debug)]
struct MsgIdPair {
    msg_id: MsgId,
    container_msg_id: MsgId,
}

enum RequestState {
    NotSerialized,
    Serialized(MsgIdPair),
    Sent(MsgIdPair),
}

pub struct Enqueuer(mpsc::UnboundedSender<Request>);

impl MsgIdPair {
    fn new(msg_id: MsgId) -> Self {
        Self {
            msg_id,
            container_msg_id: msg_id, // by default, no container
        }
    }
}

impl Enqueuer {
    /// Enqueue a Remote Procedure Call to be sent in future calls to `step`.
    pub fn enqueue<R: RemoteCall>(
        &self,
        request: &R,
    ) -> oneshot::Receiver<Result<Vec<u8>, InvocationError>> {
        let body = request.to_bytes();
        assert!(body.len() >= 4);
        let req_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        debug!(
            "enqueueing request {} to be serialized",
            tl::name_for_id(req_id)
        );

        let (tx, rx) = oneshot::channel();
        if let Err(err) = self.0.send(Request {
            body,
            state: RequestState::NotSerialized,
            result: tx,
        }) {
            err.0.result.send(Err(InvocationError::Dropped)).unwrap();
        }
        rx
    }
}

impl<T: Transport, M: Mtp> Sender<T, M> {
    async fn connect(
        transport: T,
        mtp: M,
        addr: std::net::SocketAddr,
        reconnection_policy: &'static dyn ReconnectionPolicy,
    ) -> Result<(Self, Enqueuer), io::Error> {
        let stream = connect_stream(&addr).await?;
        let (tx, rx) = mpsc::unbounded_channel();
        Ok((
            Self {
                stream,
                transport,
                mtp,
                addr,
                #[cfg(feature = "proxy")]
                proxy_url: None,
                #[cfg(feature = "proxy")]
                proxy_dc_id: 0,
                requests: vec![],
                request_rx: rx,
                next_ping: Instant::now() + PING_DELAY,
                reconnection_policy,

                read_buf: BytesMut::with_capacity(READ_INITIAL_CAPACITY),

                write_buffer: DequeBuffer::with_capacity(
                    WRITE_INITIAL_BACK_CAPACITY,
                    LEADING_BUFFER_SPACE,
                ),
                write_head: 0,
            },
            Enqueuer(tx),
        ))
    }

    #[cfg(feature = "proxy")]
    async fn connect_via_proxy(
        transport: T,
        mtp: M,
        addr: SocketAddr,
        proxy_dc_id: i16,
        proxy_url: &str,
        reconnection_policy: &'static dyn ReconnectionPolicy,
    ) -> Result<(Self, Enqueuer), io::Error> {
        info!("connecting...");
        let stream = connect_proxy_stream(&addr, proxy_url, proxy_dc_id).await?;
        let (tx, rx) = mpsc::unbounded_channel();
        Ok((
            Self {
                stream,
                transport,
                mtp,
                addr,
                proxy_url: Some(proxy_url.to_string()),
                proxy_dc_id,
                requests: vec![],
                request_rx: rx,
                next_ping: Instant::now() + PING_DELAY,
                reconnection_policy,

                read_buf: BytesMut::with_capacity(READ_INITIAL_CAPACITY),

                write_buffer: DequeBuffer::with_capacity(
                    WRITE_INITIAL_BACK_CAPACITY,
                    LEADING_BUFFER_SPACE,
                ),
                write_head: 0,
            },
            Enqueuer(tx),
        ))
    }

    pub async fn invoke<R: RemoteCall>(&mut self, request: &R) -> Result<Vec<u8>, InvocationError> {
        let rx = self.enqueue_body(request.to_bytes());
        self.step_until_receive(rx).await
    }

    /// Like `invoke` but raw data.
    async fn send(&mut self, body: Vec<u8>) -> Result<Vec<u8>, InvocationError> {
        let rx = self.enqueue_body(body);
        self.step_until_receive(rx).await
    }

    fn enqueue_body(
        &mut self,
        body: Vec<u8>,
    ) -> oneshot::Receiver<Result<Vec<u8>, InvocationError>> {
        assert!(body.len() >= 4);
        let req_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        debug!(
            "enqueueing request {} to be serialized",
            tl::name_for_id(req_id)
        );

        let (tx, rx) = oneshot::channel();
        self.requests.push(Request {
            body,
            state: RequestState::NotSerialized,
            result: tx,
        });
        rx
    }

    async fn step_until_receive(
        &mut self,
        mut rx: oneshot::Receiver<Result<Vec<u8>, InvocationError>>,
    ) -> Result<Vec<u8>, InvocationError> {
        loop {
            self.step().await.map_err(InvocationError::from)?;
            match rx.try_recv() {
                Ok(x) => break x,
                Err(TryRecvError::Empty) => continue,
                Err(TryRecvError::Closed) => {
                    panic!("request channel dropped before receiving a result")
                }
            }
        }
    }

    /// Step network events, writing and reading at the same time.
    ///
    /// Updates received during this step, if any, are returned.
    pub async fn step(&mut self) -> Result<Vec<tl::enums::Updates>, ReadError> {
        enum Sel {
            Sleep,
            Request(Option<Request>),
            Read(io::Result<usize>),
            Write(io::Result<usize>),
        }

        self.try_fill_write();
        let write_len = self.write_buffer.len().saturating_sub(self.write_head);
        trace!(
            "reading bytes and sending up to {} bytes via network",
            write_len
        );

        let (mut reader, mut writer) = self.stream.split();
        let sel = {
            let sleep = pin!(async { sleep_until(self.next_ping).await });
            let recv_req = pin!(async { self.request_rx.recv().await });

            let recv_data = pin!(async {
                if self.read_buf.len() >= MAXIMUM_DATA {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "incoming buffer exceeds MAXIMUM_DATA",
                    ));
                }
                // Reserve in small chunks (no huge prealloc).
                self.read_buf.reserve(16 * 1024);
                reader.read_buf(&mut self.read_buf).await
            });

            let send_data = pin!(async {
                if self.write_buffer.is_empty() {
                    pending().await
                } else {
                    writer.write(&self.write_buffer[self.write_head..]).await
                }
            });

            match select(select(sleep, recv_req), select(recv_data, send_data)).await {
                Either::Left((Either::Left(_), _)) => Sel::Sleep,
                Either::Left((Either::Right((request, _)), _)) => Sel::Request(request),
                Either::Right((Either::Left((n, _)), _)) => Sel::Read(n),
                Either::Right((Either::Right((n, _)), _)) => Sel::Write(n),
            }
        };

        let res = match sel {
            Sel::Request(request) => {
                self.requests.push(request.unwrap());
                Ok(Vec::new())
            }
            Sel::Read(n) => n.map_err(ReadError::Io).and_then(|n| self.on_net_read(n)),
            Sel::Write(n) => n.map_err(ReadError::Io).map(|n| {
                self.on_net_write(n);
                Vec::new()
            }),
            Sel::Sleep => {
                self.on_ping_timeout();
                Ok(Vec::new())
            }
        };

        match res {
            Ok(ok) => Ok(ok),
            Err(err) => self.on_error(err).await,
        }
    }

    #[allow(unused_variables)]
    async fn try_connect(&mut self) -> Result<(), Error> {
        let mut attempts = 0;
        loop {
            #[cfg(feature = "proxy")]
            let res = if self.proxy_url.is_some() {
                connect_proxy_stream(
                    &self.addr,
                    self.proxy_url.as_ref().unwrap(),
                    self.proxy_dc_id,
                )
                .await
            } else {
                connect_stream(&self.addr).await
            };

            #[cfg(not(feature = "proxy"))]
            let res = connect_stream(&self.addr).await;

            match res {
                Ok(result) => {
                    log::info!(
                        "auto-reconnect success after {} failed attempt(s)",
                        attempts
                    );
                    self.stream = result;
                    return Ok(());
                }
                Err(e) => {
                    attempts += 1;
                    log::warn!("auto-reconnect failed {} time(s): {}", attempts, e);
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    match self.reconnection_policy.should_retry(attempts) {
                        ControlFlow::Break(_) => {
                            log::error!(
                                "attempted more than {} times for reconnection and failed",
                                attempts
                            );
                            return Err(e);
                        }
                        ControlFlow::Continue(duration) => tokio::time::sleep(duration).await,
                    }
                }
            }
        }
    }

    /// Setup the write buffer for the transport, unless a write is already pending.
    fn try_fill_write(&mut self) {
        if !self.write_buffer.is_empty() {
            return;
        }

        for request in self
            .requests
            .iter_mut()
            .filter(|r| matches!(r.state, RequestState::NotSerialized))
        {
            // DequeBuffer grows automatically; no need to prealloc MAXIMUM_DATA.
            if let Some(msg_id) = self.mtp.push(&mut self.write_buffer, &request.body) {
                assert!(request.body.len() >= 4);
                let req_id = u32::from_le_bytes([
                    request.body[0],
                    request.body[1],
                    request.body[2],
                    request.body[3],
                ]);
                debug!(
                    "serialized request {:x} ({}) with {:?}",
                    req_id,
                    tl::name_for_id(req_id),
                    msg_id
                );
                request.state = RequestState::Serialized(MsgIdPair::new(msg_id));
            } else {
                break;
            }
        }

        if let Some(container_msg_id) = self.mtp.finalize(&mut self.write_buffer) {
            for request in self.requests.iter_mut() {
                match &mut request.state {
                    RequestState::Serialized(pair) => {
                        pair.container_msg_id = container_msg_id;
                    }
                    RequestState::NotSerialized | RequestState::Sent(..) => {}
                }
            }
            self.transport.pack(&mut self.write_buffer)
        }
    }

    /// Handle `n` more read bytes being ready to process by the transport.
    ///
    /// This keeps only the unread tail in memory. Large frames do not "break" the logic:
    /// we keep buffering until `transport.unpack` stops returning `MissingBytes`, up to MAXIMUM_DATA.
    fn on_net_read(&mut self, n: usize) -> Result<Vec<tl::enums::Updates>, ReadError> {
        if n == 0 {
            return Err(ReadError::Io(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "read 0 bytes",
            )));
        }

        trace!("read {} bytes from the network", n);
        trace!(
            "trying to unpack buffer of {} bytes...",
            self.read_buf.len()
        );

        let mut updates = Vec::new();
        let mut consumed = 0usize;

        loop {
            let buf = &self.read_buf[consumed..];
            if buf.is_empty() {
                break;
            }

            match self.transport.unpack(buf) {
                Ok(offset) => {
                    debug!("deserializing valid transport packet...");
                    let payload = &buf[offset.data_start..offset.data_end];
                    let result = self.mtp.deserialize(payload)?;
                    self.process_mtp_buffer(result, &mut updates);

                    consumed = consumed.checked_add(offset.next_offset).ok_or_else(|| {
                        ReadError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "overflow while advancing read buffer",
                        ))
                    })?;

                    if consumed > self.read_buf.len() {
                        return Err(ReadError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "transport.unpack consumed beyond buffer",
                        )));
                    }
                }
                Err(transport::Error::MissingBytes) => break,
                Err(err) => return Err(err.into()),
            }
        }

        if consumed > 0 {
            self.read_buf.advance(consumed);

            // If we had a large one-off packet, don't keep huge capacity forever.
            if self.read_buf.is_empty() && self.read_buf.capacity() > READ_SHRINK_THRESHOLD {
                self.read_buf = BytesMut::with_capacity(READ_INITIAL_CAPACITY);
            }
        }

        Ok(updates)
    }

    /// Handle `n` more written bytes being ready to process by the transport.
    fn on_net_write(&mut self, n: usize) {
        self.write_head += n;
        trace!(
            "written {} bytes to the network ({}/{})",
            n,
            self.write_head,
            self.write_buffer.len()
        );
        assert!(self.write_head <= self.write_buffer.len());
        if self.write_head != self.write_buffer.len() {
            return;
        }

        // We finished sending the whole buffer.
        let sent_len = self.write_buffer.len();

        self.write_buffer.clear();
        self.write_head = 0;

        // If the buffer had to grow a lot for a one-off big send, recreate it to drop Vec capacity.
        if sent_len > WRITE_SHRINK_ON_SEND_OVER {
            self.write_buffer =
                DequeBuffer::with_capacity(WRITE_INITIAL_BACK_CAPACITY, LEADING_BUFFER_SPACE);
        }

        for req in self.requests.iter_mut() {
            match req.state {
                RequestState::NotSerialized | RequestState::Sent(_) => {}
                RequestState::Serialized(pair) => {
                    debug!("sent request with {:?}", pair);
                    req.state = RequestState::Sent(pair);
                }
            }
        }
    }

    /// Handle a ping timeout, meaning we need to enqueue a new ping request.
    fn on_ping_timeout(&mut self) {
        let ping_id = generate_random_id();
        debug!("enqueueing keepalive ping {}", ping_id);
        drop(
            self.enqueue_body(
                tl::functions::PingDelayDisconnect {
                    ping_id,
                    disconnect_delay: NO_PING_DISCONNECT,
                }
                .to_bytes(),
            ),
        );
        self.next_ping = Instant::now() + PING_DELAY;
    }

    /// Handle errors that occured while performing I/O.
    async fn on_error(&mut self, error: ReadError) -> Result<Vec<tl::enums::Updates>, ReadError> {
        log::info!("handling error: {error}");

        self.transport.reset();
        self.mtp.reset();

        log::info!(
            "resetting sender state from read_buf len/cap {}/{}, write_buffer len {}",
            self.read_buf.len(),
            self.read_buf.capacity(),
            self.write_buffer.len(),
        );

        self.read_buf.clear();
        self.write_head = 0;
        self.write_buffer.clear();

        let error = match error {
            ReadError::Io(_)
                if matches!(
                    self.reconnection_policy.should_retry(0),
                    ControlFlow::Continue(_)
                ) =>
            {
                match self.try_connect().await {
                    Ok(_) => {
                        // Reconnect success means everything can be retried.
                        self.requests
                            .iter_mut()
                            .for_each(|r| r.state = RequestState::NotSerialized);
                        return Ok(Vec::new());
                    }
                    Err(e) => ReadError::from(e),
                }
            }
            e => e,
        };

        log::warn!(
            "marking all {} request(s) as failed: {}",
            self.requests.len(),
            &error
        );

        self.requests
            .drain(..)
            .for_each(|r| drop(r.result.send(Err(InvocationError::from(error.clone())))));

        Err(error)
    }

    /// Process the result of deserializing an MTP buffer.
    fn process_mtp_buffer(
        &mut self,
        results: Vec<Deserialization>,
        updates: &mut Vec<tl::enums::Updates>,
    ) {
        for result in results {
            match result {
                Deserialization::Update(update) => self.process_update(updates, update),
                Deserialization::RpcResult(result) => self.process_result(result),
                Deserialization::RpcError(error) => self.process_error(error),
                Deserialization::BadMessage(bad_msg) => self.process_bad_message(bad_msg),
                Deserialization::Failure(failure) => self.process_deserialize_error(failure),
            }
        }
    }

    fn process_update(&mut self, updates: &mut Vec<tl::enums::Updates>, update: Vec<u8>) {
        let update = match tl::enums::Updates::from_bytes(&update) {
            Ok(u) => Some(u),
            Err(e) => {
                // Annoyingly enough, `messages.affectedMessages` also has `pts`.
                // Mostly received when deleting messages, so pretend that's the update that actually occured.
                match tl::enums::messages::AffectedMessages::from_bytes(&update) {
                    Ok(tl::enums::messages::AffectedMessages::Messages(
                        tl::types::messages::AffectedMessages { pts, pts_count },
                    )) => Some(
                        tl::types::UpdateShort {
                            update: tl::types::UpdateDeleteMessages {
                                messages: Vec::new(),
                                pts,
                                pts_count,
                            }
                            .into(),
                            date: 0,
                        }
                        .into(),
                    ),
                    Err(_) => match tl::types::messages::InvitedUsers::from_bytes(&update) {
                        Ok(u) => Some(u.updates),
                        Err(_) => {
                            warn!(
                                "telegram sent updates that failed to be deserialized: {}",
                                e
                            );
                            None
                        }
                    },
                }
            }
        };

        if let Some(update) = update {
            updates.push(update);
        }
    }

    fn process_result(&mut self, result: RpcResult) {
        if let Some(req) = self.pop_request(result.msg_id) {
            let x = result.body;
            assert!(x.len() >= 4);
            let res_id = u32::from_le_bytes([x[0], x[1], x[2], x[3]]);
            debug!(
                "got result {:x} ({}) for request {:?}",
                res_id,
                tl::name_for_id(res_id),
                result.msg_id
            );
            drop(req.result.send(Ok(x)));
        } else {
            info!(
                "got rpc result {:?} but no such request is saved",
                result.msg_id
            );
        }
    }

    fn process_error(&mut self, error: RpcResultError) {
        if let Some(req) = self.pop_request(error.msg_id) {
            debug!("got rpc error {:?}", error.error);
            let x = req.body.as_slice();
            drop(
                req.result.send(Err(InvocationError::Rpc(
                    RpcError::from(error.error)
                        .with_caused_by(u32::from_le_bytes([x[0], x[1], x[2], x[3]])),
                ))),
            );
        } else {
            info!(
                "got rpc error {:?} but no such request is saved",
                error.msg_id
            );
        }
    }

    fn process_bad_message(&mut self, bad_msg: BadMessage) {
        for i in (0..self.requests.len()).rev() {
            match self.requests[i].state {
                RequestState::Serialized(pair)
                    if pair.msg_id == bad_msg.msg_id || pair.container_msg_id == bad_msg.msg_id =>
                {
                    panic!(
                        "bad msg for unsent request {:?}: {}",
                        bad_msg.msg_id,
                        bad_msg.description()
                    );
                }
                RequestState::Sent(pair)
                    if pair.msg_id == bad_msg.msg_id || pair.container_msg_id == bad_msg.msg_id =>
                {
                    if bad_msg.retryable() {
                        info!(
                            "{}; re-sending request {:?}",
                            bad_msg.description(),
                            pair.msg_id
                        );
                        self.requests[i].state = RequestState::NotSerialized;
                    } else {
                        if bad_msg.fatal() {
                            error!(
                                "{}; canont retry request {:?}",
                                bad_msg.description(),
                                pair.msg_id
                            );
                        } else {
                            warn!(
                                "{}; canont retry request {:?}",
                                bad_msg.description(),
                                pair.msg_id
                            );
                        }
                        let req = self.requests.swap_remove(i);
                        drop(req.result.send(Err(InvocationError::Dropped)));
                    }
                }
                _ => {}
            }
        }
    }

    fn process_deserialize_error(&mut self, failure: DeserializationFailure) {
        if let Some(req) = self.pop_request(failure.msg_id) {
            debug!("got deserialization failure {:?}", failure.error);
            drop(
                req.result
                    .send(Err(InvocationError::Read(failure.error.into()))),
            );
        } else {
            info!(
                "got deserialization failure {:?} but no such request is saved",
                failure.error
            );
        }
    }

    fn pop_request(&mut self, msg_id: MsgId) -> Option<Request> {
        for i in 0..self.requests.len() {
            match self.requests[i].state {
                RequestState::Serialized(pair) if pair.msg_id == msg_id => {
                    panic!("got response {msg_id:?} for unsent request {pair:?}");
                }
                RequestState::Sent(pair) if pair.msg_id == msg_id => {
                    return Some(self.requests.swap_remove(i));
                }
                _ => {}
            }
        }
        None
    }
}

impl<T: Transport> Sender<T, mtp::Encrypted> {
    pub fn auth_key(&self) -> [u8; 256] {
        self.mtp.auth_key()
    }
}

pub async fn connect<T: Transport>(
    transport: T,
    addr: std::net::SocketAddr,
    rc_policy: &'static dyn ReconnectionPolicy,
) -> Result<(Sender<T, mtp::Encrypted>, Enqueuer), AuthorizationError> {
    let (sender, enqueuer) = Sender::connect(transport, mtp::Plain::new(), addr, rc_policy).await?;
    generate_auth_key(sender, enqueuer).await
}

#[cfg(feature = "proxy")]
pub async fn connect_via_proxy<'a, T: Transport>(
    transport: T,
    addr: std::net::SocketAddr,
    proxy_dc_id: i16,
    proxy_url: &str,
    rc_policy: &'static dyn ReconnectionPolicy,
) -> Result<(Sender<T, mtp::Encrypted>, Enqueuer), AuthorizationError> {
    let (sender, enqueuer) = Sender::connect_via_proxy(
        transport,
        mtp::Plain::new(),
        addr,
        proxy_dc_id,
        proxy_url,
        rc_policy,
    )
    .await?;
    generate_auth_key(sender, enqueuer).await
}

async fn connect_stream(addr: &std::net::SocketAddr) -> Result<NetStream, std::io::Error> {
    info!("connecting...");
    Ok(NetStream::Tcp(TcpStream::connect(addr).await?))
}

#[cfg(feature = "proxy")]
async fn connect_proxy_stream(
    addr: &SocketAddr,
    proxy_url: &str,
    proxy_dc_id: i16,
) -> Result<NetStream, std::io::Error> {
    if let Some(config) = MtProxyConfig::parse(proxy_url) {
        let config = config?;
        match &config.mode {
            crate::mtproxy::MtProxyMode::Obfuscated => {
                info!("connecting via mtproxy obfuscated...");
            }
            crate::mtproxy::MtProxyMode::FakeTls { domain } => {
                info!("connecting via mtproxy faketls for domain {domain}...");
            }
        }
        let proxy_addr = resolve_proxy_addr(&config.host, config.port).await?;
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            MtProxyStream::connect(proxy_addr, &config, proxy_dc_id),
        )
        .await
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "mtproxy connect timeout"))??;
        return Ok(NetStream::ProxyMtProxy(stream));
    }

    let proxy =
        url::Url::parse(proxy_url).map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
    let scheme = proxy.scheme();
    let host = proxy.host().ok_or(io::Error::new(
        ErrorKind::NotFound,
        format!("proxy host is missing from url: {}", proxy_url),
    ))?;
    let port = proxy.port().ok_or(io::Error::new(
        ErrorKind::NotFound,
        format!("proxy port is missing from url: {}", proxy_url),
    ))?;
    let username = proxy.username().replace("%3B", ";");
    let password = proxy.password().unwrap_or("");
    let socks_addr = match host {
        Host::Domain(domain) => resolve_proxy_addr(domain, port).await?,
        Host::Ipv4(v4) => SocketAddr::new(IpAddr::from(v4), port),
        Host::Ipv6(v6) => SocketAddr::new(IpAddr::from(v6), port),
    };

    match scheme {
        "socks5" => {
            if username.is_empty() {
                let stream = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio_socks::tcp::Socks5Stream::connect(socks_addr, addr),
                )
                .await
                .map_err(|_| io::Error::new(ErrorKind::TimedOut, "socks5 connect timeout"))?
                .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?;

                Ok(NetStream::ProxySocks5(stream))
            } else {
                let stream = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio_socks::tcp::Socks5Stream::connect_with_password(
                        socks_addr, addr, &username, password,
                    ),
                )
                .await
                .map_err(|_| io::Error::new(ErrorKind::TimedOut, "socks5 connect timeout"))?
                .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?;

                Ok(NetStream::ProxySocks5(stream))
            }
        }
        scheme => Err(io::Error::new(
            ErrorKind::ConnectionAborted,
            format!("proxy scheme not supported: {}", scheme),
        )),
    }
}

#[cfg(feature = "proxy")]
async fn resolve_proxy_addr(host: &str, port: u16) -> Result<SocketAddr, std::io::Error> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let response = resolver.lookup_ip(host).await?;
    let ip_addr = response.into_iter().next().ok_or(io::Error::new(
        ErrorKind::NotFound,
        format!("proxy host did not return any ip address: {}", host),
    ))?;
    Ok(SocketAddr::new(ip_addr, port))
}

pub async fn generate_auth_key<T: Transport>(
    mut sender: Sender<T, mtp::Plain>,
    enqueuer: Enqueuer,
) -> Result<(Sender<T, mtp::Encrypted>, Enqueuer), AuthorizationError> {
    info!("generating new authorization key...");

    let (request, data) = authentication::step1()?;
    debug!("gen auth key: sending step 1");
    let response = sender.send(request).await?;

    debug!("gen auth key: starting step 2");
    let (request, data) = authentication::step2(data, &response)?;
    debug!("gen auth key: sending step 2");
    let response = sender.send(request).await?;

    debug!("gen auth key: starting step 3");
    let (request, data) = authentication::step3(data, &response)?;
    debug!("gen auth key: sending step 3");
    let response = sender.send(request).await?;

    debug!("gen auth key: completing generation");
    let authentication::Finished {
        auth_key,
        time_offset,
        first_salt,
    } = authentication::create_key(data, &response)?;
    info!("authorization key generated successfully");

    Ok((
        Sender {
            stream: sender.stream,
            transport: sender.transport,
            mtp: mtp::Encrypted::build()
                .time_offset(time_offset)
                .first_salt(first_salt)
                .finish(auth_key),

            requests: sender.requests,
            request_rx: sender.request_rx,
            next_ping: Instant::now() + PING_DELAY,
            reconnection_policy: sender.reconnection_policy,

            read_buf: sender.read_buf,

            write_buffer: sender.write_buffer,
            write_head: sender.write_head,

            addr: sender.addr,
            #[cfg(feature = "proxy")]
            proxy_url: sender.proxy_url,
            #[cfg(feature = "proxy")]
            proxy_dc_id: sender.proxy_dc_id,
        },
        enqueuer,
    ))
}

pub async fn connect_with_auth<T: Transport>(
    transport: T,
    addr: std::net::SocketAddr,
    auth_key: [u8; 256],
    rc_policy: &'static dyn ReconnectionPolicy,
) -> Result<(Sender<T, mtp::Encrypted>, Enqueuer), io::Error> {
    Sender::connect(
        transport,
        mtp::Encrypted::build().finish(auth_key),
        addr,
        rc_policy,
    )
    .await
}

#[cfg(feature = "proxy")]
pub async fn connect_via_proxy_with_auth<'a, T: Transport>(
    transport: T,
    addr: std::net::SocketAddr,
    auth_key: [u8; 256],
    proxy_dc_id: i16,
    proxy_url: &str,
    rc_policy: &'static dyn ReconnectionPolicy,
) -> Result<(Sender<T, mtp::Encrypted>, Enqueuer), io::Error> {
    Sender::connect_via_proxy(
        transport,
        mtp::Encrypted::build().finish(auth_key),
        addr,
        proxy_dc_id,
        proxy_url,
        rc_policy,
    )
    .await
}
