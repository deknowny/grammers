use grammers_mtproto::transport::Intermediate;
use grammers_mtsender::{connect_via_proxy, NoReconnect};
use std::net::SocketAddr;
use std::time::Duration;

const WHITE_MTPROXY: &str = "tg://proxy?server=white.mtproxy.pw&port=443&secret=ee3f8a91c2d7e04b6a9f12c5e8370bd4aa786170692e6f7a6f6e2e7275";
const MAIN_MTPROXY: &str =
    "tg://proxy?server=main.mtproxy.pw&port=443&secret=dd3f8a91c2d7e04b6a9f12c5e8370bd4aa";

#[test]
#[ignore]
fn live_faketls_mtproxy_generates_auth_key() {
    connect_via_live_proxy(WHITE_MTPROXY);
}

#[test]
#[ignore]
fn live_obfuscated_mtproxy_generates_auth_key() {
    connect_via_live_proxy(MAIN_MTPROXY);
}

fn connect_via_live_proxy(proxy_url: &str) {
    let addr: SocketAddr = "149.154.167.51:443".parse().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(25),
                connect_via_proxy(Intermediate::new(), addr, 2, proxy_url, &NoReconnect),
            )
            .await
            .expect("live mtproxy test timed out")
            .expect("connect via mtproxy");
        });
}
