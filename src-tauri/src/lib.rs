use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::Manager;

pub const APP_VERSION: &str = "1.6.0";
const SOCKS_PORT: u16 = 10808;
const HTTP_PORT: u16 = 10809;
const API_PORT: u16 = 15490;

static CHILD: Mutex<Option<std::process::Child>> = Mutex::new(None);
static CONNECTED: AtomicBool = AtomicBool::new(false);
// user intent to stay connected — gates the auto-reconnect watchdog so a manual
// disconnect is never "repaired" by an unwanted auto-reconnect
static AUTO: AtomicBool = AtomicBool::new(false);
// last successful connection, replayed by the watchdog when the tunnel dies
static LAST: Mutex<Option<LastConnect>> = Mutex::new(None);

#[derive(Clone)]
struct LastConnect {
    server: Server,
    routing: String,
    dns: String,
    ad_block: bool,
    bypass: Vec<String>,
}
static NETWORKS: Mutex<Option<sysinfo::Networks>> = Mutex::new(None);
static DL_PROGRESS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Server {
    pub id: u64,
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub network: String,
    pub security: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ping: Option<i64>,
    pub flow: String,
    pub sni: String,
    pub fingerprint: String,
    pub alpn: String,
    pub allow_insecure: bool,
    pub pbk: String,
    pub sid: String,
    pub ws_path: String,
    pub ws_host: String,
    pub grpc_service_name: String,
}

// ───────────────────────── helpers ─────────────────────────

fn hide_window(cmd: &mut std::process::Command) {
    #[cfg(target_os = "windows")]
    cmd.creation_flags(0x0800_0000);
    #[allow(unused_variables)]
    let _ = cmd;
}

// Keep the machine awake (no sleep / modern-standby) while a VPN session is up,
// so a screen-off idle never suspends xray and kills the tunnel. Display may
// still turn off; we only suppress SYSTEM sleep.
#[cfg(windows)]
extern "system" {
    fn SetThreadExecutionState(es_flags: u32) -> u32;
}

#[cfg(windows)]
fn set_keep_awake(on: bool) {
    const ES_CONTINUOUS: u32 = 0x8000_0000;
    const ES_SYSTEM_REQUIRED: u32 = 0x0000_0001;
    const ES_AWAYMODE_REQUIRED: u32 = 0x0000_0040;
    let flags = if on {
        ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED
    } else {
        ES_CONTINUOUS
    };
    unsafe {
        SetThreadExecutionState(flags);
    }
}

#[cfg(not(windows))]
fn set_keep_awake(_on: bool) {}

// True when the local SOCKS listener xray should be serving is actually up.
fn socks_listening() -> bool {
    match "127.0.0.1:10808".parse::<std::net::SocketAddr>() {
        Ok(addr) => std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(600)).is_ok(),
        Err(_) => false,
    }
}

// Runs a blocking HTTP request OFF the async runtime (spawn_blocking) so a
// slow external host (api.github.com / ip-api) can never stall the worker
// thread that also serves the per-second stats + connect/disconnect IPC.
async fn http_get(url: &str) -> Result<String, String> {
    let url = url.to_string();
    tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .user_agent("LionRayVPN/1.2")
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .map_err(|e| e.to_string())?;
        client
            .get(url)
            .send()
            .map_err(|e| e.to_string())?
            .text()
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "worker panicked".to_string())?
}

fn b64_decode_flexible(input: &str) -> Option<String> {
    use base64::Engine;
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(&cleaned) {
            if let Ok(s) = String::from_utf8(bytes) {
                return Some(s);
            }
        }
    }
    None
}

// ───────────────────────── URI parsers ─────────────────────────

#[tauri::command]
fn import_server(uri: String) -> Result<Server, String> {
    parse_uri(uri.trim())
}

#[tauri::command]
fn import_bulk(uris: Vec<String>) -> Vec<Server> {
    let mut out = Vec::new();
    for u in &uris {
        let u = u.trim().to_string();
        if u.is_empty() {
            continue;
        }
        if let Ok(s) = parse_uri(&u) {
            out.push(s);
        }
    }

    // if no servers found, try joining all input as one base64 blob and decode
    if out.is_empty() {
        let joined = uris.join("\n");
        if let Some(decoded) = b64_decode_flexible(&joined) {
            if decoded.contains("://") {
                for line in decoded.lines() {
                    let line = line.trim();
                    if let Ok(s) = parse_uri(line) {
                        out.push(s);
                    }
                }
            }
        }
    }
    out
}

#[tauri::command]
async fn fetch_subscription(url: String) -> Result<Vec<Server>, String> {
    let body = http_get(url.trim()).await?;
    let text = b64_decode_flexible(&body).filter(|s| s.contains("://")).unwrap_or(body);
    let servers: Vec<Server> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("vless://") || l.starts_with("trojan://") || l.starts_with("ss://"))
        .filter_map(|l| parse_uri(l).ok())
        .collect();
    if servers.is_empty() {
        Err("No valid servers found in subscription".into())
    } else {
        Ok(servers)
    }
}

#[tauri::command]
async fn fetch_subscription_stream(url: String, on_server: tauri::ipc::Channel<Server>) -> Result<(), String> {
    let body = http_get(url.trim()).await?;
    let text = b64_decode_flexible(&body).filter(|s| s.contains("://")).unwrap_or(body);
    let mut count = 0u32;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("vless://") || line.starts_with("trojan://") || line.starts_with("ss://") {
            if let Ok(server) = parse_uri(line) {
                on_server.send(server).map_err(|e| e.to_string())?;
                count += 1;
            }
        }
    }
    if count == 0 {
        Err("No valid servers found in subscription".into())
    } else {
        Ok(())
    }
}

#[tauri::command]
fn get_clipboard() -> Result<String, String> {
    arboard::Clipboard::new()
        .and_then(|mut c| c.get_text())
        .map_err(|e| format!("Clipboard error: {e}"))
}

#[tauri::command]
fn copy_clipboard(text: String) -> Result<(), String> {
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_text(text))
        .map_err(|e| format!("Clipboard error: {e}"))
}

fn build_uri(s: &Server) -> Result<String, String> {
    let name_enc = urlencoding::encode(if s.name.is_empty() { "Server" } else { &s.name }).to_string();
    let hp = if s.address.contains(':') {
        format!("[{}]:{}", s.address.trim_matches(|c| c == '[' || c == ']'), s.port)
    } else {
        format!("{}:{}", s.address, s.port)
    };

    match s.protocol.as_str() {
        "vless" | "trojan" => {
            let mut q: Vec<String> = vec![format!("type={}", s.network)];
            q.push(format!(
                "security={}",
                if s.security.is_empty() { "none" } else { &s.security }
            ));
            if !s.sni.is_empty() {
                q.push(format!("sni={}", s.sni));
            }
            if !s.fingerprint.is_empty() {
                q.push(format!("fp={}", s.fingerprint));
            }
            if !s.alpn.is_empty() {
                q.push(format!("alpn={}", s.alpn));
            }
            if s.allow_insecure {
                q.push("allowInsecure=1".into());
            }
            if !s.pbk.is_empty() {
                q.push(format!("pbk={}", s.pbk));
            }
            if !s.sid.is_empty() {
                q.push(format!("sid={}", s.sid));
            }
            if !s.ws_path.is_empty() {
                q.push(format!("path={}", urlencoding::encode(&s.ws_path)));
            }
            if !s.ws_host.is_empty() {
                q.push(format!("host={}", urlencoding::encode(&s.ws_host)));
            }
            if !s.grpc_service_name.is_empty() {
                q.push(format!("serviceName={}", s.grpc_service_name));
            }
            if !s.flow.is_empty() && s.protocol == "vless" {
                q.push(format!("flow={}", s.flow));
            }
            let userinfo = if s.protocol == "vless" {
                s.uuid.clone()
            } else {
                urlencoding::encode(&s.uuid).to_string()
            };
            Ok(format!("{}://{}@{}?{}#{}", s.protocol, userinfo, hp, q.join("&"), name_enc))
        }
        "shadowsocks" => {
            use base64::Engine;
            let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&s.uuid);
            Ok(format!("ss://{ui}@{hp}#{name_enc}"))
        }
        "vmess" => {
            use base64::Engine;
            let net = if s.network.is_empty() { "tcp".into() } else { s.network.clone() };
            let mut v = json!({
                "v": "2",
                "ps": s.name,
                "add": s.address,
                "port": s.port.to_string(),
                "id": s.uuid,
                "aid": 0,
                "net": net,
                "type": "none",
                "host": s.ws_host,
                "path": s.ws_path,
                "tls": if s.security.is_empty() { "" } else { &s.security },
                "sni": s.sni,
                "alpn": s.alpn
            });
            let json_str = serde_json::to_string(&mut v).map_err(|e| e.to_string())?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(json_str);
            Ok(format!("vmess://{b64}"))
        }
        _ => Err("Unsupported protocol".into()),
    }
}

#[tauri::command]
fn export_uri(server: Server) -> Result<String, String> {
    build_uri(&server)
}

fn parse_uri(uri: &str) -> Result<Server, String> {
    if uri.starts_with("vless://") {
        parse_vless(uri)
    } else if uri.starts_with("trojan://") {
        parse_trojan(uri)
    } else if uri.starts_with("ss://") {
        parse_ss(uri)
    } else if uri.starts_with("vmess://") {
        parse_vmess(uri)
    } else {
        Err("Unsupported protocol".into())
    }
}

fn query_map(q: &str) -> std::collections::HashMap<String, String> {
    q.split('&')
        .filter_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            Some((
                urlencoding::decode(k).ok()?.to_string(),
                urlencoding::decode(v).unwrap_or_default().to_string(),
            ))
        })
        .collect()
}

fn split_host_port(hp: &str) -> Result<(String, u16), String> {
    let hp = hp.trim_matches('[').trim_matches(']');
    let (a, p) = hp.rsplit_once(':').ok_or("missing port")?;
    Ok((a.trim_matches('[').to_string(), p.parse().map_err(|_| "bad port")?))
}

fn base_server(name: String, protocol: &str) -> Server {
    Server {
        name,
        protocol: protocol.into(),
        ..Default::default()
    }
}

fn parse_vless(uri: &str) -> Result<Server, String> {
    let rest = uri.strip_prefix("vless://").unwrap();
    let (rest, name) = match rest.rsplit_once('#') {
        Some((r, n)) => (r, urlencoding::decode(n).unwrap_or_default().to_string()),
        None => (rest, "VLESS Server".into()),
    };
    let (left, q) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };
    let params = query_map(q);
    let (uuid, host_port) = left.split_once('@').ok_or("invalid vless")?;
    let (address, port) = split_host_port(host_port)?;
    let g = |k: &str| params.get(k).cloned().unwrap_or_default();

    Ok(Server {
        id: 0,
        name,
        protocol: "vless".into(),
        address,
        port,
        uuid: uuid.to_string(),
        network: g("type").is_empty().then(|| "tcp".to_string()).unwrap_or(g("type")),
        security: g("security"),
        ping: None,
        flow: g("flow"),
        sni: g("sni"),
        fingerprint: g("fp"),
        alpn: g("alpn"),
        allow_insecure: g("allowInsecure") == "1",
        pbk: g("pbk"),
        sid: g("sid"),
        ws_path: g("path"),
        ws_host: g("host"),
        grpc_service_name: g("serviceName"),
        ..base_server(String::new(), "vless")
    })
}

fn parse_trojan(uri: &str) -> Result<Server, String> {
    let rest = uri.strip_prefix("trojan://").unwrap();
    let (rest, name) = match rest.rsplit_once('#') {
        Some((r, n)) => (r, urlencoding::decode(n).unwrap_or_default().to_string()),
        None => (rest, "Trojan Server".into()),
    };
    let (left, q) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };
    let params = query_map(q);
    let (pass, host_port) = left.split_once('@').ok_or("invalid trojan")?;
    let (address, port) = split_host_port(host_port)?;
    let g = |k: &str| params.get(k).cloned().unwrap_or_default();

    Ok(Server {
        id: 0,
        name,
        protocol: "trojan".into(),
        address,
        port,
        uuid: pass.to_string(),
        network: if g("type").is_empty() { "tcp".into() } else { g("type") },
        security: if g("security").is_empty() { "tls".into() } else { g("security") },
        ping: None,
        sni: g("sni"),
        fingerprint: g("fp"),
        alpn: g("alpn"),
        allow_insecure: g("allowInsecure") == "1",
        ws_path: g("path"),
        ws_host: g("host"),
        grpc_service_name: g("serviceName"),
        ..base_server(String::new(), "trojan")
    })
}

fn parse_ss(uri: &str) -> Result<Server, String> {
    let rest = uri.strip_prefix("ss://").unwrap();
    let (rest, name) = match rest.rsplit_once('#') {
        Some((r, n)) => (r, urlencoding::decode(n).unwrap_or_default().to_string()),
        None => (rest, "Shadowsocks".into()),
    };
    let rest = match rest.split_once('?') {
        Some((l, _)) => l,
        None => rest,
    };

    // SIP002: base64(method:pass)@host:port  OR  whole thing base64
    let userinfo_hostport = if let Some((ui, hp)) = rest.rsplit_once('@') {
        let decoded = b64_decode_flexible(ui).filter(|d| d.contains(':'));
        let mp = decoded.or_else(|| urlencoding::decode(ui).ok().map(|s| s.to_string())).unwrap_or(ui.to_string());
        (mp, hp.to_string())
    } else {
        let full = b64_decode_flexible(rest).ok_or("invalid ss")?;
        full.rsplit_once('@')
            .map(|(m, h)| (m.to_string(), h.to_string()))
            .ok_or("invalid ss")?
    };

    let (method_pass, host_port) = userinfo_hostport;
    let (address, port) = split_host_port(&host_port)?;

    Ok(Server {
        id: 0,
        name,
        protocol: "shadowsocks".into(),
        address,
        port,
        uuid: method_pass,
        network: "tcp".into(),
        security: "none".into(),
        ping: None,
        ..base_server(String::new(), "shadowsocks")
    })
}

fn parse_vmess(uri: &str) -> Result<Server, String> {
    let encoded = uri.strip_prefix("vmess://").ok_or("invalid vmess")?;
    let json_str = b64_decode_flexible(encoded).ok_or("invalid vmess base64")?;
    let v: Value = serde_json::from_str(&json_str).map_err(|e| format!("invalid vmess json: {e}"))?;

    let g = |k: &str| v[k].as_str().unwrap_or("").to_string();

    let addr = g("add");
    let hst = g("host");
    let address = if addr.is_empty() { hst.clone() } else { addr };
    let port: u16 = if g("port").is_empty() { 443 } else { g("port").parse().unwrap_or(443) };
    let ps_name = g("ps");
    let name = if ps_name.is_empty() { format!("{}:{}", address, port) } else { ps_name };
    let uuid = g("id");
    let n1 = g("net");
    let n2 = g("type");
    let net = if n1.is_empty() { n2 } else { n1 };
    let tls = g("tls");
    let s1 = g("sni");
    let sni = if s1.is_empty() { hst.clone() } else { s1 };
    let path = g("path");
    let host = hst;
    let alpn = g("alpn");

    let security = if tls.is_empty() { "none".into() } else { tls };

    Ok(Server {
        id: 0,
        name,
        protocol: "vmess".into(),
        address,
        port,
        uuid,
        network: if net.is_empty() { "tcp".into() } else { net },
        security,
        ping: None,
        sni,
        alpn,
        ws_path: path,
        ws_host: host,
        ..base_server(String::new(), "vmess")
    })
}

// ───────────────────────── config generation ─────────────────────────

fn build_stream(server: &Server) -> Value {
    let mut stream = json!({ "network": server.network });
    let sni = if server.sni.is_empty() { &server.address } else { &server.sni };

    match server.security.as_str() {
        "tls" => {
            let mut tls = json!({
                "serverName": sni,
                "allowInsecure": server.allow_insecure,
            });
            if !server.fingerprint.is_empty() {
                tls["fingerprint"] = json!(server.fingerprint);
            }
            if !server.alpn.is_empty() {
                tls["alpn"] = json!(server.alpn.split(',').collect::<Vec<_>>());
            }
            stream["security"] = json!("tls");
            stream["tlsSettings"] = tls;
        }
        "reality" => {
            stream["security"] = json!("reality");
            stream["realitySettings"] = json!({
                "serverName": sni,
                "fingerprint": if server.fingerprint.is_empty() { "chrome" } else { server.fingerprint.as_str() },
                "publicKey": server.pbk,
                "shortId": server.sid,
                "spiderX": ""
            });
        }
        _ => {}
    }

    match server.network.as_str() {
        "ws" => {
            let mut ws = json!({ "path": if server.ws_path.is_empty() { "/" } else { server.ws_path.as_str() } });
            if !server.ws_host.is_empty() {
                ws["headers"] = json!({ "Host": server.ws_host });
            }
            stream["wsSettings"] = ws;
        }
        "grpc" => {
            stream["grpcSettings"] = json!({
                "serviceName": server.grpc_service_name,
                "multiMode": false
            });
        }
        _ => {}
    }

    stream
}

fn build_outbound_settings(server: &Server) -> Result<Value, String> {
    match server.protocol.as_str() {
        "vless" => Ok(json!({
            "vnext": [{
                "address": server.address,
                "port": server.port,
                "users": [{
                    "id": server.uuid,
                    "flow": server.flow,
                    "encryption": "none"
                }]
            }]
        })),
        "trojan" => Ok(json!({
            "servers": [{
                "address": server.address,
                "port": server.port,
                "password": server.uuid
            }]
        })),
        "shadowsocks" => {
            let (method, password) = server.uuid.split_once(':').ok_or("invalid ss credentials")?;
            Ok(json!({
                "servers": [{
                    "address": server.address,
                    "port": server.port,
                    "method": method,
                    "password": password
                }]
            }))
        }
        "vmess" => Ok(json!({
            "vnext": [{
                "address": server.address,
                "port": server.port,
                "users": [{
                    "id": server.uuid,
                    "alterId": 0,
                    "security": "auto"
                }]
            }]
        })),
        _ => Err("Unsupported protocol".into()),
    }
}

fn generate_config(server: &Server, routing: &str, dns: &str, ad_block: bool, bypass_domains: &[String]) -> Result<String, String> {
    let mut rules = vec![];

    // ad blocker rule
    if ad_block {
        rules.push(json!({
            "type": "field",
            "domain": ["geosite:category-ads-all"],
            "outboundTag": "block"
        }));
    }

    // domain bypass — these domains go DIRECT (skip proxy)
    if !bypass_domains.is_empty() {
        rules.push(json!({
            "type": "field",
            "domain": bypass_domains.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "outboundTag": "direct"
        }));
    }

    match routing {
        "global" => {}
        "cn" => {
            rules.push(json!({ "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct" }));
            rules.push(json!({ "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" }));
            rules.push(json!({ "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" }));
        }
        _ => {
            rules.push(json!({ "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" }));
        }
    }

    rules.push(json!({
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": "proxy"
    }));

    // stats API rule must come first so api traffic routes to the api outbound
    rules.insert(0, json!({
        "type": "field",
        "inboundTag": ["api"],
        "outboundTag": "api"
    }));

    // build DNS section
    let dns_section = match dns {
        "google" => json!({ "servers": ["8.8.8.8", "8.8.4.4"] }),
        "cloudflare" => json!({ "servers": ["1.1.1.1", "1.0.0.1"] }),
        "quad9" => json!({ "servers": ["9.9.9.9", "149.112.112.112"] }),
        "adguard" => json!({ "servers": ["94.140.14.14", "94.140.15.15"] }),
        "custom" => json!({ "servers": ["8.8.8.8"] }),
        _ => json!({ "servers": ["8.8.8.8"] }), // "system" or unknown → use Google as default
    };

    let routing_domain_strategy = if dns != "system" { "IPIfNonMatch" } else { "AsIs" };

    let config = json!({
        "log": { "loglevel": "warning" },
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"]
        },
        "dns": dns_section,
        "inbounds": [
            {
                "tag": "socks-in",
                "port": SOCKS_PORT,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": { "udp": true, "auth": "noauth" }
            },
            {
                "tag": "http-in",
                "port": HTTP_PORT,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {}
            },
            {
                "tag": "api",
                "listen": "127.0.0.1",
                "port": API_PORT,
                "protocol": "dokodemo-door",
                "settings": { "address": "127.0.0.1" }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": server.protocol,
                "settings": build_outbound_settings(server)?,
                "streamSettings": build_stream(server)
            },
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" }
        ],
        "routing": {
            "domainStrategy": routing_domain_strategy,
            "rules": rules
        }
    });
    serde_json::to_string_pretty(&config).map_err(|e| e.to_string())
}

// ───────────────────────── xray process + system proxy ─────────────────────────

fn find_xray_binary() -> Result<std::path::PathBuf, String> {
    let exe_name = if cfg!(target_os = "windows") { "xray.exe" } else { "xray" };
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("xray-bundle").join(exe_name));
            candidates.push(dir.join("resources").join("xray-bundle").join(exe_name));
            candidates.push(dir.join("Resources").join("xray-bundle").join(exe_name));
            // macOS .app bundle: exe is in Contents/MacOS, resources in
            // Contents/Resources — go up one level and into Resources.
            if let Some(parent) = dir.parent() {
                candidates.push(parent.join("Resources").join("xray-bundle").join(exe_name));
                candidates.push(parent.join("resources").join("xray-bundle").join(exe_name));
            }
            candidates.push(dir.join(exe_name));
        }
    }
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        candidates.push(std::path::PathBuf::from(manifest).join("xray-bundle").join(exe_name));
    }
    candidates.push(std::path::PathBuf::from(exe_name));

    for c in &candidates {
        if c.exists() {
            // resources lose the executable bit when bundled, so ensure +x on unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(c) {
                    let mode = meta.permissions().mode();
                    if mode & 0o111 == 0 {
                        let _ = std::fs::set_permissions(c, std::fs::Permissions::from_mode(mode | 0o755));
                    }
                }
            }
            return Ok(c.clone());
        }
    }
    Err("xray binary not found (looked next to app + xray-bundle)".into())
}

fn set_system_proxy(on: bool) {
    #[cfg(target_os = "windows")]
    {
        let enable_val = if on { "1" } else { "0" };
        let mut cmd = std::process::Command::new("reg");
        cmd.args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            enable_val,
            "/f",
        ]);
        hide_window(&mut cmd);
        let _ = cmd.output();

        if on {
            let mut cmd = std::process::Command::new("reg");
            cmd.args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                &format!("127.0.0.1:{HTTP_PORT}"),
                "/f",
            ]);
            hide_window(&mut cmd);
            let _ = cmd.output();
        }
    }
    #[cfg(target_os = "macos")]
    {
        let action = if on { "on_args" } else { "off" };
        let _ = action;
        if let Ok(out) = std::process::Command::new("networksetup").arg("-listallnetworkservices").output() {
            let list = String::from_utf8_lossy(&out.stdout);
            for line in list.lines().skip(1) {
                let svc = line.trim();
                if svc.is_empty() || svc.contains('*') {
                    continue;
                }
                if on {
                    let _ = std::process::Command::new("networksetup")
                        .args(["-setwebproxy", svc, "127.0.0.1", &HTTP_PORT.to_string()])
                        .output();
                    let _ = std::process::Command::new("networksetup")
                        .args(["-setsecurewebproxy", svc, "127.0.0.1", &HTTP_PORT.to_string()])
                        .output();
                    let _ = std::process::Command::new("networksetup")
                        .args(["-setsocksfirewallproxy", svc, "127.0.0.1", &SOCKS_PORT.to_string()])
                        .output();
                } else {
                    let _ = std::process::Command::new("networksetup").args(["-setwebproxystate", svc, "off"]).output();
                    let _ = std::process::Command::new("networksetup").args(["-setsecurewebproxystate", svc, "off"]).output();
                    let _ = std::process::Command::new("networksetup")
                        .args(["-setsocksfirewallproxystate", svc, "off"])
                        .output();
                }
            }
        }
    }
}

#[tauri::command]
fn open_link(url: String) {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", "", &url])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(&url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    }
}

// Core connect logic shared by the `connect` command and the auto-reconnect
// watchdog. Brings up xray, applies the system proxy and keeps the box awake.
// Returns Err if xray failed to start / exited immediately.
fn establish(
    server: &Server,
    routing: &str,
    dns: &str,
    ad_block: bool,
    bypass: &[String],
) -> Result<(), String> {
    // drop any previous core first so we never stack orphan processes
    if let Ok(mut g) = CHILD.lock() {
        if let Some(mut c) = g.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    let config = generate_config(server, routing, dns, ad_block, bypass)?;

    let config_dir = dirs::config_dir()
        .ok_or("no config dir")?
        .join("lionray-vpn");
    std::fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;
    let config_path = config_dir.join("config.json");
    std::fs::write(&config_path, config).map_err(|e| e.to_string())?;

    let xray_path = find_xray_binary()?;
    if let Some(xray_dir) = std::path::Path::new(&xray_path).parent() {
        for f in ["geoip.dat", "geosite.dat"] {
            let dest = config_dir.join(f);
            if !dest.exists() {
                let src = xray_dir.join(f);
                if src.exists() {
                    let _ = std::fs::copy(&src, &dest);
                }
            }
        }
    }

    let mut cmd = std::process::Command::new(&xray_path);
    cmd.args(["run", "-c"]).arg(&config_path).current_dir(&config_dir);
    // discard core logs so a full pipe buffer can never stall the tunnel
    cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    hide_window(&mut cmd);

    let child = cmd.spawn().map_err(|e| format!("Failed to start xray: {e}"))?;
    *CHILD.lock().map_err(|e| e.to_string())? = Some(child);

    // give the core a moment to boot; kill+rollback if it died instantly (bad config etc.)
    std::thread::sleep(std::time::Duration::from_millis(700));
    let alive = {
        let mut guard = CHILD.lock().map_err(|e| e.to_string())?;
        match guard.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    };
    if !alive {
        *CHILD.lock().map_err(|e| e.to_string())? = None;
        return Err("xray exited immediately — check server settings".into());
    }

    set_system_proxy(true);
    set_keep_awake(true);
    CONNECTED.store(true, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
fn connect(
    server: Server,
    routing: Option<String>,
    dns: Option<String>,
    ad_block: Option<bool>,
    bypass_domains: Option<Vec<String>>,
) -> Result<String, String> {
    if CONNECTED.load(Ordering::SeqCst) {
        return Err("Already connected — disconnect first".into());
    }

    let r = routing.clone().unwrap_or_else(|| "lan".into());
    let d = dns.clone().unwrap_or_else(|| "system".into());
    let ab = ad_block.unwrap_or(true);
    let bp = bypass_domains.clone().unwrap_or_default();

    if let Err(e) = establish(&server, &r, &d, ab, &bp) {
        cleanup();
        return Err(e);
    }

    AUTO.store(true, Ordering::SeqCst);
    *LAST.lock().map_err(|e| e.to_string())? = Some(LastConnect {
        server: server.clone(),
        routing: r,
        dns: d,
        ad_block: ab,
        bypass: bp,
    });
    Ok("Connected".into())
}

#[tauri::command]
fn disconnect() -> Result<String, String> {
    if !CONNECTED.load(Ordering::SeqCst) {
        return Err("Not connected".into());
    }
    cleanup();
    Ok("Disconnected".into())
}

#[tauri::command]
fn is_connected() -> bool {
    CONNECTED.load(Ordering::SeqCst)
}

// ── lifecycle cleanup ──
// force-disconnect: kill the xray child if any and restore the original
// network (clear the system proxy) so closing the app never leaves the box
// hijacked / half-connected. Also clears the auto-reconnect intent and the
// keep-awake request so a manual disconnect stays a manual disconnect.
fn cleanup() {
    if let Ok(mut guard) = CHILD.lock() {
        if let Some(mut c) = guard.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    // always reset, in case a previous run left proxy on
    set_system_proxy(false);
    set_keep_awake(false);
    CONNECTED.store(false, Ordering::SeqCst);
    AUTO.store(false, Ordering::SeqCst);
}


#[tauri::command]
fn ping_server(address: String, port: u16) -> Result<u64, String> {
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    let target = format!("{address}:{port}");
    let addrs: Vec<std::net::SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&target as &str)
        .map_err(|e| format!("DNS fail: {e}"))?
        .collect();
    let first = addrs.first().ok_or("no address")?;

    let start = Instant::now();
    TcpStream::connect_timeout(first, Duration::from_secs(2)).map_err(|e| e.to_string())?;
    Ok(start.elapsed().as_millis() as u64)
}

#[tauri::command]
async fn check_exit_ip() -> Result<Value, String> {
    tokio::task::spawn_blocking(move || {
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{SOCKS_PORT}")).map_err(|e| e.to_string())?;
        let proxied = reqwest::blocking::Client::builder()
            .proxy(proxy)
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .map_err(|e| e.to_string())?;
        let direct = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(6))
            .build()
            .map_err(|e| e.to_string())?;

        // 1) real exit IP through the tunnel (HTTPS first, HTTP fallback)
        let exit_ip: String = proxied
            .get("https://api.ipify.org?format=json")
            .send()
            .and_then(|r| r.json::<Value>())
            .ok()
            .and_then(|v| v["ip"].as_str().map(|s| s.to_string()))
            .or_else(|| {
                proxied
                    .get("http://ip-api.com/json/?fields=query")
                    .send()
                    .and_then(|r| r.json::<Value>())
                    .ok()
                    .and_then(|v| v["query"].as_str().map(|s| s.to_string()))
            })
            .ok_or("tunnel unreachable")?;

        // 2) enrich with geolocation for that exact IP (direct, fast)
        let geo: Value = direct
            .get(format!(
                "http://ip-api.com/json/{exit_ip}?fields=status,country,countryCode,city,isp"
            ))
            .send()
            .and_then(|r| r.json::<Value>())
            .unwrap_or(Value::Null);

        Ok(json!({
            "query": exit_ip,
            "country": geo["country"],
            "countryCode": geo["countryCode"],
            "city": geo["city"],
            "isp": geo["isp"]
        }))
    })
    .await
    .map_err(|_| "worker panicked".to_string())?
}

#[tauri::command]
fn get_traffic() -> Result<Value, String> {
    if !CONNECTED.load(Ordering::SeqCst) {
        return Ok(json!({ "down": 0u64, "up": 0u64 }));
    }
    let path = find_xray_binary()?;
    let mut cmd = std::process::Command::new(&path);
    cmd.args([
        "api",
        "statsquery",
        &format!("--server=127.0.0.1:{API_PORT}"),
    ]);
    hide_window(&mut cmd);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;

    let mut down: u64 = 0;
    let mut up: u64 = 0;
    if let Some(stats) = v["stat"].as_array() {
        for s in stats {
            let name = s["name"].as_str().unwrap_or("");
            let val = s["value"].as_u64().unwrap_or(0);
            if name.contains(">>>api") {
                continue;
            }
            if name.ends_with("downlink") {
                down = down.saturating_add(val);
            } else if name.ends_with("uplink") {
                up = up.saturating_add(val);
            }
        }
    }
    Ok(json!({ "down": down, "up": up }))
}

#[tauri::command]
fn get_net_speed() -> Result<Value, String> {
    let mut guard = NETWORKS.lock().map_err(|e| e.to_string())?;
    let nets = guard.get_or_insert_with(sysinfo::Networks::new_with_refreshed_list);
    nets.refresh(true);

    let mut down: u64 = 0;
    let mut up: u64 = 0;
    for (_name, data) in nets.iter() {
        down += data.received();
        up += data.transmitted();
    }
    Ok(json!({ "down": down, "up": up }))
}

#[tauri::command]
async fn check_xray_core_update() -> Result<Option<Value>, String> {
    let body = http_get("https://api.github.com/repos/XTLS/Xray-core/releases/latest").await?;
    let v: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let tag = v["tag_name"].as_str().unwrap_or("").to_string();
    if tag.is_empty() { return Ok(None); }

    // strip "v" prefix for comparison
    let remote_ver = tag.trim_start_matches('v').trim_start_matches('V').to_string();
    let cur = get_core_version().unwrap_or_default();
    let cur_clean = cur.trim_start_matches('v').trim_start_matches('V').trim().to_string();

    // if same version, no update
    if remote_ver == cur_clean { return Ok(None); }

    // pick the asset for the current platform (windows / macos / linux)
    let platform_kw = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let mut zip_url: Option<String> = None;
    if let Some(assets) = v["assets"].as_array() {
        for a in assets {
            let name = a["name"].as_str().unwrap_or("");
            if name.contains(platform_kw) && name.contains("64") && name.ends_with(".zip") {
                zip_url = a["browser_download_url"].as_str().map(|s| s.to_string());
                break;
            }
        }
    }
    let url = match zip_url {
        Some(u) => u,
        None => return Ok(None),
    };

    Ok(Some(json!({
        "version": remote_ver,
        "current": cur_clean,
        "url": url,
    })))
}

#[tauri::command]
async fn update_xray_core(url: String) -> Result<String, String> {
    if CONNECTED.load(Ordering::SeqCst) {
        return Err("Disconnect VPN first".into());
    }

    let tmp = std::env::temp_dir().join("lionray_xray_update");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| format!("temp dir: {e}"))?;
    let zip_path = tmp.join("xray.zip");

    DL_PROGRESS.store(0, Ordering::Relaxed);

    // download in blocking thread (avoids tokio runtime issues)
    let dl_url = url.clone();
    let dl_path = zip_path.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let client = reqwest::blocking::Client::builder()
            .user_agent("LionRayVPN/1.6")
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| format!("client: {e}"))?;

        let mut resp = client.get(&dl_url).send().map_err(|e| format!("download: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        let total = resp.content_length().unwrap_or(0);
        let mut file = std::fs::File::create(&dl_path).map_err(|e| format!("create zip: {e}"))?;
        let mut buf = [0u8; 256 * 1024];
        let mut downloaded: u64 = 0;
        loop {
            let n = resp.read(&mut buf).map_err(|e| format!("read: {e}"))?;
            if n == 0 { break; }
            std::io::Write::write_all(&mut file, &buf[..n]).map_err(|e| format!("write: {e}"))?;
            downloaded += n as u64;
            let pct = if total > 0 {
                (downloaded as f64 / total as f64 * 100.0) as u32
            } else {
                let mb = downloaded / (1024 * 1024);
                (mb as u32 * 4).min(95)
            };
            DL_PROGRESS.store(pct.min(99), Ordering::Relaxed);
        }
        DL_PROGRESS.store(100, Ordering::Relaxed);
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("task: {e}"))??;

    DL_PROGRESS.store(0, Ordering::Relaxed);

    let tmp_clone = tmp.clone();
    tokio::task::spawn_blocking(move || {
        let extract_dir = tmp_clone.join("extracted");
        std::fs::create_dir_all(&extract_dir).map_err(|e| format!("extract dir: {e}"))?;
        {
            let file = std::fs::File::open(&zip_path).map_err(|e| format!("open zip: {e}"))?;
            let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("invalid zip: {e}"))?;
            archive.extract(&extract_dir).map_err(|e| format!("extract: {e}"))?;
        }

        // find xray dir inside extracted (usually "Xray-windows-64/")
        let inner = std::fs::read_dir(&extract_dir)
            .map_err(|e| format!("list extract: {e}"))?
            .filter_map(|e| e.ok())
            .find(|e| e.path().is_dir() && e.file_name().to_string_lossy().contains("Xray"))
            .map(|e| e.path())
            .unwrap_or(extract_dir.clone());

        let bin_path = find_xray_binary()?;
        let bundle_dir = bin_path.parent().ok_or("xray dir not found")?;
        let exe_name = if cfg!(target_os = "windows") { "xray.exe" } else { "xray" };

        for name in [exe_name, "geoip.dat", "geosite.dat"] {
            let src = inner.join(name);
            if src.exists() {
                let dst = bundle_dir.join(name);
                let _ = std::fs::remove_file(&dst);
                std::fs::copy(&src, &dst).map_err(|e| format!("copy {name}: {e}"))?;
            }
        }

        // remove old version.txt so new binary's real version is used
        let _ = std::fs::remove_file(bundle_dir.join("version.txt"));
        let _ = std::fs::remove_dir_all(&tmp_clone);
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("task: {e}"))??;

    let new_ver = get_core_version().unwrap_or_else(|_| "unknown".into());
    Ok(new_ver)
}

#[tauri::command]
fn get_download_progress() -> u32 {
    DL_PROGRESS.load(Ordering::Relaxed)
}

#[tauri::command]
fn get_core_version() -> Result<String, String> {
    let path = find_xray_binary()?;
    let bundle_dir = path.parent().unwrap_or(std::path::Path::new("."));

    // prefer version.txt (allows version override without replacing binary)
    let vfile = bundle_dir.join("version.txt");
    if let Ok(v) = std::fs::read_to_string(&vfile) {
        let trimmed = v.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    let out = {
        let mut cmd = std::process::Command::new(&path);
        cmd.arg("version");
        hide_window(&mut cmd);
        cmd.output().map_err(|e| e.to_string())?
    };
    let s = String::from_utf8_lossy(&out.stdout);
    let ver = s
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("unknown")
        .to_string();
    Ok(ver)
}

fn parse_ver(s: &str) -> Vec<u32> {
    s.trim_start_matches('v')
        .split('.')
        .map(|p| p.parse::<u32>().unwrap_or(0))
        .collect()
}

// numeric semver compare so e.g. 1.7.10 > 1.7.1 (a substring check would miss this)
fn ver_gt(a: &str, b: &str) -> bool {
    let va = parse_ver(a);
    let vb = parse_ver(b);
    let n = va.len().max(vb.len());
    for i in 0..n {
        let x = *va.get(i).unwrap_or(&0);
        let y = *vb.get(i).unwrap_or(&0);
        if x != y {
            return x > y;
        }
    }
    false
}

#[tauri::command]
async fn check_update() -> Result<Option<String>, String> {
    let body = http_get("https://api.github.com/repos/satminpaing1/LionRayDesktop/releases/latest").await?;
    let v: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let tag = v["tag_name"].as_str().unwrap_or("").to_string();
    if tag.is_empty() {
        Ok(None)
    } else if ver_gt(&tag, APP_VERSION) {
        Ok(Some(tag))
    } else {
        Ok(None)
    }
}

// ─── persistent key/value store (file in app data dir) ───
// Replaces the previous localStorage approach: WKWebView in Tauri v2 does not
// reliably persist localStorage across app restarts, so saved keys vanished.
fn store_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("store.json"))
}

#[tauri::command]
fn load_store(app: tauri::AppHandle, key: String) -> Result<Option<String>, String> {
    let path = store_path(&app)?;
    if !path.exists() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let map: Value = serde_json::from_str(&s).unwrap_or(Value::Null);
    Ok(map
        .get(key.as_str())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()))
}

#[tauri::command]
fn save_store(app: tauri::AppHandle, key: String, value: String) -> Result<(), String> {
    let path = store_path(&app)?;
    let mut map: Value = if path.exists() {
        let s = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        serde_json::from_str(&s).unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    if !map.is_object() {
        map = Value::Object(serde_json::Map::new());
    }
    map.as_object_mut()
        .unwrap()
        .insert(key, Value::String(value));
    std::fs::write(&path, serde_json::to_string(&map).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            import_server,
            import_bulk,
            fetch_subscription,
            fetch_subscription_stream,
            get_clipboard,
            copy_clipboard,
            export_uri,
            connect,
            disconnect,
            is_connected,
            ping_server,
            check_exit_ip,
            get_traffic,
            get_net_speed,
            get_core_version,
            check_update,
            check_xray_core_update,
            load_store,
            save_store,
            get_download_progress,
            update_xray_core,
            open_link,
        ])
        .setup(|app| {
            // Attach a real icon to every window so the running process
            // (taskbar) and the desktop shortcut that Windows ties to it never
            // fall back to the blank default icon. The .ico embedded in the exe
            // is fine for static shortcuts (Start Menu / Control Panel), but the
            // live window needs an explicit icon to stay consistent across runs.
            if let Ok(img) = image::load_from_memory(include_bytes!("../icons/256x256.png")) {
                let rgba = img.to_rgba8();
                let (w, h) = (rgba.width(), rgba.height());
                let icon = tauri::image::Image::new_owned(rgba.into_raw(), w, h);
                for (_label, win) in app.webview_windows() {
                    let _ = win.set_icon(icon.clone());
                }
            }

            // Auto-reconnect watchdog: while the user intends to be connected
            // (AUTO), if the tunnel dies — xray crashed, a flaky subscription
            // node dropped, or the PC woke from sleep with a dead core — replay
            // the last successful connection. Gives up after a few retries so a
            // permanently dead node doesn't spawn xray in a loop forever.
            std::thread::spawn(|| {
                let mut retries: u32 = 0;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(10));
                    if !AUTO.load(Ordering::SeqCst) {
                        retries = 0;
                        continue;
                    }
                    let child_alive = match CHILD.lock() {
                        Ok(mut g) => match g.as_mut() {
                            Some(c) => matches!(c.try_wait(), Ok(None)),
                            None => false,
                        },
                        Err(_) => false,
                    };
                    let dead = !child_alive || !socks_listening();
                    if !dead {
                        retries = 0;
                        continue;
                    }
                    if retries >= 6 {
                        AUTO.store(false, Ordering::SeqCst);
                        CONNECTED.store(false, Ordering::SeqCst);
                        retries = 0;
                        continue;
                    }
                    retries += 1;
                    if let Some(l) = LAST.lock().ok().and_then(|g| g.clone()) {
                        let _ = establish(&l.server, &l.routing, &l.dns, l.ad_block, &l.bypass);
                    } else {
                        AUTO.store(false, Ordering::SeqCst);
                        CONNECTED.store(false, Ordering::SeqCst);
                        retries = 0;
                    }
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            // tear down vpn + restore network when quitting, even if the user
            // closes the window without explicitly disconnecting first
            if let tauri::RunEvent::Exit { .. } = event {
                cleanup();
            }
            let _ = app_handle;
        });
}
