use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::Manager;

pub const APP_VERSION: &str = "1.8.6";
const SOCKS_PORT: u16 = 10808;
const HTTP_PORT: u16 = 10809;
const API_PORT: u16 = 15490;

static CHILD: Mutex<Option<std::process::Child>> = Mutex::new(None);
// sing-box TUN front-end (Windows system-wide capture); None when TUN is off
static TUN_CHILD: Mutex<Option<std::process::Child>> = Mutex::new(None);
// Set only when this session actually created TUN state. Lets a normal proxy
// connect skip the pointless `reg delete HKLM\...\sing-box_tun` process spawn.
static TUN_DIRTY: AtomicBool = AtomicBool::new(false);
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
    tun: bool,
    udp: bool,
    ipv6: bool,
    fragment: bool,
}
static NETWORKS: Mutex<Option<sysinfo::Networks>> = Mutex::new(None);
static DL_PROGRESS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
// Startup stale-state cleanup runs on a background thread so the window can
// paint immediately. `connect` waits for it (short, bounded) before establishing.
static STARTUP_CLEANUP_DONE: AtomicBool = AtomicBool::new(false);

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
    /// Raw `fragment=` share-link parameter (TLS ClientHello fragmentation).
    /// Shadowrocket format: `<flag>,<length>,<interval>[,packets]`
    /// e.g. `1,40-60,30-50,tlshello`.
    pub fragment: String,
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

// ───────────────────────── administrator detection ─────────────────────────
// TUN mode creates a virtual adapter and rewrites the system routing table,
// which Windows only permits for elevated processes. Raw FFI avoids adding a
// windows-sys dependency just for two calls.
#[cfg(windows)]
mod win_elevation {
    use std::ffi::c_void;

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: *mut c_void,
            desired_access: u32,
            token_handle: *mut *mut c_void,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: *mut c_void,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    pub fn is_elevated() -> bool {
        const TOKEN_QUERY: u32 = 0x0008;
        const TOKEN_ELEVATION: u32 = 20;
        unsafe {
            let mut token: *mut c_void = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TokenElevation { token_is_elevated: 0 };
            let mut len: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TOKEN_ELEVATION,
                &mut elevation as *mut _ as *mut c_void,
                std::mem::size_of::<TokenElevation>() as u32,
                &mut len,
            );
            CloseHandle(token);
            ok != 0 && elevation.token_is_elevated != 0
        }
    }
}

fn running_as_admin() -> bool {
    #[cfg(windows)]
    {
        win_elevation::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

// True when the local SOCKS listener xray should be serving is actually up.
fn socks_listening() -> bool {
    // One quick probe is enough. A transient "busy" core is already handled by
    // the watchdog's consecutive-dead threshold, so retrying here only added
    // ~300 ms to every startup probe and every connect readiness check.
    "127.0.0.1:10808"
        .parse::<std::net::SocketAddr>()
        .map(|addr| {
            std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(250))
                .is_ok()
        })
        .unwrap_or(false)
}

// ── diagnostics ─────────────────────────────────────────────
// Tiny append-only log in %APPDATA%\lionray-vpn\app.log so a drop can be
// traced afterwards. The core's own warnings go to xray.log / singbox.log.
fn utc_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if mo <= 2 { y + 1 } else { y };
    format!("{yr:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}Z")
}

fn app_log(msg: &str) {
    let Some(dir) = dirs::config_dir().map(|d| d.join("lionray-vpn")) else {
        return;
    };
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("app.log");
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > 512 * 1024 {
            let _ = std::fs::rename(&path, dir.join("app.old.log"));
        }
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(f, "{} {}", utc_stamp(), msg);
    }
}

// End-to-end probe through the local SOCKS inbound. Detects a tunnel that is
// "up" locally (xray alive, port listening) but cannot reach the internet —
// the exact case the old watchdog could never see.
fn probe_via_socks() -> bool {
    let Ok(proxy) = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{SOCKS_PORT}")) else {
        return false;
    };
    let Ok(client) = reqwest::blocking::Client::builder()
        .proxy(proxy)
        .connect_timeout(std::time::Duration::from_secs(4))
        .timeout(std::time::Duration::from_secs(8))
        .build()
    else {
        return false;
    };
    // Plain HTTP 204 endpoints: no TLS handshake, minimal overhead.
    for url in [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/generate_204",
    ] {
        if let Ok(r) = client.get(url).send() {
            if r.status().is_success() {
                return true;
            }
        }
    }
    false
}

// In TUN mode all direct traffic is captured by the adapter, so a direct
// request tests the whole sing-box -> xray path (routes, DNS, adapter).
fn probe_direct() -> bool {
    let Ok(client) = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(4))
        .timeout(std::time::Duration::from_secs(8))
        .build()
    else {
        return false;
    };
    for url in [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/generate_204",
    ] {
        if let Ok(r) = client.get(url).send() {
            if r.status().is_success() {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn system_proxy_is_ours() -> bool {
    const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    let mut q = std::process::Command::new("reg");
    q.args(["query", KEY, "/v", "ProxyEnable"]);
    hide_window(&mut q);
    let enabled = q
        .output()
        .ok()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
            s.split_whitespace().last().map(|t| t == "0x1").unwrap_or(false)
        })
        .unwrap_or(false);
    if !enabled {
        return false;
    }
    let mut q = std::process::Command::new("reg");
    q.args(["query", KEY, "/v", "ProxyServer"]);
    hide_window(&mut q);
    q.output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).contains(&format!("127.0.0.1:{HTTP_PORT}"))
        })
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn system_proxy_is_ours() -> bool {
    true
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
            if !s.fragment.is_empty() {
                q.push(format!("fragment={}", urlencoding::encode(&s.fragment)));
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
        fragment: g("fragment"),
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
        fragment: g("fragment"),
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

fn is_fragment_range(value: &str) -> bool {
    let numeric = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    match value.split_once('-') {
        Some((a, b)) => numeric(a.trim()) && numeric(b.trim()),
        None => numeric(value.trim()),
    }
}

fn is_fragment_number(value: &str) -> bool {
    let v = value.trim();
    !v.is_empty() && v.chars().all(|c| c.is_ascii_digit())
}

struct FragmentSpec {
    packets: String,
    length: String,
    interval: String,
}

/// Parse the share-link `fragment=` parameter into Xray freedom fragment
/// settings. Supports both common layouts:
///   * Shadowrocket: `<flag>,<length>,<interval>[,tlshello]` (e.g. `1,40-60,30-50,tlshello`)
///   * Happ/others:  `<length>,<interval>,tlshello` (e.g. `3,1,tlshello`)
/// The first Shadowrocket field is an enable flag, not a fragment size.
fn parse_fragment_spec(spec: &str) -> Option<FragmentSpec> {
    let parts: Vec<&str> = spec
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() < 2 {
        return None;
    }

    // `tlshello,<length>,<interval>` variant.
    if parts[0].eq_ignore_ascii_case("tlshello") {
        if parts.len() >= 3 && is_fragment_range(parts[1]) && is_fragment_range(parts[2]) {
            return Some(FragmentSpec {
                packets: "tlshello".into(),
                length: parts[1].into(),
                interval: parts[2].into(),
            });
        }
        return None;
    }

    let body: &[&str] = match parts.split_last() {
        Some((last, rest)) if last.eq_ignore_ascii_case("tlshello") => rest,
        _ => &parts,
    };

    let (length, interval) = match body.len() {
        2 => (body[0], body[1]),
        3 => {
            // Shadowrocket puts a flag first: `1,40-60,30-50`.
            let flag_form = is_fragment_number(body[0])
                && is_fragment_range(body[1])
                && is_fragment_range(body[2])
                && (body[1].contains('-') || body[2].contains('-'));
            if flag_form {
                if body[0].trim() == "0" {
                    return None;
                }
                (body[1], body[2])
            } else {
                (body[0], body[1])
            }
        }
        _ => return None,
    };

    if !is_fragment_range(length) || !is_fragment_range(interval) {
        return None;
    }
    // Long inter-fragment waits (Shadowrocket presets use 30-50 ms) add more
    // than a second to every TLS handshake: a ~1.5 KB ClientHello split into
    // 40-60 byte records waits once per record. The splitting itself is what
    // defeats DPI, so keep it but cap the wait to stay responsive.
    let interval = if range_max(interval) > 5 {
        "1-3".to_string()
    } else {
        interval.to_string()
    };
    Some(FragmentSpec {
        packets: "tlshello".into(),
        length: length.into(),
        interval,
    })
}

fn range_max(value: &str) -> u64 {
    value
        .split('-')
        .next_back()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

fn generate_config(
    server: &Server,
    routing: &str,
    dns: &str,
    ad_block: bool,
    bypass_domains: &[String],
    udp: bool,
    ipv6: bool,
    fragment_on: bool,
) -> Result<String, String> {
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

    // IPv6 disabled (default): reject IPv6 literals so apps don't waste seconds
    // trying unreachable routes. Domain traffic is resolved remotely anyway.
    if !ipv6 {
        rules.push(json!({
            "type": "field",
            "ip": ["::/0"],
            "outboundTag": "block"
        }));
    }

    rules.push(json!({
        "type": "field",
        "network": if udp { "tcp,udp" } else { "tcp" },
        "outboundTag": "proxy"
    }));

    // stats API rule must come first so api traffic routes to the api outbound
    rules.insert(0, json!({
        "type": "field",
        "inboundTag": ["api"],
        "outboundTag": "api"
    }));

    // Build the DNS section. "system" must truly use the OS resolver: emitting
    // a plaintext 8.8.8.8 resolver here used to make every outbound lookup
    // depend on a reachable public DNS, which stalls badly on networks that
    // block UDP/53.
    let explicit_dns = match dns {
        "system" | "" => None,
        "google" => Some(json!({ "servers": ["8.8.8.8", "8.8.4.4"] })),
        "cloudflare" => Some(json!({ "servers": ["1.1.1.1", "1.0.0.1"] })),
        "quad9" => Some(json!({ "servers": ["9.9.9.9", "149.112.112.112"] })),
        "adguard" => Some(json!({ "servers": ["94.140.14.14", "94.140.15.15"] })),
        "custom" => Some(json!({ "servers": ["8.8.8.8"] })),
        _ => None,
    }
    .map(|mut section| {
        section["queryStrategy"] = json!(if ipv6 { "UseIP" } else { "UseIPv4" });
        section
    });

    let routing_domain_strategy = if explicit_dns.is_some() { "IPIfNonMatch" } else { "AsIs" };

    // TLS ClientHello fragmentation requested by the share link: the proxy
    // outbound dials through a freedom outbound that fragments the handshake.
    // Only meaningful when the transport is actually TLS, and only when the
    // user explicitly enabled it in Settings.
    let fragment = match server.security.as_str() {
        "tls" | "reality" if fragment_on => parse_fragment_spec(&server.fragment),
        _ => None,
    };
    let mut proxy_stream = build_stream(server);
    // Low latency for interactive traffic; Nagle only adds delay here.
    let mut sockopt = json!({ "tcpNoDelay": true });
    if fragment.is_some() {
        sockopt["dialerProxy"] = json!("fragment");
    }
    proxy_stream["sockopt"] = sockopt;

    // `proxy` must stay first: Xray uses the first outbound as the default for
    // traffic that matches no rule, and it must never fall through to freedom.
    let mut outbounds = vec![json!({
        "tag": "proxy",
        "protocol": server.protocol,
        "settings": build_outbound_settings(server)?,
        "streamSettings": proxy_stream
    })];
    if let Some(f) = fragment {
        outbounds.push(json!({
            "tag": "fragment",
            "protocol": "freedom",
            "settings": {
                "fragment": {
                    "packets": f.packets,
                    "length": f.length,
                    "interval": f.interval
                }
            },
            "streamSettings": { "sockopt": { "tcpNoDelay": true } }
        }));
    }
    if ipv6 {
        outbounds.push(json!({ "tag": "direct", "protocol": "freedom" }));
    } else {
        // Bypass/direct traffic must never dial IPv6 when IPv6 is disabled.
        outbounds.push(json!({
            "tag": "direct",
            "protocol": "freedom",
            "settings": { "domainStrategy": "UseIPv4" }
        }));
    }
    outbounds.push(json!({ "tag": "block", "protocol": "blackhole" }));

    let mut config = json!({
        "log": { "loglevel": "warning" },
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"]
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "port": SOCKS_PORT,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": { "udp": udp, "auth": "noauth" }
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
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": routing_domain_strategy,
            "rules": rules
        }
    });
    if let Some(dns_section) = explicit_dns {
        config["dns"] = dns_section;
    }
    serde_json::to_string_pretty(&config).map_err(|e| e.to_string())
}

// ───────────────────────── xray process + system proxy ─────────────────────────

fn find_xray_binary() -> Result<std::path::PathBuf, String> {
    let exe_name = if cfg!(target_os = "windows") { "xray.exe" } else { "xray" };
    // Windows builds stage their core in xray-bundle-win; the shared
    // xray-bundle folder keeps the macOS core. Search the native folder first
    // so Windows never tries to launch the Mach-O binary.
    let bundle_names: &[&str] = if cfg!(target_os = "windows") {
        &["xray-bundle-win", "xray-bundle"]
    } else {
        &["xray-bundle", "xray-bundle-win"]
    };
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for b in bundle_names {
                candidates.push(dir.join(b).join(exe_name));
                candidates.push(dir.join("resources").join(b).join(exe_name));
                candidates.push(dir.join("Resources").join(b).join(exe_name));
            }
            // macOS .app bundle: exe is in Contents/MacOS, resources in
            // Contents/Resources — go up one level and into Resources.
            if let Some(parent) = dir.parent() {
                for b in bundle_names {
                    candidates.push(parent.join("Resources").join(b).join(exe_name));
                    candidates.push(parent.join("resources").join(b).join(exe_name));
                }
            }
            candidates.push(dir.join(exe_name));
        }
    }
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let manifest = std::path::PathBuf::from(manifest);
        for b in bundle_names {
            candidates.push(manifest.join(b).join(exe_name));
        }
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

fn find_singbox_binary() -> Result<std::path::PathBuf, String> {
    let exe_name = if cfg!(target_os = "windows") { "sing-box.exe" } else { "sing-box" };
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // Windows builds stage their binaries in xray-bundle-win so the
            // macOS bundle can keep its own xray binary. Accept both layouts.
            for bundle in ["xray-bundle-win", "xray-bundle"] {
                candidates.push(dir.join(bundle).join(exe_name));
            }
            candidates.push(dir.join("resources").join("xray-bundle-win").join(exe_name));
            candidates.push(dir.join("resources").join("xray-bundle").join(exe_name));
            candidates.push(dir.join("Resources").join("xray-bundle-win").join(exe_name));
            candidates.push(dir.join("Resources").join("xray-bundle").join(exe_name));
            if let Some(parent) = dir.parent() {
                candidates.push(parent.join("Resources").join("xray-bundle-win").join(exe_name));
                candidates.push(parent.join("Resources").join("xray-bundle").join(exe_name));
                candidates.push(parent.join("resources").join("xray-bundle-win").join(exe_name));
                candidates.push(parent.join("resources").join("xray-bundle").join(exe_name));
            }
            candidates.push(dir.join(exe_name));
        }
    }
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let manifest = std::path::PathBuf::from(manifest);
        candidates.push(manifest.join("xray-bundle-win").join(exe_name));
        candidates.push(manifest.join("xray-bundle").join(exe_name));
    }
    candidates.push(std::path::PathBuf::from(exe_name));

    for c in &candidates {
        if c.exists() {
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
    Err("sing-box binary not found — TUN mode needs sing-box.exe in xray-bundle-win".into())
}

// TUN front-end config: sing-box owns the virtual adapter + default routes,
// then hands every connection to the existing Xray SOCKS listener. Xray keeps
// doing all protocol work, routing rules, ad blocking and stats, so TUN and
// proxy mode behave identically from the app's point of view.
fn generate_tun_config(dns: &str, interface_name: &str, udp: bool, ipv6: bool) -> String {
    // Resolve DNS through the tunnel with DoH so queries can never leak to the
    // local ISP resolver while the TUN adapter is default route.
    let (dns_ip, dns_name) = match dns {
        "google" => ("8.8.8.8", "dns.google"),
        "quad9" => ("9.9.9.9", "dns.quad9.net"),
        "adguard" => ("94.140.14.14", "dns.adguard-dns.com"),
        _ => ("1.1.1.1", "cloudflare-dns.com"),
    };

    let tun_addresses = if ipv6 {
        vec!["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
    } else {
        vec!["172.19.0.1/30"]
    };
    // Many Windows networks have no working IPv6. Returning AAAA records makes
    // apps try unreachable routes through the TUN and hang, so IPv4-only is the
    // default; the toggle allows IPv6 when the network actually supports it.
    let dns_strategy = if ipv6 { "prefer_ipv4" } else { "ipv4_only" };
    let dns_rules: Vec<Value> = if ipv6 {
        Vec::new()
    } else {
        vec![json!({ "query_type": ["AAAA"], "action": "reject" })]
    };
    let self_cidr = if ipv6 {
        vec!["172.19.0.0/30", "fdfe:dcba:9876::/126"]
    } else {
        vec!["172.19.0.0/30"]
    };

    let mut route_rules = vec![
        // recover the hostname so Xray's domain rules (CN bypass, ad-block,
        // bypass list) keep working for TUN traffic
        json!({ "action": "sniff" }),
        json!({ "port": 53, "action": "hijack-dns" }),
    ];
    if !udp {
        // TCP-only mode: reject non-DNS UDP right away instead of stalling on
        // a UDP relay the server may not support (QUIC would retry forever).
        route_rules.push(json!({ "network": "udp", "action": "reject" }));
    }
    route_rules.extend([
        json!({ "ip_cidr": self_cidr, "action": "reject" }),
        // xray must reach the real server directly, never through TUN
        json!({ "process_name": ["xray.exe", "sing-box.exe"], "action": "route", "outbound": "direct" }),
        json!({ "ip_is_private": true, "action": "route", "outbound": "direct" }),
        json!({ "action": "route", "outbound": "proxy" }),
    ]);

    let config = json!({
        "log": { "level": "warn", "timestamp": true },
        "dns": {
            "servers": [{
                "type": "https",
                "tag": "remote-dns",
                "server": dns_ip,
                "server_port": 443,
                "path": "/dns-query",
                "detour": "proxy",
                "tls": { "server_name": dns_name }
            }],
            "final": "remote-dns",
            "strategy": dns_strategy,
            "rules": dns_rules
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": interface_name,
            "address": tun_addresses,
            "mtu": 9000,
            "auto_route": true,
            "strict_route": true,
            "stack": "mixed",
            "dns_mode": "hijack"
        }],
        "outbounds": [
            {
                "type": "socks",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": SOCKS_PORT,
                "version": "5",
                "udp_over_tcp": false
            },
            { "type": "direct", "tag": "direct" }
        ],
        "route": {
            "auto_detect_interface": true,
            // never fall back to the system resolver (which points back into
            // this TUN) when a direct outbound has to resolve a domain
            "default_domain_resolver": "remote-dns",
            "rules": route_rules,
            "final": "proxy"
        }
    });
    serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".into())
}

fn tun_alive() -> bool {
    match TUN_CHILD.lock() {
        Ok(mut g) => match g.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        },
        Err(_) => false,
    }
}

#[cfg(target_os = "windows")]
const TUN_ROOT_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Network\sing-box_tun";

#[cfg(target_os = "windows")]
fn restore_singbox_tun_state() {
    let mut cmd = std::process::Command::new("reg");
    cmd.args(["delete", TUN_ROOT_KEY, "/f"]);
    hide_window(&mut cmd);
    let _ = cmd.output();
}

#[cfg(not(target_os = "windows"))]
fn restore_singbox_tun_state() {}

fn stop_tun() {
    let had_child = if let Ok(mut guard) = TUN_CHILD.lock() {
        if let Some(mut c) = guard.take() {
            let _ = c.kill();
            let _ = c.wait();
            true
        } else {
            false
        }
    } else {
        false
    };
    // Undo the host route that keeps the core outside the tunnel (see
    // tunnel_host_route). Without this, a stale /32 for a dead server would
    // shadow the next session.
    clear_tunnel_host_route();
    // sing-box's default auto_route keeps its routing state in the registry
    // ("sing-box_tun") and recreates the adapter at boot. Only clean it when a
    // TUN session actually existed — a plain proxy connect must not pay for a
    // needless `reg delete` process spawn. Startup still sweeps stale state.
    if TUN_DIRTY.swap(false, Ordering::SeqCst) || had_child {
        restore_singbox_tun_state();
    }
    #[cfg(windows)]
    if had_child {
        std::thread::spawn(sweep_phantom_wintun);
    }
    #[cfg(not(windows))]
    let _ = had_child;
}

// When TUN is on, sing-box owns 0.0.0.0/0. Xray still has to dial the real
// server, so we add a host route for the server IP through the physical
// gateway (192.168.x.1 etc.). Without it the server address itself is routed
// into the tunnel and Xray never reaches the server: every request times out
// and it looks like "connected but no internet".
//
// The route is written to a small helper file (IP + gateway + interface) so
// stop_tun can remove it even after the process restarts.
#[cfg(target_os = "windows")]
fn tunnel_host_route(server_ip: &str) {
    // only valid for a real IPv4 literal; domains are pre-resolved to IPs
    if server_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return;
    }
    clear_tunnel_host_route();
    // find the physical default route (the one that is NOT the tun adapter)
    let out = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "route"])
        .output();
    let Ok(out) = out else { return };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut gw = String::new();
    let mut iface = String::new();
    for line in text.lines() {
        // "  0.0.0.0/0     192.168.31.1   Wi-Fi   2"
        if !line.contains("0.0.0.0/0") {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 {
            // gateway is after the prefix, interface name is the 3rd column
            let g = cols[1];
            if !g.starts_with("10.") && !g.starts_with("192.168") && !g.starts_with("172.") {
                continue;
            }
            gw = g.to_string();
            iface = cols[2].to_string();
            break;
        }
    }
    if gw.is_empty() {
        return;
    }
    let _ = std::fs::create_dir_all(tunnel_route_file().parent().unwrap());
    let _ = std::fs::write(
        tunnel_route_file(),
        format!("{server_ip}\n{gw}\n{iface}\n"),
    );
    let _ = std::process::Command::new("route")
        .args(["add", server_ip, "mask", "255.255.255.255", &gw, "metric", "1"])
        .output();
}

fn tunnel_route_file() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("lionray-vpn")
        .join("tun-route.txt")
}

fn clear_tunnel_host_route() {
    let Ok(content) = std::fs::read_to_string(tunnel_route_file()) else {
        return;
    };
    let mut lines = content.lines();
    if let Some(ip) = lines.next() {
        let _ = std::process::Command::new("route")
            .args(["delete", ip])
            .output();
    }
    let _ = std::fs::remove_file(tunnel_route_file());
}

#[cfg(not(target_os = "windows"))]
fn tunnel_host_route(_server_ip: &str) {}

#[cfg(not(target_os = "windows"))]
fn clear_tunnel_host_route() {}

// A forcibly killed Wintun process leaves a hidden "phantom" device behind
// (CM_PROB_PHANTOM). Reusing the same adapter name can then silently fail to
// configure the interface, so every session gets a fresh name and this sweep
// removes old sing-box phantoms in the background.
#[cfg(windows)]
fn sweep_phantom_wintun() {
    // Wait for the killed process's PnP node to transition to CM_PROB_PHANTOM
    // before removing it, otherwise the sweep runs too early and misses it.
    let script = r#"Start-Sleep -Milliseconds 1500; Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -like '*sing-tun*' -and $_.Problem -eq 'CM_PROB_PHANTOM' } | ForEach-Object { pnputil /remove-device $_.InstanceId | Out-Null }"#;
    let mut cmd = std::process::Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", script]);
    hide_window(&mut cmd);
    let _ = cmd.output();
}

fn start_tun(dns: &str, udp: bool, ipv6: bool) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = (dns, udp, ipv6);
        Err("TUN mode is only supported on Windows".into())
    }
    #[cfg(windows)]
    {
        if !running_as_admin() {
            return Err("TUN mode needs administrator rights — restart LionRay as administrator".into());
        }
        let path = find_singbox_binary()?;
        let config_dir = dirs::config_dir()
            .ok_or("no config dir")?
            .join("lionray-vpn");
        std::fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;
        let config_path = config_dir.join("singbox-tun.json");

        // unique per session so a crashed/killed previous run can never leave
        // a phantom adapter that blocks this one
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let interface_name = format!("LionRayTun{}{}", std::process::id() % 1000, seed % 100000);
        std::fs::write(&config_path, generate_tun_config(dns, &interface_name, udp, ipv6))
            .map_err(|e| e.to_string())?;

        let mut cmd = std::process::Command::new(&path);
        cmd.args(["run", "-c"]).arg(&config_path).current_dir(&config_dir);
        // same reasoning as xray.log: file, not a pipe, not /dev/null
        match std::fs::File::create(config_dir.join("singbox.log")) {
            Ok(f) => {
                if let Ok(err) = f.try_clone() {
                    cmd.stdout(std::process::Stdio::from(f));
                    cmd.stderr(std::process::Stdio::from(err));
                } else {
                    cmd.stdout(std::process::Stdio::from(f));
                    cmd.stderr(std::process::Stdio::null());
                }
            }
            Err(_) => {
                cmd.stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
            }
        }
        hide_window(&mut cmd);

        let child = cmd.spawn().map_err(|e| format!("Failed to start TUN engine: {e}"))?;
        *TUN_CHILD.lock().map_err(|e| e.to_string())? = Some(child);
        TUN_DIRTY.store(true, Ordering::SeqCst);

        // adapter creation + route programming takes a moment; fail fast if
        // Windows refused (usually because the process is not elevated)
        std::thread::sleep(std::time::Duration::from_millis(1500));
        if !tun_alive() {
            stop_tun();
            return Err("TUN engine exited immediately — administrator rights are required".into());
        }
        // No phantom sweep here: it spawns PowerShell + WMI and is only needed
        // after a real session ends (stop_tun) or once at app startup.
        Ok(())
    }
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

// A crash, an installer upgrade, or a force-killed core can leave the Windows
// system proxy pointing at our local port after xray is already gone. Every
// browser then behaves as if the machine is offline. Only clear the value when
// it is ours and nothing is listening, so a second running instance that is
// actually connected is never disturbed.
#[cfg(target_os = "windows")]
fn restore_stale_proxy() {
    if socks_listening() {
        return;
    }
    let mut cmd = std::process::Command::new("reg");
    cmd.args([
        "query",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "/v",
        "ProxyServer",
    ]);
    hide_window(&mut cmd);
    let ours = cmd
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .to_ascii_lowercase()
                .contains(&format!("127.0.0.1:{HTTP_PORT}"))
        })
        .unwrap_or(false);
    if ours {
        set_system_proxy(false);
    }
}

#[cfg(not(target_os = "windows"))]
fn restore_stale_proxy() {}

#[tauri::command]
async fn open_link(url: String) {
    let _ = tokio::task::spawn_blocking(move || {
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
    })
    .await;
}

#[tauri::command]
fn is_elevated() -> bool {
    running_as_admin()
}

// Relaunch this executable through UAC and hand over to the elevated instance.
// The old process exits (RunEvent::Exit runs cleanup) so there is only ever
// one LionRay/tunnel owner.
#[tauri::command]
async fn relaunch_as_admin(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        // PowerShell single-quoted strings escape ' by doubling it
        let exe_str = exe.to_string_lossy().replace('\'', "''");
        let script = format!(
            "$ErrorActionPreference='Stop'; Start-Process -FilePath '{}' -Verb RunAs",
            exe_str
        );
        tokio::task::spawn_blocking(move || {
            let mut cmd = std::process::Command::new("powershell.exe");
            cmd.args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script]);
            hide_window(&mut cmd);
            let status = cmd.status().map_err(|e| format!("elevation failed: {e}"))?;
            if !status.success() {
                return Err("Administrator request was cancelled".to_string());
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| format!("elevation task failed: {e}"))??;

        // give the new process a moment to appear before we tear this one down
        std::thread::sleep(std::time::Duration::from_millis(500));
        app.exit(0);
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        Err("TUN mode is only supported on Windows".into())
    }
}

// Core connect logic shared by the `connect` command and the auto-reconnect
// watchdog. Brings up xray, applies the system proxy and keeps the box awake.
// Returns Err if xray failed to start / exited immediately.
fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

// Last known-good address per proxy hostname. Windows/ISP DNS occasionally
// answers NXDOMAIN for perfectly valid hosts; falling back to the cached IP
// keeps reconnects instant instead of leaving the UI stuck for seconds.
static DNS_CACHE: Mutex<Option<std::collections::HashMap<String, (String, std::time::Instant)>>> =
    Mutex::new(None);
const DNS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

fn cache_dns(host: &str, ip: &str) {
    if let Ok(mut guard) = DNS_CACHE.lock() {
        let map = guard.get_or_insert_with(std::collections::HashMap::new);
        map.insert(host.to_string(), (ip.to_string(), std::time::Instant::now()));
    }
}

fn cached_dns(host: &str) -> Option<String> {
    let guard = DNS_CACHE.lock().ok()?;
    let map = guard.as_ref()?;
    let (ip, at) = map.get(host)?;
    if at.elapsed() <= DNS_CACHE_TTL {
        Some(ip.clone())
    } else {
        None
    }
}

/// System resolver with a hard time budget, returning every IPv4 address.
/// One Cloudflare edge IP can be unreachable from a given ISP while another
/// works, so callers need the full list instead of just the first entry.
fn system_lookup_all(host: &str, port: u16, budget: std::time::Duration) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let host = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut v4: Vec<String> = Vec::new();
        if let Ok(addrs) = (host.as_str(), port).to_socket_addrs() {
            for addr in addrs {
                if let std::net::IpAddr::V4(ip) = addr.ip() {
                    let s = ip.to_string();
                    if !v4.contains(&s) {
                        v4.push(s);
                    }
                }
            }
        }
        let _ = tx.send(v4);
    });
    rx.recv_timeout(budget).unwrap_or_default()
}

/// Race a short TCP handshake to each address and return the first success.
fn first_reachable(addrs: &[String], port: u16, budget: std::time::Duration) -> Option<String> {
    use std::net::{SocketAddr, TcpStream};
    let (tx, rx) = std::sync::mpsc::channel();
    let mut spawned = 0;
    for ip in addrs {
        let Ok(sock) = format!("{ip}:{port}").parse::<SocketAddr>() else {
            continue;
        };
        let tx = tx.clone();
        let ip = ip.clone();
        std::thread::spawn(move || {
            if TcpStream::connect_timeout(&sock, std::time::Duration::from_millis(900)).is_ok() {
                let _ = tx.send(ip);
            }
        });
        spawned += 1;
    }
    if spawned == 0 {
        return None;
    }
    drop(tx);
    rx.recv_timeout(budget).ok()
}

/// DNS-over-HTTPS fallback for networks whose plain DNS misbehaves. Runs on a
/// plain OS thread so the blocking HTTP client never sees a Tokio runtime
/// context, and is bounded by a hard timeout.
fn doh_lookup(host: &str) -> Option<String> {
    let host = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(doh_lookup_blocking(&host));
    });
    rx.recv_timeout(std::time::Duration::from_secs(7))
        .ok()
        .flatten()
}

fn doh_lookup_blocking(host: &str) -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let name = urlencoding::encode(host);
    for url in [
        format!("https://cloudflare-dns.com/dns-query?name={name}&type=A"),
        format!("https://dns.google/resolve?name={name}&type=A"),
    ] {
        let Ok(resp) = client.get(&url).header("accept", "application/dns-json").send() else {
            continue;
        };
        let Ok(body) = resp.json::<Value>() else { continue };
        if let Some(answers) = body.get("Answer").and_then(|a| a.as_array()) {
            for record in answers {
                if record.get("type").and_then(|t| t.as_u64()) != Some(1) {
                    continue;
                }
                if let Some(data) = record.get("data").and_then(|d| d.as_str()) {
                    if data.parse::<std::net::Ipv4Addr>().is_ok() {
                        return Some(data.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Resolve the proxy hostname once before xray starts so the core dials a
/// cached IP while keeping SNI/Host unchanged. Falls back to the last known
/// address, then DoH.
fn resolve_server_address(server: &Server) -> Option<String> {
    if is_ip_literal(&server.address) {
        return None;
    }
    let addrs = system_lookup_all(
        &server.address,
        server.port,
        std::time::Duration::from_millis(1500),
    );
    if !addrs.is_empty() {
        // Prefer an IP that actually accepts TCP. If none do right now, keep
        // the first one so xray can still attempt it.
        let ip = first_reachable(&addrs, server.port, std::time::Duration::from_millis(1200))
            .unwrap_or_else(|| addrs[0].clone());
        cache_dns(&server.address, &ip);
        return Some(ip);
    }
    if let Some(ip) = cached_dns(&server.address) {
        return Some(ip);
    }
    if let Some(ip) = doh_lookup(&server.address) {
        cache_dns(&server.address, &ip);
        return Some(ip);
    }
    None
}

fn establish(
    server: &Server,
    routing: &str,
    dns: &str,
    ad_block: bool,
    bypass: &[String],
    tun: bool,
    udp: bool,
    ipv6: bool,
    fragment_on: bool,
) -> Result<(), String> {
    // drop any previous core first so we never stack orphan processes
    stop_tun();
    if let Ok(mut g) = CHILD.lock() {
        if let Some(mut c) = g.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    // Preserve the hostname for TLS/SNI and the WS Host header even though the
    // socket itself will dial a pre-resolved address.
    let mut dial_server = server.clone();
    if dial_server.sni.is_empty() {
        dial_server.sni = dial_server.address.clone();
    }
    if let Some(ip) = resolve_server_address(server) {
        dial_server.address = ip;
    }

    let config = generate_config(&dial_server, routing, dns, ad_block, bypass, udp, ipv6, fragment_on)?;

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
    // Write the core's warnings to a file instead of a pipe (a full pipe can
    // stall the tunnel) and instead of /dev/null (which threw away the reason
    // for drops). The file is truncated on every connect.
    match std::fs::File::create(config_dir.join("xray.log")) {
        Ok(f) => {
            if let Ok(err) = f.try_clone() {
                cmd.stdout(std::process::Stdio::from(f));
                cmd.stderr(std::process::Stdio::from(err));
            } else {
                cmd.stdout(std::process::Stdio::from(f));
                cmd.stderr(std::process::Stdio::null());
            }
        }
        Err(_) => {
            cmd.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
        }
    }
    hide_window(&mut cmd);

    let child = cmd.spawn().map_err(|e| format!("Failed to start xray: {e}"))?;
    *CHILD.lock().map_err(|e| e.to_string())? = Some(child);

    // Wait until the SOCKS listener is actually accepting connections. A fixed
    // sleep made the UI spin on slow machines and could race the first
    // request; polling also detects a core that died from a bad config.
    let mut ready = false;
    // 25 ms granularity instead of 100 ms: the core is usually listening in
    // ~50 ms, so the old loop wasted ~75-100 ms on every single connect.
    for _ in 0..200 {
        std::thread::sleep(std::time::Duration::from_millis(25));
        let alive = {
            let mut guard = CHILD.lock().map_err(|e| e.to_string())?;
            match guard.as_mut() {
                Some(c) => matches!(c.try_wait(), Ok(None)),
                None => false,
            }
        };
        if !alive {
            break;
        }
        if socks_listening() {
            ready = true;
            break;
        }
    }
    if !ready {
        if let Ok(mut g) = CHILD.lock() {
            if let Some(mut c) = g.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
        return Err("xray could not start - check server settings".into());
    }

    if tun {
        if let Err(e) = start_tun(dns, udp, ipv6) {
            // roll back xray so a failed TUN start cannot leave a half state
            if let Ok(mut g) = CHILD.lock() {
                if let Some(mut c) = g.take() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
            }
            CONNECTED.store(false, Ordering::SeqCst);
            return Err(e);
        }
        // keep the proxy server reachable outside the tunnel: Xray must dial
        // the real IP directly, not through the TUN adapter sing-box owns
        tunnel_host_route(&dial_server.address);
        // TUN captures everything; a system proxy on top would double-route
        // traffic and can leak DNS, so make sure it is off.
        set_system_proxy(false);
    } else {
        clear_tunnel_host_route();
        set_system_proxy(true);
    }

    set_keep_awake(true);
    CONNECTED.store(true, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
async fn connect(
    server: Server,
    routing: Option<String>,
    dns: Option<String>,
    ad_block: Option<bool>,
    bypass_domains: Option<Vec<String>>,
    tun: Option<bool>,
    udp: Option<bool>,
    ipv6: Option<bool>,
    fragment: Option<bool>,
) -> Result<String, String> {
    if CONNECTED.load(Ordering::SeqCst) {
        return Err("Already connected — disconnect first".into());
    }

    let tun_on = tun.unwrap_or(false);
    if tun_on && !running_as_admin() {
        return Err("TUN mode needs administrator rights — restart LionRay as administrator".into());
    }

    let r = routing.clone().unwrap_or_else(|| "lan".into());
    let d = dns.clone().unwrap_or_else(|| "system".into());
    let ab = ad_block.unwrap_or(true);
    let bp = bypass_domains.clone().unwrap_or_default();
    let udp_on = udp.unwrap_or(false);
    let ipv6_on = ipv6.unwrap_or(false);
    let fragment_on = fragment.unwrap_or(false);

    let srv = server.clone();
    let (r2, d2, bp2) = (r.clone(), d.clone(), bp.clone());
    let started = tokio::task::spawn_blocking(move || {
        // Never let the startup cleanup thread clear the proxy we are about to
        // enable. It normally finishes in <100 ms, so this is effectively free.
        for _ in 0..100 {
            if STARTUP_CLEANUP_DONE.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        establish(
            &srv, &r2, &d2, ab, &bp2, tun_on, udp_on, ipv6_on, fragment_on,
        )
    })
    .await
    .map_err(|e| format!("connect task failed: {e}"))?;

    if let Err(e) = started {
        app_log(&format!("connect failed: {e}"));
        cleanup();
        return Err(e);
    }

    AUTO.store(true, Ordering::SeqCst);
    app_log(&format!(
        "connect ok: {}:{} tun={} udp={} ipv6={} fragment={}",
        server.address, server.port, tun_on, udp_on, ipv6_on, fragment_on
    ));
    *LAST.lock().map_err(|e| e.to_string())? = Some(LastConnect {
        server,
        routing: r,
        dns: d,
        ad_block: ab,
        bypass: bp,
        tun: tun_on,
        udp: udp_on,
        ipv6: ipv6_on,
        fragment: fragment_on,
    });
    Ok("Connected".into())
}

#[tauri::command]
async fn disconnect() -> Result<String, String> {
    // Always run the full cleanup: even when CONNECTED is already false (the
    // core died, or the frontend missed a heartbeat) the user's intent is to
    // stop, so clear AUTO and any half-open TUN/proxy state too.
    app_log("disconnect: requested by user");
    tokio::task::spawn_blocking(cleanup)
        .await
        .map_err(|e| format!("disconnect task failed: {e}"))?;
    Ok("Disconnected".into())
}

#[tauri::command]
fn is_connected() -> bool {
    if !CONNECTED.load(Ordering::SeqCst) {
        return false;
    }
    // Detect a crashed core immediately instead of waiting for the watchdog,
    // so the UI's heartbeat can show "connection lost" and reconnect.
    let core_alive = match CHILD.lock() {
        Ok(mut g) => match g.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        },
        Err(_) => false,
    };
    if !core_alive {
        CONNECTED.store(false, Ordering::SeqCst);
        app_log("core exited unexpectedly - watchdog will reconnect");
        return false;
    }
    let tun_on = LAST
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|l| l.tun))
        .unwrap_or(false);
    if tun_on && !tun_alive() {
        CONNECTED.store(false, Ordering::SeqCst);
        return false;
    }
    true
}

// ── lifecycle cleanup ──
// Tear down the tunnel but keep the user's "stay connected" intent. Used by the
// watchdog between retry attempts; `cleanup` adds the AUTO reset for a real
// manual disconnect. (The old watchdog called cleanup() on repeated failures,
// which silently turned AUTO off and stopped reconnecting forever.)
fn reset_tunnel_state() {
    // stop the TUN adapter first: it owns the default routes, so removing it
    // before xray avoids a short window where traffic is sent to a dead proxy
    stop_tun();
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
}

// force-disconnect: kill the xray child if any and restore the original
// network (clear the system proxy) so closing the app never leaves the box
// hijacked / half-connected. Also clears the auto-reconnect intent and the
// keep-awake request so a manual disconnect stays a manual disconnect.
fn cleanup() {
    reset_tunnel_state();
    AUTO.store(false, Ordering::SeqCst);
}


#[tauri::command]
async fn ping_server(address: String, port: u16) -> Result<u64, String> {
    tokio::task::spawn_blocking(move || {
        use std::net::TcpStream;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let target = format!("{address}:{port}");
        let addrs: Vec<std::net::SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&target as &str)
            .map_err(|e| format!("DNS fail: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err("no address".into());
        }

        // Happy eyeballs: race every resolved address (IPv4 first, as Windows
        // returns it) instead of trusting the first entry. A network that
        // advertises IPv6 but cannot route it used to make healthy IPv4
        // servers show as "ERR" after the 2 s timeout.
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        for addr in addrs.into_iter().take(4) {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let r = TcpStream::connect_timeout(&addr, Duration::from_millis(1800));
                let elapsed = start.elapsed().as_millis() as u64;
                let _ = tx.send(r.map(|_| elapsed).map_err(|e| format!("{addr}: {e}")));
            });
        }
        drop(tx);

        let deadline = Instant::now() + Duration::from_millis(2200);
        let mut last_err = "timed out".to_string();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match rx.recv_timeout(left) {
                Ok(Ok(ms)) => return Ok(ms),
                Ok(Err(e)) => last_err = e,
                Err(_) => break,
            }
        }
        Err(last_err)
    })
    .await
    .map_err(|e| format!("ping task failed: {e}"))?
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
async fn get_traffic() -> Result<Value, String> {
    tokio::task::spawn_blocking(|| {
        if !CONNECTED.load(Ordering::SeqCst) {
            return Ok(json!({ "down": 0u64, "up": 0u64 }));
        }
        // This spawns xray.exe once per poll. It is deliberately kept off the
        // UI thread; the frontend also polls it slowly (5s) so a 35 MB process
        // start can never compete with clicks/animations.
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
    })
    .await
    .map_err(|e| format!("traffic task failed: {e}"))?
}

#[tauri::command]
async fn get_net_speed() -> Result<Value, String> {
    tokio::task::spawn_blocking(|| {
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
    })
    .await
    .map_err(|e| format!("net speed task failed: {e}"))?
}

#[tauri::command]
async fn check_xray_core_update() -> Result<Option<Value>, String> {
    let body = http_get("https://api.github.com/repos/XTLS/Xray-core/releases/latest").await?;
    let v: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let tag = v["tag_name"].as_str().unwrap_or("").to_string();
    if tag.is_empty() {
        return Ok(None);
    }

    // strip "v" prefix for comparison
    let remote_ver = tag.trim_start_matches('v').trim_start_matches('V').to_string();
    let cur = tokio::task::spawn_blocking(get_core_version_sync)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let cur_clean = cur.trim_start_matches('v').trim_start_matches('V').trim().to_string();

    // if same version, no update
    if remote_ver == cur_clean {
        return Ok(None);
    }

    // Pick the exact asset for this platform/arch. A loose "contains 64"
    // match can select Xray-windows-arm64-v8a.zip (or the 32-bit build) on
    // an x86_64 PC and install a core that cannot run there.
    let wanted: &[&str] = if cfg!(target_os = "windows") {
        if cfg!(target_arch = "aarch64") {
            &["Xray-windows-arm64-v8a.zip"]
        } else {
            &["Xray-windows-64.zip"]
        }
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            &["Xray-macos-arm64-v8a.zip"]
        } else {
            &["Xray-macos-64.zip"]
        }
    } else {
        &["Xray-linux-64.zip"]
    };
    let mut zip_url: Option<String> = None;
    if let Some(assets) = v["assets"].as_array() {
        for a in assets {
            let name = a["name"].as_str().unwrap_or("");
            if wanted.contains(&name) {
                zip_url = a["browser_download_url"].as_str().map(|s| s.to_string());
                break;
            }
        }
        if zip_url.is_none() && cfg!(target_os = "windows") {
            // fallback for future naming changes, but never the arm64/32 build
            for a in assets {
                let name = a["name"].as_str().unwrap_or("");
                if name.starts_with("Xray-windows-")
                    && name.ends_with(".zip")
                    && !name.contains("arm")
                    && !name.contains("32")
                {
                    zip_url = a["browser_download_url"].as_str().map(|s| s.to_string());
                    break;
                }
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

    // 1) download
    let tmp = std::env::temp_dir().join("lionray_xray_update");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| format!("temp dir: {e}"))?;
    let zip_path = tmp.join("xray.zip");

    DL_PROGRESS.store(0, Ordering::Relaxed);
    let dl_url = url.clone();
    let dl_path = zip_path.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let client = reqwest::blocking::Client::builder()
            .user_agent("LionRayVPN/1.8")
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
            if n == 0 {
                break;
            }
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

    // 2) extract
    let (new_exe, bundle_dir) = tokio::task::spawn_blocking({
        let tmp = tmp.clone();
        let zip_path = zip_path.clone();
        move || {
            let extract_dir = tmp.join("extracted");
            std::fs::create_dir_all(&extract_dir).map_err(|e| format!("extract dir: {e}"))?;
            {
                let file = std::fs::File::open(&zip_path).map_err(|e| format!("open zip: {e}"))?;
                let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("invalid zip: {e}"))?;
                archive.extract(&extract_dir).map_err(|e| format!("extract: {e}"))?;
            }
            let inner = std::fs::read_dir(&extract_dir)
                .map_err(|e| format!("list extract: {e}"))?
                .filter_map(|e| e.ok())
                .find(|e| e.path().is_dir() && e.file_name().to_string_lossy().contains("Xray"))
                .map(|e| e.path())
                .unwrap_or(extract_dir.clone());
            let exe_name = if cfg!(target_os = "windows") {
                "xray.exe"
            } else {
                "xray"
            };
            let new_exe = inner.join(exe_name);
            if !new_exe.exists() {
                return Err("xray binary not found in archive".to_string());
            }
            let bin_path = find_xray_binary()?;
            let bundle_dir = bin_path.parent().ok_or("xray dir not found")?.to_path_buf();
            Ok((new_exe, bundle_dir))
        }
    })
    .await
    .map_err(|e| format!("task: {e}"))??;

    let exe_name = if cfg!(target_os = "windows") {
        "xray.exe"
    } else {
        "xray"
    };
    let config_path = dirs::config_dir()
        .map(|d| d.join("lionray-vpn").join("config.json"))
        .unwrap_or_default();

    // 3) baseline latency with the CURRENT core
    let old_exe = find_xray_binary().ok();
    let old_median = if config_path.exists() {
        if let Some(ref oe) = old_exe {
            tokio::task::spawn_blocking({
                let oe = oe.clone();
                let cp = config_path.clone();
                move || measure_core_latency_sync(&oe, &cp)
            })
            .await
            .ok()
            .flatten()
        } else {
            None
        }
    } else {
        None
    };

    // 4) back up the current (working) core
    let bundle_dir_clone = bundle_dir.clone();
    tokio::task::spawn_blocking(move || backup_bundle(&bundle_dir_clone))
        .await
        .ok();

    // 5) swap in the new core
    let swap_res = tokio::task::spawn_blocking({
        let bundle_dir = bundle_dir.clone();
        let inner = new_exe.parent().unwrap().to_path_buf();
        let exe_name = exe_name.to_string();
        move || {
            for name in [exe_name.as_str(), "geoip.dat", "geosite.dat"] {
                let src = inner.join(name);
                if src.exists() {
                    let dst = bundle_dir.join(name);
                    let _ = std::fs::remove_file(&dst);
                    std::fs::copy(&src, &dst).map_err(|e| format!("copy {name}: {e}"))?;
                }
            }
            let _ = std::fs::remove_file(bundle_dir.join("version.txt"));
            Ok::<(), String>(())
        }
    })
    .await;
    if let Err(e) = swap_res {
        let bd = bundle_dir.clone();
        tokio::task::spawn_blocking(move || restore_bundle_backup(&bd)).await.ok();
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(format!("swap failed: {e}"));
    }

    // 6) validate config with the new core
    if config_path.exists() {
        let out = tokio::task::spawn_blocking({
            let new_exe = new_exe.clone();
            let cp = config_path.clone();
            move || std::process::Command::new(&new_exe).args(["run", "-test", "-c"]).arg(&cp).output()
        })
        .await
        .ok()
        .and_then(|r| r.ok());
        let ok = out.map(|o| o.status.success()).unwrap_or(true);
        if !ok {
            let bd = bundle_dir.clone();
            tokio::task::spawn_blocking(move || restore_bundle_backup(&bd)).await.ok();
            let _ = std::fs::remove_dir_all(&tmp);
            return Err("New core failed config validation - kept previous core.".to_string());
        }
    }

    // 7) connectivity + latency test with the new core
    let new_median = if config_path.exists() {
        tokio::task::spawn_blocking({
            let ne = new_exe.clone();
            let cp = config_path.clone();
            move || measure_core_latency_sync(&ne, &cp)
        })
        .await
        .ok()
        .flatten()
    } else {
        Some(0)
    };

    // rollback if broken or much slower (2.5x)
    let rollback = match (old_median, new_median) {
        (Some(o), Some(n)) if n == -2 => true, // broken
        (Some(o), Some(n)) if n >= 0 && o > 0 && n > o * 5 / 2 => true,
        (None, Some(n)) if n == -2 => true,
        _ => false,
    };
    if rollback {
        let bd = bundle_dir.clone();
        tokio::task::spawn_blocking(move || restore_bundle_backup(&bd)).await.ok();
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("New core is slower or broken - kept previous core.".to_string());
    }

    let _ = std::fs::remove_dir_all(&tmp);
    let new_ver = tokio::task::spawn_blocking(get_core_version_sync)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_else(|| "unknown".into());
    Ok(new_ver)
}

#[cfg(target_os = "windows")]
fn backup_bundle(bundle_dir: &std::path::Path) {
    for name in ["xray.exe", "geoip.dat", "geosite.dat"] {
        let src = bundle_dir.join(name);
        if src.exists() {
            let _ = std::fs::copy(&src, bundle_dir.join(format!("{}.bak", name)));
        }
    }
}

#[cfg(target_os = "windows")]
fn restore_bundle_backup(bundle_dir: &std::path::Path) {
    for name in ["xray.exe", "geoip.dat", "geosite.dat"] {
        let bak = bundle_dir.join(format!("{}.bak", name));
        if bak.exists() {
            let dst = bundle_dir.join(name);
            let _ = std::fs::remove_file(&dst);
            let _ = std::fs::copy(&bak, &dst);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn backup_bundle(_d: &std::path::Path) {}
#[cfg(not(target_os = "windows"))]
fn restore_bundle_backup(_d: &std::path::Path) {}

// Returns: -2 = broken (socks never came up), -1 = curl unavailable (skip),
// >=0 = median TLS handshake time in ms.
fn measure_core_latency_sync(exe: &std::path::Path, config_path: &std::path::Path) -> Option<i64> {
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["run", "-c"]).arg(config_path);
    if let Some(d) = config_path.parent() {
        cmd.current_dir(d);
    }
    cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    hide_window(&mut cmd);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return Some(-1),
    };
    let mut ready = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        if socks_listening() {
            ready = true;
            break;
        }
    }
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        return Some(-2);
    }

    // check curl availability
    let curl_path = if std::path::Path::new(r"C:\Windows\System32\curl.exe").exists() {
        r"C:\Windows\System32\curl.exe"
    } else {
        "curl"
    };
    // quick spawn test
    if std::process::Command::new(curl_path).arg("--version").output().is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Some(-1);
    }

    let mut samples: Vec<i64> = Vec::new();
    for _ in 0..3 {
        let out = std::process::Command::new(curl_path)
            .args([
                "-s",
                "--socks5-hostname",
                "127.0.0.1:10808",
                "--max-time",
                "15",
                "-o",
                "NUL",
                "-w",
                "%{time_appconnect}",
                "https://www.google.com/generate_204",
            ])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            if let Ok(ms) = s.trim().parse::<f64>() {
                samples.push((ms * 1000.0) as i64);
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    if samples.is_empty() {
        return Some(-1);
    }
    samples.sort();
    Some(samples[samples.len() / 2])
}

#[tauri::command]
fn get_download_progress() -> u32 {
    DL_PROGRESS.load(Ordering::Relaxed)
}

fn get_core_version_sync() -> Result<String, String> {
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

#[tauri::command]
async fn get_core_version() -> Result<String, String> {
    // spawning the core just to read its version must not block the webview
    tokio::task::spawn_blocking(get_core_version_sync)
        .await
        .map_err(|e| format!("version task failed: {e}"))?
}

// Real, stamped app version (overwritten by the build workflow via sed).
// Read through this command instead of the @tauri-apps/api/app plugin so it
// works without extra capability permissions.
#[tauri::command]
fn app_version() -> String {
    APP_VERSION.to_string()
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
async fn load_store(app: tauri::AppHandle, key: String) -> Result<Option<String>, String> {
    let path = store_path(&app)?;
    tokio::task::spawn_blocking(move || {
        if !path.exists() {
            return Ok(None);
        }
        let s = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let map: Value = serde_json::from_str(&s).unwrap_or(Value::Null);
        Ok(map
            .get(key.as_str())
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()))
    })
    .await
    .map_err(|e| format!("store read task failed: {e}"))?
}

#[tauri::command]
async fn save_store(app: tauri::AppHandle, key: String, value: String) -> Result<(), String> {
    let path = store_path(&app)?;
    tokio::task::spawn_blocking(move || {
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
    })
    .await
    .map_err(|e| format!("store write task failed: {e}"))?
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
            app_version,
            check_update,
            check_xray_core_update,
            load_store,
            save_store,
            get_download_progress,
            update_xray_core,
            open_link,
            is_elevated,
            relaunch_as_admin,
        ])
        .setup(|app| {
            // Heal stale state from a previous crash on a background thread:
            // these spawn reg/netsh child processes and must not hold up the
            // first webview paint. `connect` waits for the flag below.
            std::thread::spawn(|| {
                app_log(&format!("app start v{}", APP_VERSION));
                restore_stale_proxy();
                clear_tunnel_host_route();
                restore_singbox_tun_state();
                STARTUP_CLEANUP_DONE.store(true, Ordering::Release);
            });

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

            // Remove Wintun devices left behind by a previous force-killed
            // sing-box before the user starts a new TUN session.
            #[cfg(windows)]
            std::thread::spawn(sweep_phantom_wintun);

            // Self-healing watchdog. Detects three distinct failures:
            //  * hard — xray / sing-box process exited
            //  * soft — the local SOCKS port stopped accepting connections
            //  * net  — process alive and port listening, but the tunnel cannot
            //           carry traffic (this is what used to require a manual
            //           reconnect after a drop)
            // It never "gives up" while AUTO is set; it only backs off.
            std::thread::spawn(|| {
                let mut retries: u32 = 0;
                let mut dead_streak: u32 = 0;
                let mut probe_fail_streak: u32 = 0;
                let mut tick: u32 = 0;
                const DEAD_THRESHOLD: u32 = 2; // 2 * 5 s for soft failures
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    tick = tick.wrapping_add(1);
                    if !AUTO.load(Ordering::SeqCst) {
                        retries = 0;
                        dead_streak = 0;
                        probe_fail_streak = 0;
                        continue;
                    }
                    let child_alive = match CHILD.lock() {
                        Ok(mut g) => match g.as_mut() {
                            Some(c) => matches!(c.try_wait(), Ok(None)),
                            None => false,
                        },
                        Err(_) => false,
                    };
                    let tun_needed = LAST
                        .lock()
                        .ok()
                        .and_then(|g| g.as_ref().map(|l| l.tun))
                        .unwrap_or(false);
                    let hard_dead = !child_alive || (tun_needed && !tun_alive());
                    let soft_dead = !hard_dead && !socks_listening();

                    // End-to-end probe every 30 s. In TUN mode a direct request
                    // traverses the adapter, so it tests the whole path.
                    let mut net_dead = false;
                    if !hard_dead && !soft_dead && tick % 6 == 0 {
                        let ok = if tun_needed { probe_direct() } else { probe_via_socks() };
                        if ok {
                            probe_fail_streak = 0;
                        } else {
                            probe_fail_streak += 1;
                            app_log(&format!(
                                "watchdog: tunnel probe failed ({probe_fail_streak}/3)"
                            ));
                            net_dead = probe_fail_streak >= 3;
                        }
                    }

                    // Another app/installer can flip the Windows proxy off;
                    // restore ours every 60 s so the browser keeps using it.
                    if !hard_dead && !soft_dead && !net_dead && !tun_needed && tick % 12 == 0 {
                        if !system_proxy_is_ours() {
                            app_log("watchdog: system proxy was reset - restoring");
                            set_system_proxy(true);
                        }
                    }

                    if !hard_dead && !soft_dead && !net_dead {
                        retries = 0;
                        dead_streak = 0;
                        continue;
                    }
                    if !hard_dead && !net_dead {
                        dead_streak += 1;
                        if dead_streak < DEAD_THRESHOLD {
                            continue;
                        }
                    }
                    dead_streak = 0;
                    probe_fail_streak = 0;

                    let Some(l) = LAST.lock().ok().and_then(|g| g.clone()) else {
                        app_log("watchdog: no saved connection - auto-reconnect stopped");
                        reset_tunnel_state();
                        AUTO.store(false, Ordering::SeqCst);
                        continue;
                    };
                    retries = retries.saturating_add(1);
                    app_log(&format!(
                        "watchdog: reconnect attempt {retries} (hard={hard_dead} net={net_dead})"
                    ));
                    let ok = establish(
                        &l.server, &l.routing, &l.dns, l.ad_block, &l.bypass, l.tun, l.udp,
                        l.ipv6, l.fragment,
                    )
                    .is_ok();
                    if ok {
                        retries = 0;
                        app_log("watchdog: reconnected");
                        // let the new tunnel settle before the next probe
                        std::thread::sleep(std::time::Duration::from_secs(15));
                    } else {
                        // Don't leave the OS pointing at a dead core while we
                        // back off — every app would look offline.
                        reset_tunnel_state();
                        let backoff = if retries >= 6 { 60 } else { 15 };
                        app_log(&format!(
                            "watchdog: reconnect failed - next attempt in {backoff}s"
                        ));
                        std::thread::sleep(std::time::Duration::from_secs(backoff));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn user_server() -> Server {
        Server {
            protocol: "vless".into(),
            address: "smp.settminpaing.mm.am".into(),
            port: 443,
            uuid: "5f487d99-05c7-4f7c-8b18-987c247d716e".into(),
            network: "ws".into(),
            security: "tls".into(),
            sni: "smp.settminpaing.mm.am".into(),
            fingerprint: "chrome".into(),
            ws_path: "/?ed=2560".into(),
            ws_host: "smp.settminpaing.mm.am".into(),
            fragment: "1,40-60,30-50,tlshello".into(),
            ..Server::default()
        }
    }

    #[test]
    fn fragment_parses_shadowrocket_format() {
        let spec = parse_fragment_spec("1,40-60,30-50,tlshello").expect("spec");
        assert_eq!(spec.packets, "tlshello");
        assert_eq!(spec.length, "40-60");
        // long Shadowrocket waits are capped so the handshake stays fast
        assert_eq!(spec.interval, "1-3");
        assert!(parse_fragment_spec("0,40-60,30-50").is_none());
        assert!(parse_fragment_spec("").is_none());
    }

    #[test]
    fn config_routes_proxy_through_fragment_outbound() {
        let cfg: Value = serde_json::from_str(
            &generate_config(&user_server(), "global", "system", false, &[], false, false, true)
                .unwrap(),
        )
        .unwrap();
        let outbounds = cfg["outbounds"].as_array().unwrap();
        // proxy must be first (Xray's default outbound), never freedom
        assert_eq!(outbounds[0]["tag"], "proxy");
        assert_eq!(
            outbounds[0]["streamSettings"]["sockopt"]["dialerProxy"],
            "fragment"
        );
        assert_eq!(outbounds[1]["tag"], "fragment");
        assert_eq!(outbounds[1]["settings"]["fragment"]["packets"], "tlshello");
        assert_eq!(outbounds[1]["settings"]["fragment"]["length"], "40-60");
        assert_eq!(outbounds[1]["settings"]["fragment"]["interval"], "1-3");
        // SNI and WS Host stay on the hostname
        assert_eq!(
            outbounds[0]["streamSettings"]["tlsSettings"]["serverName"],
            "smp.settminpaing.mm.am"
        );
        assert_eq!(
            outbounds[0]["streamSettings"]["wsSettings"]["headers"]["Host"],
            "smp.settminpaing.mm.am"
        );
        assert_eq!(
            outbounds[0]["streamSettings"]["wsSettings"]["path"],
            "/?ed=2560"
        );
    }

    #[test]
    fn fragment_is_ignored_when_disabled_or_plaintext() {
        let s = user_server();
        let cfg =
            generate_config(&s, "global", "system", false, &[], false, false, false).unwrap();
        assert!(!cfg.contains("\"fragment\""));
        let mut plain = user_server();
        plain.security = "none".into();
        let cfg =
            generate_config(&plain, "global", "system", false, &[], false, false, true).unwrap();
        assert!(!cfg.contains("\"fragment\""));
    }

    #[test]
    fn system_dns_uses_os_resolver_and_defaults_are_tcp_ipv4() {
        let cfg: Value = serde_json::from_str(
            &generate_config(&user_server(), "global", "system", false, &[], false, false, false)
                .unwrap(),
        )
        .unwrap();
        assert!(cfg.get("dns").is_none());
        assert_eq!(cfg["routing"]["domainStrategy"], "AsIs");
        // UDP off by default
        assert_eq!(cfg["inbounds"][0]["settings"]["udp"], false);
        let final_rule = cfg["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["outboundTag"] == "proxy")
            .unwrap();
        assert_eq!(final_rule["network"], "tcp");
        // IPv6 off by default: IPv6 literals blocked, direct traffic is IPv4
        assert!(cfg["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["ip"][0] == "::/0" && r["outboundTag"] == "block"));
        assert!(cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["tag"] == "direct" && o["settings"]["domainStrategy"] == "UseIPv4"));

        let explicit = generate_config(
            &user_server(), "global", "cloudflare", true, &[], true, true, false,
        )
        .unwrap();
        assert!(explicit.contains("1.1.1.1"));
        assert!(explicit.contains("UseIP"));
    }

    #[test]
    fn tun_defaults_to_tcp_and_ipv4() {
        let cfg: Value =
            serde_json::from_str(&generate_tun_config("system", "LionRayTunTest", false, false))
                .unwrap();
        assert_eq!(cfg["dns"]["strategy"], "ipv4_only");
        assert_eq!(cfg["inbounds"][0]["address"].as_array().unwrap().len(), 1);
        assert!(cfg["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["network"] == "udp" && r["action"] == "reject"));

        let cfg6: Value =
            serde_json::from_str(&generate_tun_config("system", "LionRayTunTest", true, true))
                .unwrap();
        assert_eq!(cfg6["dns"]["strategy"], "prefer_ipv4");
        assert_eq!(cfg6["inbounds"][0]["address"].as_array().unwrap().len(), 2);
        assert!(!cfg6["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["network"] == "udp"));
    }

    #[test]
    fn vless_uri_roundtrip_keeps_fragment() {
        let uri = build_uri(&user_server()).unwrap();
        assert!(
            uri.contains("fragment=1%2C40-60%2C30-50%2Ctlshello"),
            "{uri}"
        );
        let parsed = parse_vless(&uri).unwrap();
        assert_eq!(parsed.fragment, "1,40-60,30-50,tlshello");
        assert_eq!(parsed.ws_path, "/?ed=2560");
    }
}
