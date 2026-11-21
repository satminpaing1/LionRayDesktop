import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { invoke, Channel } from "@tauri-apps/api/core";
import { getCurrentWindow, currentMonitor, LogicalSize } from "@tauri-apps/api/window";

import jsQR from "jsqr";
import QRCode from "qrcode";

interface Server {
  id: number;
  name: string;
  protocol: string;
  address: string;
  port: number;
  uuid: string;
  network: string;
  security: string;
  ping: number | null;
  flow: string;
  sni: string;
  fingerprint: string;
  alpn: string;
  allow_insecure: boolean;
  pbk: string;
  sid: string;
  ws_path: string;
  ws_host: string;
  grpc_service_name: string;
  /** TLS ClientHello fragmentation spec from the share link, e.g. "1,40-60,30-50,tlshello". */
  fragment?: string;
  subId?: number;
}

interface Sub {
  id: number;
  name: string;
  url: string;
  loading?: boolean;
}

interface ExitInfo {
  query?: string;
  country?: string;
  countryCode?: string;
  city?: string;
  isp?: string;
}

interface Settings {
  routing: "global" | "lan" | "cn";
  dns: string;
  adBlock: boolean;
  bypassDomains: string[];
  dark: boolean;
  autoConnect: boolean;
  subAutoUpdate: boolean;
  tunMode: boolean;
  /** Allow UDP relay (QUIC/games). Off = TCP only. */
  udp: boolean;
  /** Allow IPv6. Off = IPv4 only. */
  ipv6: boolean;
  /** Apply the share link's TLS fragment value. Off by default. */
  fragment: boolean;
}

const DEFAULT_SETTINGS: Settings = {
  routing: "lan",
  dns: "system",
  adBlock: true,
  bypassDomains: [],
  dark: false,
  autoConnect: false,
  subAutoUpdate: false,
  tunMode: false,
  udp: false,
  ipv6: false,
  fragment: false,
};

const IS_WINDOWS = typeof navigator !== "undefined" && /Windows/i.test(navigator.userAgent);

type Tab = "home" | "servers" | "subs" | "settings" | "logs";
type LogKind = "app" | "xray" | "singbox";
type LogLevel = "all" | "warn" | "error";
type SheetMode = null | "menu" | "sub";

const PROTO_COLORS: Record<string, string> = { vless: "#6366F1", trojan: "#F59E0B", shadowsocks: "#10B981" };
const protoLabel = (p?: string): string => {
  const key = (p || "").toLowerCase();
  if (key === "shadowsocks") return "SS";
  if (key === "vless") return "VLESS";
  if (key === "vmess") return "VMESS";
  if (key === "trojan") return "TROJAN";
  return (p || "???").slice(0, 4).toUpperCase();
};
// App Version is read from Tauri at runtime (the appVer state) so the
// Settings screen always shows the real, stamped build version.
let idCounter = Date.now() % 100000;

const pingColor = (ms: number | null): string =>
  ms === null ? "var(--sub)" : ms < 0 ? "#EF4444" : ms < 150 ? "#10B981" : ms < 350 ? "#F59E0B" : "#EF4444";

type IconName =
  | "shield" | "home" | "globe" | "layers" | "terminal" | "sliders"
  | "power" | "download" | "upload" | "server" | "chevron" | "arrow-left"
  | "plus" | "refresh" | "copy" | "trash" | "search" | "close"
  | "camera" | "image" | "clipboard" | "link" | "edit" | "share"
  | "more" | "timer" | "check" | "lock";

// One consistent line-icon set instead of multicolour emoji, so the whole
// window reads as one calm surface.
function Icon({ name, size = 20, strokeWidth = 1.8 }: { name: IconName; size?: number; strokeWidth?: number }) {
  let body: React.ReactNode;
  switch (name) {
    case "shield":
      body = <><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3Z" /><path d="m9.5 12 1.7 1.7 3.3-3.4" /></>;
      break;
    case "home":
      body = <><path d="m3 10.5 9-7.5 9 7.5" /><path d="M5.5 9.5V20a1 1 0 0 0 1 1H10v-5h4v5h3.5a1 1 0 0 0 1-1V9.5" /></>;
      break;
    case "globe":
      body = <><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17" /><path d="M12 3.5c2.4 2.3 3.6 5.1 3.6 8.5S14.4 18.2 12 20.5c-2.4-2.3-3.6-5.1-3.6-8.5S9.6 5.8 12 3.5Z" /></>;
      break;
    case "layers":
      body = <><path d="m12 3 9 5-9 5-9-5 9-5Z" /><path d="m3 12 9 5 9-5" /><path d="m3 16 9 5 9-5" /></>;
      break;
    case "terminal":
      body = <><rect x="3" y="4.5" width="18" height="15" rx="3" /><path d="m7 9 3 3-3 3" /><path d="M13 15h4" /></>;
      break;
    case "sliders":
      body = <><path d="M4 7h3" /><circle cx="9" cy="7" r="2" /><path d="M11 7h9" /><path d="M4 17h7" /><circle cx="13" cy="17" r="2" /><path d="M15 17h5" /></>;
      break;
    case "power":
      body = <><path d="M12 3v9" /><path d="M6.4 6.4a8 8 0 1 0 11.2 0" /></>;
      break;
    case "download":
      body = <><path d="M12 3v12" /><path d="m7.5 10.5 4.5 4.5 4.5-4.5" /><path d="M4 20h16" /></>;
      break;
    case "upload":
      body = <><path d="M12 16V4" /><path d="m7.5 8.5 4.5-4.5 4.5 4.5" /><path d="M4 20h16" /></>;
      break;
    case "server":
      body = <><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 7.5h.01M7 16.5h.01" /></>;
      break;
    case "chevron":
      body = <path d="m9 5 7 7-7 7" />;
      break;
    case "arrow-left":
      body = <><path d="M19 12H5" /><path d="m11 18-6-6 6-6" /></>;
      break;
    case "plus":
      body = <path d="M12 5v14M5 12h14" />;
      break;
    case "refresh":
      body = <><path d="M20 11a8 8 0 1 0-2.3 5.7" /><path d="M20 4v7h-7" /></>;
      break;
    case "copy":
      body = <><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3" /></>;
      break;
    case "trash":
      body = <><path d="M4 7h16" /><path d="M9 7V4h6v3" /><path d="m6.5 7 1 13h9l1-13" /><path d="M10 11v5M14 11v5" /></>;
      break;
    case "search":
      body = <><circle cx="11" cy="11" r="6.5" /><path d="m16 16 4 4" /></>;
      break;
    case "close":
      body = <path d="m6 6 12 12M18 6 6 18" />;
      break;
    case "camera":
      body = <><path d="M4 8h3l1.5-2h7L17 8h3a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1Z" /><circle cx="12" cy="13" r="3.2" /></>;
      break;
    case "image":
      body = <><rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="8.5" cy="9" r="1.5" /><path d="m21 16-5-5L5 20" /></>;
      break;
    case "clipboard":
      body = <><rect x="5" y="4" width="14" height="17" rx="2" /><path d="M9 4V3h6v1" /><path d="M8.5 9h7M8.5 13h7M8.5 17h4" /></>;
      break;
    case "link":
      body = <><path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.2 1.2" /><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.2-1.2" /></>;
      break;
    case "edit":
      body = <><path d="M4 20h4l10-10-4-4L4 16v4Z" /><path d="m13.5 6.5 4 4" /></>;
      break;
    case "share":
      body = <><path d="M14 4h6v6" /><path d="m20 4-9 9" /><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" /></>;
      break;
    case "more":
      body = <><circle cx="5" cy="12" r="1.2" fill="currentColor" stroke="none" /><circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none" /><circle cx="19" cy="12" r="1.2" fill="currentColor" stroke="none" /></>;
      break;
    case "timer":
      body = <><circle cx="12" cy="13" r="8" /><path d="M12 9v4l2.5 1.5" /><path d="M9 3h6" /></>;
      break;
    case "check":
      body = <path d="m5 12.5 4.5 4.5L19 7.5" />;
      break;
    case "lock":
      body = <><rect x="4.5" y="10" width="15" height="10.5" rx="2.5" /><path d="M8 10V7.5a4 4 0 0 1 8 0V10" /></>;
      break;
  }
  return (
    <svg
      width={size} height={size} viewBox="0 0 24 24" aria-hidden="true"
      fill="none" stroke="currentColor" strokeWidth={strokeWidth}
      strokeLinecap="round" strokeLinejoin="round"
    >
      {body}
    </svg>
  );
}

interface ServerRowProps {
  s: Server;
  selected: boolean;
  onSelect: (id: number) => void;
  onPing: (id: number) => void;
  onMenu: (s: Server) => void;
}

// memoized: only re-renders when its own `s` / `selected` / handlers change
const ServerRow = React.memo(function ServerRow({ s, selected, onSelect, onPing, onMenu }: ServerRowProps) {
  return (
    <div className={`row ${selected ? "sel" : ""}`} onClick={() => onSelect(s.id)}>
      <span className={`radio ${selected ? "on" : ""}`} />
      <span
        className="proto-chip"
        style={{
          background: `${PROTO_COLORS[s.protocol] || "#64748B"}14`,
          color: PROTO_COLORS[s.protocol] || "#64748B",
          borderColor: `${PROTO_COLORS[s.protocol] || "#64748B"}26`,
        }}
      >
        {protoLabel(s.protocol)}
      </span>
      <div className="row-main">
        <div className="row-name">{s.name || "Unnamed"}</div>
        <div className="row-meta">{(s.security || "none").toUpperCase()} · {(s.network || "tcp").toUpperCase()}</div>
      </div>
      <span className="ping-val" style={{ color: pingColor(s.ping) }} onClick={(e) => { e.stopPropagation(); onPing(s.id); }}>
        {s.ping == null ? "—" : s.ping < 0 ? "ERR" : `${s.ping}`}
      </span>
      <button className="row-more" title="More actions" onClick={(e) => { e.stopPropagation(); onMenu(s); }}>
        <Icon name="more" size={16} />
      </button>
    </div>
  );
});

// persistence now goes through the Rust side (a JSON file in the app data
// dir) — WKWebView's localStorage is not reliable across restarts in Tauri v2.
async function loadStore<T>(key: string, fallback: T): Promise<T> {
  try {
    const raw = await invoke<string | null>("load_store", { key });
    if (raw) return JSON.parse(raw) as T;
  } catch {}
  return fallback;
}
async function saveStore(key: string, val: unknown) {
  try {
    await invoke("save_store", { key, value: JSON.stringify(val) });
  } catch {}
}

function flagEmoji(cc?: string): string {
  if (!cc || cc.length !== 2) return "🌐";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 127397 + c.charCodeAt(0)));
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url.slice(0, 30);
  }
}

// ── error boundary: show errors instead of a blank/dead screen ──
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { err: string | null }
> {
  state = { err: null as string | null };
  static getDerivedStateFromError(e: unknown) {
    return { err: e instanceof Error ? e.message + "\n" + (e.stack || "") : String(e) };
  }
  render() {
    if (this.state.err)
      return (
        <div style={{ padding: 24, color: "#fff", fontFamily: "monospace", fontSize: 12, whiteSpace: "pre-wrap" }}>
          <b style={{ color: "#EF4444" }}>App crashed:</b>
          {"\n\n"}
          {this.state.err}
        </div>
      );
    return this.props.children;
  }
}

// ─── formatting helpers (module scope: used by App + LiveStats) ───
const fmtTime = (sec: number) =>
  `${String(Math.floor(sec / 3600)).padStart(2, "0")}:${String(Math.floor((sec % 3600) / 60)).padStart(2, "0")}:${String(sec % 60).padStart(2, "0")}`;

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}
function fmtRate(bps: number): string {
  return `${fmtBytes(bps)}/s`;
}

// Live, per-second stats. Isolated here so the parent <App> does NOT
// re-render every second (important on older macOS / WebKit).
function LiveStats() {
  const [elapsed, setElapsed] = useState(0);
  const [speeds, setSpeeds] = useState({ down: "—", up: "—" });
  const [totals, setTotals] = useState({ down: 0, up: 0 });

  useEffect(() => {
    const t = setInterval(() => setElapsed((e) => e + 1), 1000);

    // system-wide speed via sysinfo (always works)
    let sysT = Date.now();
    let sysDown = -1;
    let sysUp = -1;
    let smDown = 0;
    let smUp = 0;
    let speedBusy = false;
    const A = 0.3; // EMA smoothing
    const sysPoll = setInterval(async () => {
      // never queue overlapping invokes if a sample is slow (sleep/resume)
      if (speedBusy) return;
      speedBusy = true;
      try {
        const r = await invoke<{ down: number; up: number }>("get_net_speed");
        const now = Date.now();
        const dt = Math.max((now - sysT) / 1000, 0.001);
        if (sysDown >= 0) {
          const rd = Math.max(0, (r.down - sysDown) / dt);
          const ru = Math.max(0, (r.up - sysUp) / dt);
          smDown = smDown ? smDown + A * (rd - smDown) : rd;
          smUp = smUp ? smUp + A * (ru - smUp) : ru;
          setSpeeds({ down: fmtRate(smDown), up: fmtRate(smUp) });
        }
        sysDown = r.down;
        sysUp = r.up;
        sysT = now;
      } catch { /* ignore */ }
      finally { speedBusy = false; }
    }, 1000);

    // xray session totals spawn a 35 MB CLI process per query — poll sparingly
    // so the tool stays light. System speed above still updates every second.
    let trafficBusy = false;
    const tpoll = setInterval(() => {
      if (trafficBusy) return;
      trafficBusy = true;
      invoke<{ down: number; up: number }>("get_traffic")
        .then((r) => setTotals({ down: r.down, up: r.up }))
        .catch(() => {})
        .finally(() => { trafficBusy = false; });
    }, 20000);

    return () => {
      clearInterval(t);
      clearInterval(sysPoll);
      clearInterval(tpoll);
    };
  }, []);

  return (
    <div className="stat-grid">
      <div className="stat">
        <span className="stat-label"><Icon name="download" size={12} /> Download</span>
        <b className="stat-val">{speeds.down}</b>
      </div>
      <div className="stat">
        <span className="stat-label"><Icon name="upload" size={12} /> Upload</span>
        <b className="stat-val">{speeds.up}</b>
      </div>
      <div className="stat" title={`This session: ${fmtBytes(totals.down)} down · ${fmtBytes(totals.up)} up`}>
        <span className="stat-label"><Icon name="timer" size={12} /> Session</span>
        <b className="stat-val">{fmtTime(elapsed)}</b>
      </div>
    </div>
  );
}

// Colorise log lines so errors / warnings stand out at a glance.
function logLineClass(line: string): string {
  const s = line.toLowerCase();
  if (/fatal|error|failed|refused|eof|timeout|timed out|probe failed|no usage|denied/.test(s)) return "err";
  if (/warn|deprecated|retry|slow|stale/.test(s)) return "warn";
  if (/ok|connected|confirmed|success|accepted|started|listening|204/.test(s)) return "ok";
  return "";
}

function App() {
  const [tab, setTab] = useState<Tab>("home");
  const [servers, setServers] = useState<Server[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [subs, setSubs] = useState<Sub[]>([]);
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [selBusy, setSelBusy] = useState(false);
  const [toast, setToast] = useState<{ msg: string; bad?: boolean } | null>(null);
  const [sheet, setSheet] = useState<SheetMode>(null);
  const [subUrl, setSubUrl] = useState("");
  const [qrOpen, setQrOpen] = useState(false);
  const [exitInfo, setExitInfo] = useState<ExitInfo | null>(null);
  const [coreVer, setCoreVer] = useState("...");
  // xray core updates are intentionally disabled (see backend PINNED_XRAY_VERSION)
  const [xrayUpdate, setXrayUpdate] = useState<{ version: string; url: string } | null>(null);
  const [xrayUpdating, setXrayUpdating] = useState(false);
  const [xrayProgress, setXrayProgress] = useState(0);
  const [xrayCheckMsg, setXrayCheckMsg] = useState("");
  const [confirmDlg, setConfirmDlg] = useState<{ msg: string; onOk: () => void } | null>(null);
  const [bypassInput, setBypassInput] = useState("");
  const [appUpdate, setAppUpdate] = useState<string | null>(null);
  const [logKind, setLogKind] = useState<LogKind>("app");
  const [logs, setLogs] = useState<Record<LogKind, string>>({ app: "", xray: "", singbox: "" });
  const [logBusy, setLogBusy] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [logLevel, setLogLevel] = useState<LogLevel>("all");
  const [logQuery, setLogQuery] = useState("");
  const logBoxRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const loadedRef = useRef(false);
  // set while a manual disconnect is in progress so the heartbeat's
  // auto-reconnect doesn't fire on the brief "xray is dead" window
  const manualDisconnectRef = useRef(false);
  const [editing, setEditing] = useState<Server | null>(null);
  const [menuServer, setMenuServer] = useState<Server | null>(null);
  const [ef, setEf] = useState<Partial<Server>>({});
  const [sharing, setSharing] = useState<{ srv: Server; uri: string } | null>(null);
  const [qrUrl, setQrUrl] = useState("");
  const [appVer, setAppVer] = useState("…");

  const activeServer = servers.find((s) => s.id === activeId) ?? null;
  const manualServers = useMemo(() => servers.filter((s) => s.subId == null), [servers]);

  // load persisted data from the Rust store on first mount
  useEffect(() => {
    (async () => {
      try {
        invoke<string>("app_version").then(setAppVer).catch(() => {});
        const s = await loadStore<Server[]>("lr_servers", []);
        setServers(
          (s || []).map((x) => ({
            ...x,
            protocol: x.protocol || "vless",
            security: x.security || "none",
            network: x.network || "tcp",
            name: x.name || "Unnamed",
            address: x.address || "",
            port: x.port || 443,
          }))
        );
        setActiveId(await loadStore<number | null>("lr_active", null));
        setSubs(await loadStore<Sub[]>("lr_subs", []));
        const savedSettings = await loadStore<Partial<Settings>>("lr_settings", {});
        setSettings({ ...DEFAULT_SETTINGS, ...savedSettings });
      } catch {
        /* ignore */
      }
      loadedRef.current = true;
    })();
  }, []);

  // persist (guarded so the initial empty state doesn't clobber the store)
  useEffect(() => {
    if (loadedRef.current) saveStore("lr_servers", servers);
  }, [servers]);
  useEffect(() => {
    if (loadedRef.current) saveStore("lr_active", activeId);
  }, [activeId]);
  useEffect(() => {
    if (loadedRef.current) saveStore("lr_subs", subs);
  }, [subs]);
  useEffect(() => {
    if (loadedRef.current) saveStore("lr_settings", settings);
  }, [settings]);
  useEffect(() => {
    document.documentElement.classList.toggle("dark", settings.dark);
  }, [settings.dark]);

  // notify the user when a newer desktop release is published. Delayed so the
  // GitHub request never competes with window paint / auto-connect on launch.
  useEffect(() => {
    const t = setTimeout(() => {
      invoke<string | null>("check_update")
        .then((v) => { if (v) setAppUpdate(v); })
        .catch(() => {});
    }, 2500);
    return () => clearTimeout(t);
  }, []);

  const showToast = useCallback((msg: string, bad = false) => {
    setToast({ msg, bad });
    setTimeout(() => setToast(null), 2600);
  }, []);

  // ─── logs: read / refresh / clear from inside the app ───
  const loadLogs = useCallback(async (silent = false) => {
    if (!silent) setLogBusy(true);
    try {
      const data = await invoke<Record<string, string>>("read_logs");
      setLogs({
        app: data.app || "",
        xray: data.xray || "",
        singbox: data.singbox || "",
      });
    } catch (e) {
      if (!silent) showToast(`Log ဖတ်လို့မရပါ: ${e}`, true);
    } finally {
      if (!silent) setLogBusy(false);
    }
  }, [showToast]);

  const clearLogs = useCallback(() => {
    setConfirmDlg({
      msg: "Log အားလုံး (App / Xray / TUN) ကို ဖျက်မလား?\nဒါကနောက်ပြန်ရလို့မရပါဘူး။",
      onOk: async () => {
        setConfirmDlg(null);
        try {
          await invoke("clear_logs");
          setLogs({ app: "", xray: "", singbox: "" });
          showToast("Log တွေ ရှင်းပြီး ✅");
        } catch (e) {
          showToast(`Log ဖျက်လို့မရပါ: ${e}`, true);
        }
      },
    });
  }, [showToast]);

  const copyLogs = useCallback(async () => {
    const text = logs[logKind];
    if (!text) { showToast("Copy လုပ်စရာ log မရှိသေးပါ", true); return; }
    try {
      await invoke("copy_clipboard", { text });
      showToast("Log ကို copy လုပ်ပြီး ✅");
    } catch (e) {
      showToast(`Copy မရပါ: ${e}`, true);
    }
  }, [logs, logKind, showToast]);

  // Live-refresh while the Logs tab is open so a drop can be watched in real time.
  useEffect(() => {
    if (tab !== "logs") return;
    void loadLogs(true);
    const timer = setInterval(() => void loadLogs(true), 4000);
    return () => clearInterval(timer);
  }, [tab, loadLogs]);

  // Follow the newest line unless the user scrolled up to read history.
  useEffect(() => {
    if (tab !== "logs" || !autoScroll) return;
    const box = logBoxRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [logs, logKind, logLevel, logQuery, autoScroll, tab]);

  const onLogScroll = useCallback(() => {
    const box = logBoxRef.current;
    if (!box) return;
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 48;
    setAutoScroll(atBottom);
  }, []);

  // Only render what the user asked for. Capping the DOM keeps the console
  // rock-steady instead of re-laying out thousands of lines every refresh.
  const { shownLines, totalLines } = useMemo(() => {
    const raw = logs[logKind];
    if (!raw) return { shownLines: [] as { n: number; text: string; cls: string }[], totalLines: 0 };
    const q = logQuery.trim().toLowerCase();
    const all = raw.replace(/\r\n?/g, "\n").split("\n");
    while (all.length && all[all.length - 1].trim() === "") all.pop();
    const picked: { n: number; text: string; cls: string }[] = [];
    for (let i = 0; i < all.length; i++) {
      const text = all[i].replace(/\u001b\[[0-9;?]*[A-Za-z]/g, "");
      const cls = logLineClass(text);
      if (logLevel === "error" && cls !== "err") continue;
      if (logLevel === "warn" && cls !== "err" && cls !== "warn") continue;
      if (q && !text.toLowerCase().includes(q)) continue;
      picked.push({ n: i + 1, text, cls });
    }
    return { shownLines: picked.slice(-500), totalLines: picked.length };
  }, [logs, logKind, logLevel, logQuery]);

  // ─── restart with UAC so TUN mode can create its adapter ───
  const requestAdmin = useCallback(() => {
    setConfirmDlg({
      msg:
        "TUN mode captures every app on this PC, which requires administrator rights.\n\n" +
        "LionRay will restart elevated. Any current connection will be closed. Continue?",
      onOk: async () => {
        setConfirmDlg(null);
        try {
          if (connected) {
            manualDisconnectRef.current = true;
            await invoke("disconnect").catch(() => {});
            setConnected(false);
            manualDisconnectRef.current = false;
          }
          await invoke("relaunch_as_admin");
        } catch (e) {
          showToast(String(e), true);
        }
      },
    });
  }, [connected, showToast]);

  // ─── init ───
  const doConnect = useCallback(
    async (srv: Server, silent = false) => {
      // TUN needs an elevated process. Prompt once instead of failing with a
      // raw error, and let auto-connect stay quiet until the user acts.
      if (settings.tunMode && IS_WINDOWS && !isAdmin) {
        if (!silent) requestAdmin();
        return;
      }
      setBusy(true);
      try {
        const mode = await invoke<string>("connect", {
          server: { ...srv, id: 0, ping: null },
          routing: settings.routing,
          dns: settings.dns,
          adBlock: settings.adBlock,
          bypassDomains: settings.bypassDomains,
          tun: settings.tunMode,
          udp: settings.udp,
          ipv6: settings.ipv6,
          fragment: settings.fragment,
        });
        setConnected(true);
        const label = settings.tunMode && mode?.includes("Proxy") ? "Proxy ✓" : "Connected ✓";
        if (!silent) showToast(label, false);
        else showToast(`Auto-connected: ${mode?.replace("Connected via", "").trim() || "tunnel"}`);
      } catch (e) {
        if (!silent) showToast(String(e), true);
      }
      setBusy(false);
    },
    [settings.routing, settings.dns, settings.adBlock, settings.bypassDomains, settings.tunMode, settings.udp, settings.ipv6, settings.fragment, isAdmin, requestAdmin, showToast]
  );

  useEffect(() => {
    invoke<boolean>("is_connected").then(setConnected).catch(() => {});
    invoke<string>("get_core_version").then(setCoreVer).catch(() => {});
    invoke<boolean>("is_elevated").then(setIsAdmin).catch(() => {});
  }, []);

  const checkXrayUpdate = async () => {
    setXrayCheckMsg("Checking…");
    try {
      const r = await invoke<{ version: string; url: string } | null>("check_xray_core_update");
      if (r) {
        setXrayUpdate(r);
        setXrayCheckMsg(`v${r.version} available`);
      } else {
        setXrayUpdate(null);
        setXrayCheckMsg("Xray core is up to date ✓");
      }
    } catch (e: any) {
      const msg = typeof e === "string" ? e : e?.message || "Check failed";
      setXrayCheckMsg(`Error: ${msg.slice(0, 100)}`);
    }
  };

  useEffect(() => {
    // subscription auto-update on launch
    if (settings.subAutoUpdate && subs.length) {
      updateAllSubscriptions();
    }
    if (settings.autoConnect && !connected && !busy) {
      const srv = activeServer ?? servers[0];
      if (srv) {
        const t = setTimeout(() => doConnect(srv, true), 200);
        return () => clearTimeout(t);
      }
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // auto-check xray update when settings tab opens
  useEffect(() => {
    if (tab === "settings") {
      // always re-check for an available app update (shows the global banner)
      invoke<string | null>("check_update")
        .then((t) => { if (t) setAppUpdate(t); })
        .catch(() => {});
    }
  }, [tab]);

  // ─── fit the window to the current screen so it never overflows ───
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const win = getCurrentWindow();
        const mon = await currentMonitor();
        if (!mon || cancelled) return;
        const sf = mon.scaleFactor;
        const availW = mon.workArea.size.width / sf;
        const availH = mon.workArea.size.height / sf;
        const w = Math.round(Math.max(360, Math.min(410, availW - 24)));
        const h = Math.round(Math.max(480, Math.min(700, availH - 24)));
        await win.setSize(new LogicalSize(w, h));
        await win.center();
      } catch {
        /* non-fatal: keep config defaults */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // ─── exit-ip lookup (15s) while connected ───
  // NOTE: live per-second stats (elapsed / speeds / totals) live in the
  // <LiveStats> child so the whole App no longer re-renders every tick.
  useEffect(() => {
    if (!connected) return;
    let exitBusy = false;
    const check = () => {
      if (exitBusy) return;
      exitBusy = true;
      invoke<ExitInfo>("check_exit_ip")
        .then((j) => setExitInfo(j))
        .catch(() => {})
        .finally(() => { exitBusy = false; });
    };
    const first = setTimeout(check, 300);
    const poll = setInterval(check, 20000);

    return () => {
      clearTimeout(first);
      clearInterval(poll);
    };
  }, [connected]);

  // Background connection heartbeat. The backend repairs Windows networking
  // immediately when the core/TUN dies but never reconnects by itself, so this
  // only mirrors its state and tells the user to tap Connect when ready.
  useEffect(() => {
    let last: boolean | null = null;
    const heartbeat = setInterval(async () => {
      if (manualDisconnectRef.current) return;
      try {
        const alive = await invoke<boolean>("is_connected");
        if (manualDisconnectRef.current) return;
        if (last !== null && last !== alive) {
          showToast(alive ? "Connected ✓" : "Connection lost — network restored, tap Connect to retry", !alive);
        }
        last = alive;
        setConnected(alive);
      } catch { /* backend busy; try again next tick */ }
    }, 5000);
    return () => clearInterval(heartbeat);
  }, [showToast]);

  // ─── import helpers ───
  const appendServers = (list: Server[], subId?: number) => {
    if (!list.length) return showToast("No valid servers found", true);
    const tagged = list.map((s) => ({ ...s, id: ++idCounter, ...(subId ? { subId } : {}) }));
    setServers((prev) => [...prev, ...tagged]);
    // Select the newly imported server so Connect uses it immediately.
    setActiveId(tagged[0].id);
    showToast(`Imported ${tagged.length} server${tagged.length > 1 ? "s" : ""} ✓`);
  };

  const importFromClipboard = async () => {
    setSheet(null);
    try {
      const text = await invoke<string>("get_clipboard");
      const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      if (!lines.length) return showToast("Clipboard is empty", true);

      // 1. direct URIs
      if (lines.some((l) => /^(vless|trojan|ss|vmess):\/\//.test(l))) {
        const parsed = await invoke<Server[]>("import_bulk", { uris: lines });
        return appendServers(parsed);
      }
      // 2. base64-encoded blob
      const parsedB64 = await invoke<Server[]>("import_bulk", { uris: lines });
      if (parsedB64.length) return appendServers(parsedB64);
      // 3. subscription URL
      if (/^https?:\/\//.test(lines[0])) {
        const url = lines[0];
        const sid = ++idCounter;
        setSubs((prev) => [...prev, { id: sid, name: hostOf(url), url, loading: true }]);
        try {
          const channel = new Channel();
          let firstId: number | null = null;
          channel.onmessage = (srv: unknown) => {
            const s = srv as Server;
            const nid = ++idCounter;
            if (firstId == null) firstId = nid;
            setServers((prev) => [...prev, { ...s, id: nid, subId: sid }]);
          };
          await invoke("fetch_subscription_stream", { url, onServer: channel });
          if (firstId != null) setActiveId(firstId);
          setSubs((prev) => prev.map((s) => (s.id === sid ? { ...s, loading: false } : s)));
          showToast("Subscription imported ✓");
        } catch (e) {
          setSubs((prev) => prev.filter((s) => s.id !== sid));
          showToast(String(e), true);
        }
        return;
      }
      showToast("Clipboard has no VPN link", true);
    } catch (e) {
      showToast(String(e), true);
    }
  };

  const addSubscription = async () => {
    if (!subUrl.trim()) return showToast("Enter a subscription URL", true);
    const url = subUrl.trim();
    const sid = ++idCounter;
    // show sub + loading state immediately
    setSubs((prev) => [...prev, { id: sid, name: hostOf(url), url, loading: true }]);
    setSheet(null);
    setSubUrl("");
    setTab("subs");
    try {
      const channel = new Channel();
      let firstId: number | null = null;
      channel.onmessage = (srv: unknown) => {
        const s = srv as Server;
        const nid = ++idCounter;
        if (firstId == null) firstId = nid;
        setServers((prev) => [...prev, { ...s, id: nid, subId: sid }]);
      };
      await invoke("fetch_subscription_stream", { url, onServer: channel });
      if (firstId != null) setActiveId(firstId);
      setSubs((prev) => prev.map((s) => (s.id === sid ? { ...s, loading: false } : s)));
      showToast("Subscription imported ✓");
    } catch (e) {
      setSubs((prev) => prev.filter((s) => s.id !== sid));
      showToast(String(e), true);
    }
  };

  const updateSubscription = async (sub: Sub) => {
    try {
      // remove old servers for this sub
      setServers((prev) => prev.filter((s) => s.subId !== sub.id));
      setSubs((prev) => prev.map((s) => (s.id === sub.id ? { ...s, loading: true } : s)));
      const channel = new Channel();
      let count = 0;
      channel.onmessage = (srv: unknown) => {
        const s = srv as Server;
        count++;
        setServers((prev) => [...prev, { ...s, id: ++idCounter, subId: sub.id }]);
      };
      await invoke("fetch_subscription_stream", { url: sub.url, onServer: channel });
      setSubs((prev) => prev.map((s) => (s.id === sub.id ? { ...s, loading: false } : s)));
      showToast(`${sub.name}: ${count} servers updated ✓`);
    } catch (e) {
      showToast(String(e), true);
    }
  };

  // refresh every subscription at once (used by Subscription Auto-Update)
  const updateAllSubscriptions = async () => {
    for (const sub of subs) {
      try {
        setServers((prev) => prev.filter((s) => s.subId !== sub.id));
        const channel = new Channel();
        channel.onmessage = (srv: unknown) => {
          const s = srv as Server;
          setServers((prev) => [...prev, { ...s, id: ++idCounter, subId: sub.id }]);
        };
        await invoke("fetch_subscription_stream", { url: sub.url, onServer: channel });
      } catch {
        /* skip failed subs */
      }
    }
  };

  const deleteSubscription = (id: number) => {
    setSubs((p) => p.filter((s) => s.id !== id));
    setServers((prev) => prev.filter((s) => s.subId !== id));
    setActiveId((cur) => (servers.find((s) => s.id === cur)?.subId === id ? null : cur));
    showToast("Subscription deleted");
  };

  // ─── QR ───
  const handleQrResult = async (data: string) => {
    stopCamera();
    setQrOpen(false);
    try {
      const trimmed = data.trim();
      if (/^(vless|trojan|ss|vmess):\/\//.test(trimmed)) {
        const s = await invoke<Server>("import_server", { uri: trimmed });
        appendServers([s]);
      } else if (/^https?:\/\//.test(trimmed)) {
        const sid = ++idCounter;
        setSubs((prev) => [...prev, { id: sid, name: hostOf(trimmed), url: trimmed, loading: true }]);
        const channel = new Channel();
        let firstId: number | null = null;
        channel.onmessage = (srv: unknown) => {
          const s = srv as Server;
          const nid = ++idCounter;
          if (firstId == null) firstId = nid;
          setServers((prev) => [...prev, { ...s, id: nid, subId: sid }]);
        };
        await invoke("fetch_subscription_stream", { url: trimmed, onServer: channel });
        if (firstId != null) setActiveId(firstId);
        setSubs((prev) => prev.map((s) => (s.id === sid ? { ...s, loading: false } : s)));
        showToast("Subscription imported ✓");
      } else {
        // try as base64 blob
        const parsedB64 = await invoke<Server[]>("import_bulk", { uris: [trimmed] });
        if (parsedB64.length) {
          appendServers(parsedB64);
        } else {
          showToast("QR has no VPN link", true);
        }
      }
    } catch (e) {
      showToast(String(e), true);
    }
  };

  const startCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      streamRef.current = stream;
      setQrOpen(true);
      setTimeout(() => {
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          videoRef.current.play();
          scanLoop();
        }
      }, 120);
    } catch {
      showToast("Camera not available", true);
    }
  };

  const scanLoop = () => {
    const tick = () => {
      const video = videoRef.current;
      if (!video || video.readyState !== video.HAVE_ENOUGH_DATA) return requestAnimationFrame(tick);
      const canvas = document.createElement("canvas");
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext("2d")!;
      ctx.drawImage(video, 0, 0);
      const code = jsQR(ctx.getImageData(0, 0, canvas.width, canvas.height).data, canvas.width, canvas.height);
      if (code?.data) handleQrResult(code.data);
      else requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  };

  const stopCamera = () => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
  };

  const decodeImageFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext("2d")!;
        ctx.drawImage(img, 0, 0);
        const code = jsQR(ctx.getImageData(0, 0, canvas.width, canvas.height).data, canvas.width, canvas.height);
        if (code?.data) handleQrResult(code.data);
        else showToast("No QR code in image", true);
      };
      img.src = reader.result as string;
    };
    reader.readAsDataURL(file);
  };

  // ─── connect / disconnect ───
  const toggleConnect = async () => {
    if (busy) return;
    if (connected) {
      setBusy(true);
      manualDisconnectRef.current = true;
      try {
        await invoke("disconnect");
        setConnected(false);
        setExitInfo(null);
        showToast("Disconnected");
      } catch (e) {
        showToast(String(e), true);
      }
      setBusy(false);
      manualDisconnectRef.current = false;
      return;
    }
    if (!activeServer) {
      setTab("servers");
      return showToast("Add & select a server first", true);
    }
    doConnect(activeServer);
  };

  const serversRef = useRef(servers);
  serversRef.current = servers;

  const pingOne = useCallback(async (id: number) => {
    const s = serversRef.current.find((x) => x.id === id);
    if (!s) return;
    try {
      const ms = await invoke<number>("ping_server", { address: s.address, port: s.port });
      setServers((prev) => prev.map((x) => (x.id === id ? { ...x, ping: ms } : x)));
    } catch {
      setServers((prev) => prev.map((x) => (x.id === id ? { ...x, ping: -1 } : x)));
    }
  }, []);

  // parallel ping — batched UI update (single re-render for all keys)
  const pingAll = async () => {
    showToast(`Testing ${servers.length} servers…`);
    const BATCH = 12;
    const results: { id: number; ms: number }[] = [];
    for (let i = 0; i < servers.length; i += BATCH) {
      const chunk = servers.slice(i, i + BATCH);
      const batch = await Promise.all(
        chunk.map(async (s) => {
          try {
            const ms = await invoke<number>("ping_server", { address: s.address, port: s.port });
            return { id: s.id, ms };
          } catch {
            return { id: s.id, ms: -1 };
          }
        })
      );
      results.push(...batch);
      // single setServers per batch — only renders ~12 rows at a time
      const map = new Map(batch.map((r) => [r.id, r.ms]));
      setServers((prev) => prev.map((x) => (map.has(x.id) ? { ...x, ping: map.get(x.id)! } : x)));
      await new Promise((r) => setTimeout(r, 0));
    }
    showToast("Latency test done ✓");
    setServers((prev) => sortByPing(prev));
  };

  // sort: usable (ping>=0) fastest first, then errored (-1) / timed out last
  const sortByPing = (list: Server[]) =>
    [...list].sort((a, b) => {
      const aOk = a.ping != null && a.ping >= 0;
      const bOk = b.ping != null && b.ping >= 0;
      if (aOk && !bOk) return -1;
      if (!aOk && bOk) return 1;
      if (aOk && bOk) return (a.ping as number) - (b.ping as number);
      return 0;
    });

  // auto-select: connect immediately (~1s) to current/first node, then ping in
  // the background and silently switch to the fastest without the user noticing.
  const autoSelect = async () => {
    if (selBusy) return;
    if (!servers.length) return showToast("No servers to select", true);
    setSelBusy(true);
    setTab("home");
    try {
      // 1) connect right away so VPN is up within ~1 second
      const initial = activeServer ?? servers[0];
      if (!connected || activeId !== initial.id) {
        setActiveId(initial.id);
        await doConnect(initial);
      }
      showToast("Auto-Select: connected ✓ (optimizing in background…)");

      // 2) ping everything in the background, updating pings silently
      const BATCH = 12;
      const results: { id: number; ms: number }[] = [];
      for (let i = 0; i < servers.length; i += BATCH) {
        const chunk = servers.slice(i, i + BATCH);
        const batch = await Promise.all(
          chunk.map(async (s) => {
            try {
              const ms = await invoke<number>("ping_server", { address: s.address, port: s.port });
              return { id: s.id, ms };
            } catch {
              return { id: s.id, ms: -1 };
            }
          })
        );
        results.push(...batch);
        const map = new Map(batch.map((r) => [r.id, r.ms]));
        setServers((prev) => prev.map((x) => (map.has(x.id) ? { ...x, ping: map.get(x.id)! } : x)));
        await new Promise((r) => setTimeout(r, 0));
      }

      // 3) silently switch to the fastest node if it beats the current one
      const best = results.filter((r) => r.ms >= 0).sort((a, b) => a.ms - b.ms)[0];
      const cur = results.find((r) => r.id === activeId);
      if (best && best.id !== activeId && (!cur || cur.ms < 0 || best.ms < cur.ms)) {
        const srv = servers.find((s) => s.id === best.id);
        if (srv) {
          setActiveId(srv.id);
          await doConnect(srv, true);
          showToast(`Auto-Select → ${srv.name} (${best.ms}ms) ✓`);
        }
      } else {
        showToast("Auto-Select: best node already connected ✓");
      }
    } catch (e) {
      showToast("Auto-Select failed: " + (e as Error).message, true);
    } finally {
      setSelBusy(false);
    }
  };

  const removeServer = useCallback((id: number) => {
    setServers((p) => p.filter((s) => s.id !== id));
    setActiveId((cur) => (cur === id ? null : cur));
  }, []);

  const startEdit = useCallback((s: Server) => {
    setEf({ ...s });
    setEditing(s);
  }, []);

  const saveEdit = () => {
    if (!editing) return;
    if (!ef.name?.trim() || !ef.address?.trim()) return showToast("Name and address required", true);
    const port = parseInt(String(ef.port)) || 443;
    setServers((prev) =>
      prev.map((x) => (x.id === editing.id ? { ...x, ...ef, port } as Server : x))
    );
    setEditing(null);
    showToast("Config updated ✓");
  };

  const startShare = useCallback(async (srv: Server) => {
    try {
      const uri = await invoke<string>("export_uri", { server: { ...srv, ping: null } });
      await invoke("copy_clipboard", { text: uri });
      setQrUrl("");
      setSharing({ srv, uri });
      showToast("Link copied to clipboard ✓");
    } catch (e) {
      showToast(String(e), true);
    }
  }, [showToast]);

  const showQr = () => {
    if (!sharing) return;
    QRCode.toDataURL(sharing.uri, {
      width: 260,
      margin: 1,
      color: { dark: "#14192B", light: "#FFFFFF" },
    })
      .then(setQrUrl)
      .catch((e) => showToast(String(e), true));
  };

  const doXrayUpdate = async (url: string) => {
    setConfirmDlg({
      msg: "Download & replace xray core?\nApp will need restart after.",
      onOk: async () => {
        setConfirmDlg(null);
        setXrayUpdating(true);
        setXrayProgress(0);
        // poll progress every 300ms
        const poll = setInterval(async () => {
          try {
            const p = await invoke<number>("get_download_progress");
            if (p > 0) setXrayProgress(p);
          } catch {}
        }, 300);
        try {
          const newVer = await invoke<string>("update_xray_core", { url });
          setCoreVer(newVer);
          setXrayUpdate(null);
          setXrayCheckMsg(`Updated to v${newVer} ✓`);
          showToast(`Xray core → ${newVer} ✓  Restarting app…`);
          // auto-restart so the new core binary takes effect immediately
          // persist selection so it survives the restart
          saveStore("lr_servers", servers);
          saveStore("lr_active", activeId);
          setTimeout(() => { invoke("restart_app").catch(() => {}); }, 800);
        } catch (e: any) {
          const msg = typeof e === "string" ? e : e?.message || "Update failed";
          showToast(msg.slice(0, 120), true);
        } finally {
          clearInterval(poll);
          setXrayUpdating(false);
          setXrayProgress(0);
        }
      },
    });
  };

  const routingLabel =
    settings.routing === "global" ? "Global" : settings.routing === "cn" ? "Bypass CN" : "Bypass LAN";
  const RoutingIcon = () => (
    <button className="route-chip" onClick={() => setTab("settings")} title="Routing mode">
      <Icon name="globe" size={13} />
      {routingLabel}
      <Icon name="chevron" size={11} />
    </button>
  );

  return (
    <ErrorBoundary>
    <div className="app">
      {toast && (
        <div className={`toast ${toast.bad ? "bad" : ""}`}>{toast.msg}</div>
      )}

      {appUpdate && (
        <div
          className="update-banner"
          onClick={() =>
            invoke("open_link", {
              url: "https://github.com/satminpaing1/LionRayDesktop/releases/latest",
            })
          }
        >
          <Icon name="download" size={14} />
          New version {appUpdate} available
          <Icon name="chevron" size={12} />
        </div>
      )}

      {/* ═══════════ HOME ═══════════ */}
      {tab === "home" && (
        <>
          <header className="topbar home-top">
            <div className="brand">
              <div className="brand-mark">🦁</div>
              <div className="brand-text">
                <span className="logo">LionRay</span>
                <small>VPN</small>
              </div>
            </div>
            <RoutingIcon />
          </header>

          <div className="home-body">
            <section className={`status-stage ${connected ? "on" : ""}`}>
              <div className="power-wrap">
                <button
                  className={`power ${connected ? "on" : ""}`}
                  disabled={busy}
                  onClick={toggleConnect}
                  aria-label={connected ? "Disconnect" : "Connect"}
                >
                  {busy ? <span className="power-busy" /> : <Icon name="power" size={40} strokeWidth={1.7} />}
                </button>
              </div>

              <div className={`hero-status ${connected ? "on" : ""}`}>
                <span className="status-dot" />
                <b>{connected ? "Connected" : "Not connected"}</b>
              </div>
              <p className="hero-sub">
                {connected
                  ? settings.tunMode
                    ? "Every app on this PC is routed through the encrypted tunnel."
                    : "Your browser and apps are using the secure tunnel."
                  : settings.autoConnect
                    ? "Auto-connect is on. Tap the power button to start now."
                    : "Pick a server below, then tap the power button."}
              </p>
            </section>

            <section className="home-panel">
              <button className={`server-row ${connected ? "on" : ""}`} onClick={() => setTab("servers")}>
                <span className={`server-avatar ${connected ? "on" : ""}`}>
                  {activeServer && connected && exitInfo?.countryCode
                    ? flagEmoji(exitInfo.countryCode)
                    : <Icon name="server" size={17} />}
                </span>
                <span className="server-info">
                  <span className="server-name">
                    {activeServer ? activeServer.name : "Choose a server"}
                  </span>
                  <span className="server-meta">
                    {activeServer
                      ? `${activeServer.protocol.toUpperCase()} · ${(activeServer.network || "tcp").toUpperCase()} · ${activeServer.port}`
                      : "No server selected yet"}
                  </span>
                </span>
                <span className="server-end">
                  {activeServer?.ping != null && activeServer.ping >= 0 && (
                    <span className="ping-pill" style={{ color: pingColor(activeServer.ping) }}>
                      {activeServer.ping} ms
                    </span>
                  )}
                  <Icon name="chevron" size={15} />
                </span>
              </button>

              {connected ? (
                <>
                  <div className="panel-sep" />
                  <LiveStats />
                  {exitInfo?.query && (
                    <>
                      <div className="panel-sep" />
                      <div className="exit-row" title={exitInfo.isp || ""}>
                        <span className="exit-flag">{flagEmoji(exitInfo.countryCode)}</span>
                        <span className="exit-text">Exit IP <b>{exitInfo.query}</b></span>
                        <span className="exit-loc">
                          {[exitInfo.city, exitInfo.country].filter(Boolean).join(", ")}
                        </span>
                      </div>
                    </>
                  )}
                </>
              ) : (
                <>
                  <div className="panel-sep" />
                  <div className="panel-note">
                    <Icon name="lock" size={14} />
                    <span>Tunnel is off — traffic goes direct until you connect.</span>
                  </div>
                </>
              )}
            </section>
          </div>
        </>
      )}

      {/* ═══════════ SERVERS ═══════════ */}
      {tab === "servers" && (
        <>
          <header className="topbar">
            <button className="back-btn" onClick={() => setTab("home")} aria-label="Back"><Icon name="arrow-left" size={17} /></button>
            <span className="topbar-title">Nodes</span>
            {servers.length > 0 && <span className="topbar-count">{servers.length}</span>}
            <div className="tb-actions">
              <button className="sel-btn" onClick={autoSelect} disabled={!servers.length || selBusy}>
                <Icon name="refresh" size={13} /> Auto
              </button>
              <button className="test-btn" onClick={pingAll} disabled={!servers.length}>Test all</button>
            </div>
          </header>
          <div className="content">
            {servers.length === 0 ? (
              <div className="empty">
                <div className="empty-icon"><Icon name="server" size={27} /></div>
                <div>No nodes yet</div>
                <small>Tap + to import via clipboard, QR, or subscription.</small>
              </div>
            ) : (
              <div className="list">
                {manualServers.length > 0 && (
                  <div className="node-group">
                    <div className="group-label">
                      <span>My keys</span>
                      <span className="group-right"><span className="group-count">{manualServers.length}</span></span>
                    </div>
                    <div className="group-body">
                      {manualServers.map((s) => (
                        <ServerRow
                          key={s.id}
                          s={s}
                          selected={s.id === activeId}
                          onSelect={setActiveId}
                          onPing={pingOne}
                          onMenu={setMenuServer}
                        />
                      ))}
                    </div>
                  </div>
                )}
                {subs.map((sub) => {
                  const srv = servers.filter((x) => x.subId === sub.id);
                  if (srv.length === 0 && !sub.loading) return null;
                  return (
                    <div key={`g-${sub.id}`} className="node-group">
                      <div className="group-label">
                        <span>{sub.name} {sub.loading && <span className="loading-dots">…</span>}</span>
                        <span className="group-right">
                          <span className="group-count">{sub.loading ? "…" : srv.length}</span>
                          <button className="group-del" title="Delete whole profile" onClick={() => deleteSubscription(sub.id)}><Icon name="trash" size={13} /></button>
                        </span>
                      </div>
                      <div className="group-body">
                        {srv.length === 0 ? (
                          <div className="group-empty">Fetching nodes…</div>
                        ) : srv.map((s) => (
                          <ServerRow
                            key={s.id}
                            s={s}
                            selected={s.id === activeId}
                            onSelect={setActiveId}
                            onPing={pingOne}
                            onMenu={setMenuServer}
                          />
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}

      {/* ═══════════ SUBSCRIPTIONS ═══════════ */}
      {tab === "subs" && (
        <>
          <header className="topbar">
            <button className="back-btn" onClick={() => setTab("home")} aria-label="Back"><Icon name="arrow-left" size={17} /></button>
            <span className="topbar-title">Subscriptions</span>
            {subs.length > 0 && <span className="topbar-count">{subs.length}</span>}
            <span style={{ width: 46 }} />
          </header>
          <div className="content">
            {subs.length === 0 ? (
              <div className="empty">
                <div className="empty-icon"><Icon name="layers" size={27} /></div>
                <div>No subscriptions</div>
                <small>Tap + to add a subscription link.</small>
              </div>
            ) : (
              <div className="sub-list">
                {subs.map((sub) => {
                  const count = servers.filter((s) => s.subId === sub.id).length;
                  return (
                    <div key={sub.id} className="sub-card">
                      <span className="sub-avatar"><Icon name="layers" size={17} /></span>
                      <div className="sub-main">
                        <div className="sub-name">{sub.name} {sub.loading && <span className="loading-dots">…</span>}</div>
                        <div className="sub-url" title={sub.url}>{hostOf(sub.url)} · {sub.loading ? "updating" : `${count} ${count === 1 ? "node" : "nodes"}`}</div>
                      </div>
                      <div className="sub-actions">
                        <button className="sub-btn" title="Update subscription" disabled={sub.loading} onClick={() => updateSubscription(sub)}>
                          <Icon name="refresh" size={14} />
                        </button>
                        <button className="sub-btn danger" title="Delete subscription" disabled={sub.loading} onClick={() => deleteSubscription(sub.id)}>
                          <Icon name="trash" size={14} />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}

      {/* ═══════════ SETTINGS ═══════════ */}
      {tab === "settings" && (
        <>
          <header className="topbar">
            <button className="back-btn" onClick={() => setTab("home")} aria-label="Back"><Icon name="arrow-left" size={17} /></button>
            <span className="topbar-title">Settings</span>
            <span style={{ width: 46 }} />
          </header>
          <div className="content">
            <div className="sec">Routing Mode</div>
            <div className="card seg-card">
              {([
                ["global", "Global"],
                ["lan", "Skip LAN"],
                ["cn", "Skip CN"],
              ] as const).map(([v, label]) => (
                <button
                  key={v}
                  className={`seg ${settings.routing === v ? "on" : ""}`}
                  onClick={() => setSettings({ ...settings, routing: v })}
                >
                  {label}
                </button>
              ))}
            </div>
            <div className="hint">Applies on next connect. Ads blocked always.</div>

            {IS_WINDOWS && (
              <>
                <div className="sec">Tunnel Mode</div>
                <div className="card">
                  <div className="toggle-row">
                    <div>
                      <div className="kv-t">TUN Mode</div>
                      <div className="kv-s">Capture every PC app, even ones that ignore the system proxy</div>
                    </div>
                    <label className="switch">
                      <input
                        type="checkbox"
                        checked={settings.tunMode}
                        onChange={() => setSettings({ ...settings, tunMode: !settings.tunMode })}
                      />
                      <span className="slider" />
                    </label>
                  </div>
                  {settings.tunMode && !isAdmin && (
                    <>
                      <div className="hr" />
                      <div className="tun-admin-row">
                        <div className="kv-s">Administrator access is required to create the virtual adapter.</div>
                        <button className="btn-secondary" onClick={requestAdmin}>Restart as Admin</button>
                      </div>
                    </>
                  )}
                </div>
                <div className="hint">
                  {settings.tunMode
                    ? isAdmin
                      ? "TUN is ready. The system proxy stays off while connected."
                      : "Restart as administrator before connecting."
                    : "Proxy mode (current): the Windows proxy is enabled only while connected and your saved proxy/PAC is restored on disconnect."}
                </div>
              </>
            )}

            <div className="sec">Security</div>
            <div className="card">
              <div className="toggle-row">
                <div>
                  <div className="kv-t">Ad Blocker</div>
                  <div className="kv-s">Block ads & trackers (geosite filter)</div>
                </div>
                <label className="switch">
                  <input type="checkbox" checked={settings.adBlock} onChange={() => setSettings({ ...settings, adBlock: !settings.adBlock })} />
                  <span className="slider" />
                </label>
              </div>
              <div className="hr" />
              <div className="toggle-row">
                <div>
                  <div className="kv-t">DNS Server</div>
                  <div className="kv-s">DNS resolver for domain lookups</div>
                </div>
                <select
                  className="dns-select"
                  value={settings.dns}
                  onChange={(e) => setSettings({ ...settings, dns: e.target.value })}
                >
                  <option value="system">System DNS</option>
                  <option value="google">Google (8.8.8.8)</option>
                  <option value="cloudflare">Cloudflare (1.1.1.1)</option>
                  <option value="quad9">Quad9 (9.9.9.9)</option>
                  <option value="adguard">AdGuard (94.140.14.14)</option>
                </select>
              </div>
            </div>
            <div className="hint">DNS changes apply on next connect.</div>

            <div className="sec">Advanced</div>
            <div className="card">
              <div className="toggle-row">
                <div>
                  <div className="kv-t">IPv6</div>
                  <div className="kv-s">Off = IPv4 only (recommended). Turn on if your network has working IPv6.</div>
                </div>
                <label className="switch">
                  <input type="checkbox" checked={settings.ipv6} onChange={() => setSettings({ ...settings, ipv6: !settings.ipv6 })} />
                  <span className="slider" />
                </label>
              </div>
              <div className="hr" />
              <div className="toggle-row">
                <div>
                  <div className="kv-t">TLS Fragment</div>
                  <div className="kv-s">Use the link's fragment value. Turn on only if the server is blocked.</div>
                </div>
                <label className="switch">
                  <input type="checkbox" checked={settings.fragment} onChange={() => setSettings({ ...settings, fragment: !settings.fragment })} />
                  <span className="slider" />
                </label>
              </div>
              <div className="hr" />
              <div className="toggle-row">
                <div>
                  <div className="kv-t">UDP Relay</div>
                  <div className="kv-s">Off = TCP only (recommended). Turn on for QUIC/games.</div>
                </div>
                <label className="switch">
                  <input type="checkbox" checked={settings.udp} onChange={() => setSettings({ ...settings, udp: !settings.udp })} />
                  <span className="slider" />
                </label>
              </div>
            </div>
            <div className="hint">All advanced options are off by default. Changes apply on next connect.</div>

            <div className="sec">Domain Bypass</div>
            <div className="card">
              <div className="kv-t" style={{ marginBottom: 8 }}>Domains below skip the proxy (go direct)</div>
              <div className="bypass-input-row">
                <input
                  className="bypass-input"
                  placeholder="example.com"
                  value={bypassInput}
                  onChange={(e) => setBypassInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && bypassInput.trim()) {
                      const d = bypassInput.trim().toLowerCase();
                      if (!settings.bypassDomains.includes(d)) {
                        setSettings({ ...settings, bypassDomains: [...settings.bypassDomains, d] });
                      }
                      setBypassInput("");
                    }
                  }}
                />
                <button
                  className="btn-secondary"
                  style={{ flexShrink: 0 }}
                  onClick={() => {
                    if (bypassInput.trim()) {
                      const d = bypassInput.trim().toLowerCase();
                      if (!settings.bypassDomains.includes(d)) {
                        setSettings({ ...settings, bypassDomains: [...settings.bypassDomains, d] });
                      }
                      setBypassInput("");
                    }
                  }}
                >+ Add</button>
              </div>
              {settings.bypassDomains.length > 0 && (
                <div className="bypass-list">
                  {settings.bypassDomains.map((d) => (
                    <span key={d} className="bypass-chip">
                      {d}
                      <button
                        className="bypass-remove"
                        onClick={() => setSettings({
                          ...settings,
                          bypassDomains: settings.bypassDomains.filter((x) => x !== d),
                        })}
                      >×</button>
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div className="hint">Applies on next connect. e.g. google.com, netflix.com</div>

            <div className="sec">General</div>
            <div className="card">
              <div className="toggle-row">
                <div>
                  <div className="kv-t">Dark Mode</div>
                  <div className="kv-s">Switch app theme</div>
                </div>
                <label className="switch">
                  <input type="checkbox" checked={settings.dark} onChange={() => setSettings({ ...settings, dark: !settings.dark })} />
                  <span className="slider" />
                </label>
              </div>
              <div className="hr" />
              <div className="toggle-row">
                <div>
                  <div className="kv-t">Auto Connect</div>
                  <div className="kv-s">Connect on app launch</div>
                </div>
                <label className="switch">
                  <input type="checkbox" checked={settings.autoConnect} onChange={() => setSettings({ ...settings, autoConnect: !settings.autoConnect })} />
                  <span className="slider" />
                </label>
              </div>
              <div className="hr" />
              <div className="toggle-row">
                <div>
                  <div className="kv-t">Subscription Auto-Update</div>
                  <div className="kv-s">Refresh subs on app launch</div>
                </div>
                <label className="switch">
                  <input type="checkbox" checked={settings.subAutoUpdate} onChange={() => setSettings({ ...settings, subAutoUpdate: !settings.subAutoUpdate })} />
                  <span className="slider" />
                </label>
              </div>
            </div>

            <div className="sec">Connection</div>
            <div className="card">
              <div className="kv"><span>Local SOCKS</span><b>127.0.0.1:10808</b></div>
              <div className="hr" />
              <div className="kv"><span>Local HTTP</span><b>127.0.0.1:10809</b></div>
              <div className="hr" />
              <div className="kv">
                <span>Tunnel Mode</span>
                <b>{settings.tunMode ? "TUN (system-wide)" : "System Proxy"}</b>
              </div>
              <div className="hr" />
              <div className="kv">
                <span>Xray Core</span>
                <b style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  v{coreVer}
                  {xrayUpdate && <span className="update-dot" title={`Update to ${xrayUpdate.version}`} />}
                </b>
              </div>
              <div className="hr" />
              <div className="kv"><span>App Version</span><b>{appVer}</b></div>
            </div>

            <div className="sec">Xray Core Update</div>
            <div className="card update-card">
              {xrayUpdating ? (
                <div className="update-progress-wrap">
                  <div className="update-progress-bar">
                    <div className="update-progress-fill" style={{ width: `${xrayProgress}%` }} />
                  </div>
                  <div className="update-progress-text">Downloading… {xrayProgress}%</div>
                </div>
              ) : xrayUpdate ? (
                <>
                  <div className="kv">
                    <span>New version available</span>
                    <b style={{ color: "var(--green)" }}>v{xrayUpdate.version}</b>
                  </div>
                  <div className="hr" />
                  <div className="update-btn-row">
                    <button className="btn-primary m0" onClick={() => doXrayUpdate(xrayUpdate.url)}>
                      Update Now
                    </button>
                    <button className="btn-secondary" onClick={checkXrayUpdate} aria-label="Refresh"><Icon name="refresh" size={14} /></button>
                  </div>
                </>
              ) : (
                <>
                  {xrayCheckMsg && (
                    <div className="kv">
                      <span style={{ color: xrayCheckMsg.startsWith("Error") ? "var(--red)" : "var(--sub)" }}>{xrayCheckMsg}</span>
                    </div>
                  )}
                  <button
                    className="btn-secondary btn-block"
                    style={{ marginTop: xrayCheckMsg ? 0 : 8 }}
                    onClick={checkXrayUpdate}
                  >
                    <Icon name="refresh" size={13} /> Check for updates
                  </button>
                </>
              )}
            </div>

            <div className="sec">Community</div>
            <div className="card link-card">
              <button
                className="link-row"
                onClick={() => invoke("open_link", { url: "https://t.me/lionrayvpn" })}
              >
                <span className="link-row-ico"><Icon name="link" size={16} /></span>
                <span className="link-row-main">
                  <b>Telegram channel</b>
                  <small>News, updates and support</small>
                </span>
                <Icon name="chevron" size={14} />
              </button>
            </div>

            <div className="sec">Danger Zone</div>
            <button
              className="danger-btn"
              onClick={() =>
                setConfirmDlg({
                  msg: "Delete ALL nodes?\nThis cannot be undone.",
                  onOk: () => {
                    setConfirmDlg(null);
                    setServers([]);
                    setActiveId(null);
                    showToast("All nodes deleted");
                  },
                })
              }
            >
              Delete All Nodes
            </button>

            <div className="about-box">
              Powered by Sett Min Paing
            </div>
          </div>
        </>
      )}

      {tab === "logs" && (
        <>
          <header className="topbar">
            <button className="back-btn" onClick={() => setTab("home")} aria-label="Back"><Icon name="arrow-left" size={17} /></button>
            <span className="topbar-title">Logs</span>
            <span style={{ width: 46 }} />
          </header>
          <div className="content logs-content">
            <div className="log-toolbar">
              <div className="log-tabs">
                {([
                  ["app", "App"],
                  ["xray", "Xray"],
                  ["singbox", "TUN"],
                ] as const).map(([id, label]) => (
                  <button
                    key={id}
                    className={`log-tab ${logKind === id ? "on" : ""}`}
                    onClick={() => setLogKind(id)}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <div className="log-actions">
                <button className="log-ico-btn" onClick={() => void loadLogs()} disabled={logBusy} title="Refresh"><Icon name="refresh" size={14} /></button>
                <button className="log-ico-btn" onClick={() => void copyLogs()} title="Copy log"><Icon name="copy" size={14} /></button>
                <button className="log-ico-btn danger" onClick={clearLogs} title="Clear all logs"><Icon name="trash" size={14} /></button>
              </div>
            </div>
            <div className="log-filters">
              <div className="log-levels">
                {([
                  ["all", "All"],
                  ["warn", "Warn"],
                  ["error", "Error"],
                ] as const).map(([id, label]) => (
                  <button
                    key={id}
                    className={`log-level ${logLevel === id ? "on" : ""}`}
                    onClick={() => setLogLevel(id)}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <div className="log-search">
                <Icon name="search" size={13} />
                <input
                  value={logQuery}
                  onChange={(e) => setLogQuery(e.target.value)}
                  placeholder="Search log…"
                  spellCheck={false}
                />
                {logQuery && (
                  <button onClick={() => setLogQuery("")} title="Clear search">×</button>
                )}
              </div>
            </div>
            <div className="log-meta">
              <span className="live-dot" />
              <span>LIVE · 4s</span>
              <span className="log-meta-dot">•</span>
              <span>{totalLines.toLocaleString()} / {logs[logKind] ? logs[logKind].split("\n").length.toLocaleString() : 0} lines</span>
              <button
                className={`log-autoscroll ${autoScroll ? "on" : ""}`}
                onClick={() => setAutoScroll(!autoScroll)}
              >
                {autoScroll ? "▼ Auto-scroll" : "▽ Paused"}
              </button>
            </div>
            <div className="log-box" ref={logBoxRef} onScroll={onLogScroll}>
              {shownLines.length ? (
                <>
                  {totalLines > shownLines.length && (
                    <div className="log-cap">နောက်ဆုံး {shownLines.length} ကြောင်းပဲ ပြထားပါတယ် ({totalLines} ထဲမှ)</div>
                  )}
                  <pre className="log-pre">
                    {shownLines.map((l) => (
                      <div key={l.n} className={`log-line ${l.cls}`}>
                        <span className="log-no">{l.n}</span>
                        <span className="log-txt">{l.text || "\u00a0"}</span>
                      </div>
                    ))}
                  </pre>
                </>
              ) : (
                <div className="log-empty">
                  <span>
                    <Icon name={logLevel !== "all" || logQuery ? "search" : "terminal"} size={24} />
                  </span>
                  <p>{logLevel !== "all" || logQuery ? "မကိုက်ညီတဲ့ log မရှိပါ" : "Log မရှိသေးပါ"}</p>
                  <small>
                    {logLevel !== "all" || logQuery
                      ? "Filter ကို All ပြန်ပြောင်းပြီး ကြည့်ပါ"
                      : "ချိတ်ဆက်ပြီးရင် ဒီမှာ အလိုအလျောက် ပေါ်လာပါမယ်"}
                  </small>
                </div>
              )}
            </div>
            <div className="log-footer">%APPDATA%\lionray-vpn · Clear လုပ်ရင် လက်ရှိ session log တွေလည်း ပါသွားပါမယ်</div>
          </div>
        </>
      )}

      {/* FAB */}
      {(tab === "servers" || tab === "subs") && (
        <button className="fab" onClick={() => setSheet(sheet === "menu" ? null : "menu")} aria-label="Add node">
          <Icon name="plus" size={20} />
        </button>
      )}

      {/* action sheet */}
      {sheet && (
        <div className="overlay" onClick={() => setSheet(null)}>
          <div className="sheet" onClick={(e) => e.stopPropagation()}>
            {sheet === "menu" ? (
              <>
                <div className="sheet-title">Add Node</div>
                <button className="sheet-item" onClick={importFromClipboard}>
                  <span className="sheet-ico"><Icon name="clipboard" size={17} /></span>
                  <div><b>Import from Clipboard</b><small>Paste copied links</small></div>
                </button>
                <button className="sheet-item" onClick={() => { setSheet(null); startCamera(); }}>
                  <span className="sheet-ico"><Icon name="camera" size={17} /></span>
                  <div><b>Scan QR Code</b><small>Use camera</small></div>
                </button>
                <button className="sheet-item" onClick={() => { setSheet(null); fileRef.current?.click(); }}>
                  <span className="sheet-ico"><Icon name="image" size={17} /></span>
                  <div><b>Import QR Photo</b><small>Decode saved image</small></div>
                </button>
                <button className="sheet-item" onClick={() => setSheet("sub")}>
                  <span className="sheet-ico"><Icon name="link" size={17} /></span>
                  <div><b>Add Subscription</b><small>Fetch nodes from URL</small></div>
                </button>
              </>
            ) : (
              <>
                <div className="sheet-title">New Subscription</div>
                <input
                  className="input"
                  placeholder="https://example.com/sub"
                  value={subUrl}
                  onChange={(e) => setSubUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addSubscription()}
                  autoFocus
                />
                <button className="btn-primary" onClick={addSubscription}>Subscribe</button>
              </>
            )}
            <button className="sheet-cancel" onClick={() => setSheet(null)}>Cancel</button>
          </div>
        </div>
      )}

      {/* server actions */}
      {menuServer && (
        <div className="overlay" onClick={() => setMenuServer(null)}>
          <div className="sheet" onClick={(e) => e.stopPropagation()}>
            <div className="sheet-head">
              <span
                className="proto-chip"
                style={{
                  background: `${PROTO_COLORS[menuServer.protocol] || "#64748B"}14`,
                  color: PROTO_COLORS[menuServer.protocol] || "#64748B",
                  borderColor: `${PROTO_COLORS[menuServer.protocol] || "#64748B"}26`,
                }}
              >
                {protoLabel(menuServer.protocol)}
              </span>
              <div className="sheet-head-copy">
                <b>{menuServer.name}</b>
                <small>{menuServer.address}:{menuServer.port}</small>
              </div>
              <span className="sheet-ping" style={{ color: pingColor(menuServer.ping) }}>
                {menuServer.ping == null ? "—" : menuServer.ping < 0 ? "ERR" : `${menuServer.ping} ms`}
              </span>
            </div>
            <button className="sheet-item" onClick={() => { void pingOne(menuServer.id); setMenuServer(null); }}>
              <span className="sheet-ico"><Icon name="timer" size={17} /></span>
              <div><b>Test latency</b><small>Ping this node</small></div>
            </button>
            <button className="sheet-item" onClick={() => { const s = menuServer; setMenuServer(null); startEdit(s); }}>
              <span className="sheet-ico"><Icon name="edit" size={17} /></span>
              <div><b>Edit config</b><small>Name, address, transport</small></div>
            </button>
            <button className="sheet-item" onClick={() => { const s = menuServer; setMenuServer(null); void startShare(s); }}>
              <span className="sheet-ico"><Icon name="share" size={17} /></span>
              <div><b>Share link</b><small>Copy link or show QR</small></div>
            </button>
            <button
              className="sheet-item danger"
              onClick={() => {
                const s = menuServer;
                setMenuServer(null);
                setConfirmDlg({
                  msg: `Delete "${s.name}"?\nThis cannot be undone.`,
                  onOk: () => {
                    removeServer(s.id);
                    showToast("Node removed");
                  },
                });
              }}
            >
              <span className="sheet-ico"><Icon name="trash" size={17} /></span>
              <div><b>Delete node</b><small>Remove it from this device</small></div>
            </button>
            <button className="sheet-cancel" onClick={() => setMenuServer(null)}>Cancel</button>
          </div>
        </div>
      )}
      {qrOpen && (
        <div className="overlay center-overlay" onClick={() => { stopCamera(); setQrOpen(false); }}>
          <div className="qr-modal" onClick={(e) => e.stopPropagation()}>
            <video ref={videoRef} className="qr-video" muted playsInline />
            <div className="qr-hint">Point camera at QR code</div>
            <button className="sheet-cancel" onClick={() => { stopCamera(); setQrOpen(false); }}>Close</button>
          </div>
        </div>
      )}

      {/* edit modal */}
      {editing && (
        <div className="modal-overlay" onClick={() => setEditing(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">Edit config</div>
            <div className="modal-body">
              <div className="f-label">Name</div>
              <input className="input" value={ef.name ?? ""} onChange={(e) => setEf({ ...ef, name: e.target.value })} />

              <div className="f-row">
                <div style={{ flex: 2 }}>
                  <div className="f-label">Address</div>
                  <input className="input" value={ef.address ?? ""} onChange={(e) => setEf({ ...ef, address: e.target.value })} />
                </div>
                <div>
                  <div className="f-label">Port</div>
                  <input className="input" type="number" value={ef.port ?? 443} onChange={(e) => setEf({ ...ef, port: parseInt(e.target.value) || 443 })} />
                </div>
              </div>

              <div className="f-label">{editing.protocol === "trojan" ? "Password" : editing.protocol === "shadowsocks" ? "Method : Password" : "UUID"}</div>
              <input className="input" value={ef.uuid ?? ""} onChange={(e) => setEf({ ...ef, uuid: e.target.value })} />

              <div className="f-row">
                <div>
                  <div className="f-label">Network</div>
                  <select className="input" value={ef.network ?? "tcp"} onChange={(e) => setEf({ ...ef, network: e.target.value })}>
                    {["tcp", "ws", "grpc"].map((n) => <option key={n}>{n}</option>)}
                  </select>
                </div>
                <div>
                  <div className="f-label">Security</div>
                  <select className="input" value={ef.security ?? "none"} onChange={(e) => setEf({ ...ef, security: e.target.value })}>
                    {["none", "tls", "reality"].map((n) => <option key={n}>{n}</option>)}
                  </select>
                </div>
              </div>

              {(ef.security === "tls" || ef.security === "reality") && (
                <>
                  <div className="f-label">SNI</div>
                  <input className="input" value={ef.sni ?? ""} placeholder="server name" onChange={(e) => setEf({ ...ef, sni: e.target.value })} />
                  <div className="f-row">
                    <div>
                      <div className="f-label">Fingerprint</div>
                      <select className="input" value={ef.fingerprint ?? ""} onChange={(e) => setEf({ ...ef, fingerprint: e.target.value })}>
                        {["", "chrome", "firefox", "safari", "ios", "android", "edge", "random"].map((n) => <option key={n}>{n}</option>)}
                      </select>
                    </div>
                    <div>
                      <div className="f-label">ALPN</div>
                      <input className="input" value={ef.alpn ?? ""} placeholder="h2,http/1.1" onChange={(e) => setEf({ ...ef, alpn: e.target.value })} />
                    </div>
                  </div>
                  {ef.security === "reality" && (
                    <div className="f-row">
                      <div>
                        <div className="f-label">Public Key (pbk)</div>
                        <input className="input" value={ef.pbk ?? ""} onChange={(e) => setEf({ ...ef, pbk: e.target.value })} />
                      </div>
                      <div>
                        <div className="f-label">Short ID (sid)</div>
                        <input className="input" value={ef.sid ?? ""} onChange={(e) => setEf({ ...ef, sid: e.target.value })} />
                      </div>
                    </div>
                  )}
                  <label className="checkbox-row">
                    <input type="checkbox" checked={!!ef.allow_insecure} onChange={(e) => setEf({ ...ef, allow_insecure: e.target.checked })} />
                    Allow insecure
                  </label>
                  <div className="f-label">TLS Fragment</div>
                  <input
                    className="input"
                    value={ef.fragment ?? ""}
                    placeholder="1,40-60,30-50,tlshello"
                    onChange={(e) => setEf({ ...ef, fragment: e.target.value })}
                  />
                </>
              )}

              {ef.network === "ws" && (
                <div className="f-row">
                  <div>
                    <div className="f-label">WS Path</div>
                    <input className="input" value={ef.ws_path ?? ""} placeholder="/path" onChange={(e) => setEf({ ...ef, ws_path: e.target.value })} />
                  </div>
                  <div>
                    <div className="f-label">WS Host</div>
                    <input className="input" value={ef.ws_host ?? ""} onChange={(e) => setEf({ ...ef, ws_host: e.target.value })} />
                  </div>
                </div>
              )}

              {ef.network === "grpc" && (
                <>
                  <div className="f-label">gRPC Service Name</div>
                  <input className="input" value={ef.grpc_service_name ?? ""} onChange={(e) => setEf({ ...ef, grpc_service_name: e.target.value })} />
                </>
              )}

              {editing.protocol === "vless" && (
                <>
                  <div className="f-label">Flow</div>
                  <select className="input" value={ef.flow ?? ""} onChange={(e) => setEf({ ...ef, flow: e.target.value })}>
                    {["", "xtls-rprx-vision"].map((n) => <option key={n}>{n}</option>)}
                  </select>
                </>
              )}
            </div>
            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => setEditing(null)}>Cancel</button>
              <button className="btn-primary m0" onClick={saveEdit}>Save</button>
            </div>
          </div>
        </div>
      )}

      {/* share modal */}
      {sharing && (
        <div className="modal-overlay" onClick={() => setSharing(null)}>
          <div className="modal center" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">Share "{sharing.srv.name}"</div>
            <div className="modal-body">
              <div className="uri-box">{sharing.uri}</div>
              {qrUrl && <img src={qrUrl} alt="QR" className="qr-img" />}
            </div>
            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => invoke("copy_clipboard", { text: sharing.uri }).then(() => showToast("Copied ✓"))}>
                Copy
              </button>
              <button className="btn-secondary" onClick={() => (qrUrl ? setQrUrl("") : showQr())}>
                {qrUrl ? "Hide QR" : "Show QR"}
              </button>
              <button className="btn-primary m0" onClick={() => setSharing(null)}>Done</button>
            </div>
          </div>
        </div>
      )}

      {/* confirm modal */}
      {confirmDlg && (
        <div className="modal-overlay" onClick={() => setConfirmDlg(null)}>
          <div className="modal center" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">Confirm</div>
            <div className="modal-body">
              <div style={{ fontSize: 14, lineHeight: 1.6, whiteSpace: "pre-line" }}>{confirmDlg.msg}</div>
            </div>
            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => setConfirmDlg(null)}>Cancel</button>
              <button className="btn-primary m0" onClick={confirmDlg.onOk}>OK</button>
            </div>
          </div>
        </div>
      )}

      <input
        ref={fileRef}
        type="file"
        accept="image/*"
        style={{ display: "none" }}
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) decodeImageFile(f);
          e.target.value = "";
        }}
      />

      {/* bottom nav */}
      <nav className="nav">
        {([
          ["home", "home", "Home"],
          ["servers", "server", "Nodes"],
          ["subs", "layers", "Subs"],
          ["logs", "terminal", "Logs"],
          ["settings", "sliders", "Settings"],
        ] as const).map(([id, icon, label]) => (
          <button key={id} className={`nav-btn ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>
            <span className="nav-ico"><Icon name={icon} size={19} /></span>
            {id === "settings" && xrayUpdate && <span className="nav-dot" />}
            <span>{label}</span>
          </button>
        ))}
      </nav>
    </div>
    </ErrorBoundary>
  );
}

export default App;
