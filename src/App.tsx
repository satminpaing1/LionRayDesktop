import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { invoke, Channel } from "@tauri-apps/api/core";
import { getCurrentWindow, currentMonitor, LogicalSize } from "@tauri-apps/api/window";
import { getVersion } from "@tauri-apps/api/app";

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
}

type Tab = "home" | "servers" | "subs" | "settings";
type SheetMode = null | "menu" | "sub";

const PROTO_COLORS: Record<string, string> = { vless: "#6366F1", trojan: "#F59E0B", shadowsocks: "#10B981" };
// App Version is read from Tauri at runtime (the appVer state) so the
// Settings screen always shows the real, stamped build version.
let idCounter = Date.now() % 100000;

const pingColor = (ms: number | null): string =>
  ms === null ? "var(--sub)" : ms < 0 ? "#EF4444" : ms < 150 ? "#22C55E" : ms < 350 ? "#F59E0B" : "#EF4444";

interface ServerRowProps {
  s: Server;
  selected: boolean;
  onSelect: (id: number) => void;
  onPing: (id: number) => void;
  onEdit: (s: Server) => void;
  onShare: (s: Server) => void;
  onRemove: (id: number) => void;
}

// memoized: only re-renders when its own `s` / `selected` / handlers change
const ServerRow = React.memo(function ServerRow({ s, selected, onSelect, onPing, onEdit, onShare, onRemove }: ServerRowProps) {
  return (
    <div className={`row ${selected ? "sel" : ""}`} onClick={() => onSelect(s.id)}>
      <span className={`radio ${selected ? "on" : ""}`} />
      <span className="proto-chip" style={{ background: PROTO_COLORS[s.protocol] || "#888" }}>
        {s.protocol === "shadowsocks" ? "SS" : (s.protocol || "???").slice(0, 3).toUpperCase()}
      </span>
      <div className="row-main">
        <div className="row-name">{s.name || "Unnamed"}</div>
        <div className="row-meta">**** · {(s.security || "none").toUpperCase()} · {(s.network || "tcp").toUpperCase()}</div>
      </div>
      <span className="ping-val" style={{ color: pingColor(s.ping) }} onClick={(e) => { e.stopPropagation(); onPing(s.id); }}>
        {s.ping == null ? "—" : s.ping < 0 ? "ERR" : `${s.ping}`}
      </span>
      <button className="row-act" title="Edit" onClick={(e) => { e.stopPropagation(); onEdit(s); }}>✎</button>
      <button className="row-act" title="Share" onClick={(e) => { e.stopPropagation(); onShare(s); }}>📤</button>
      <button className="row-del" onClick={(e) => { e.stopPropagation(); onRemove(s.id); }}>✕</button>
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
    const A = 0.3; // EMA smoothing
    const sysPoll = setInterval(async () => {
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
    }, 1000);

    // xray session totals (for the "Total" row)
    const tpoll = setInterval(() => {
      invoke<{ down: number; up: number }>("get_traffic")
        .then((r) => setTotals({ down: r.down, up: r.up }))
        .catch(() => {});
    }, 2000);

    return () => {
      clearInterval(t);
      clearInterval(sysPoll);
      clearInterval(tpoll);
    };
  }, []);

  return (
    <>
      <div className="power-sub">Session {fmtTime(elapsed)}</div>
      <div className="speed-row">
        <div className="speed-box">
          <span className="speed-ico">⬇</span>
          <b className="speed-val">{speeds.down}</b>
          <small>DOWNLOAD</small>
        </div>
        <div className="speed-box">
          <span className="speed-ico up">⬆</span>
          <b className="speed-val">{speeds.up}</b>
          <small>UPLOAD</small>
        </div>
      </div>
      {(totals.down > 0 || totals.up > 0) && (
        <div className="usage-line">
          Via VPN ⬇ {fmtBytes(totals.down)} · ⬆ {fmtBytes(totals.up)}
        </div>
      )}
    </>
  );
}

function App() {
  const [tab, setTab] = useState<Tab>("home");
  const [servers, setServers] = useState<Server[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [subs, setSubs] = useState<Sub[]>([]);
  const [settings, setSettings] = useState<Settings>({
    routing: "lan",
    dns: "system",
    adBlock: true,
    bypassDomains: [],
    dark: false,
    autoConnect: false,
    subAutoUpdate: false,
  });
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [selBusy, setSelBusy] = useState(false);
  const [toast, setToast] = useState<{ msg: string; bad?: boolean } | null>(null);
  const [sheet, setSheet] = useState<SheetMode>(null);
  const [subUrl, setSubUrl] = useState("");
  const [qrOpen, setQrOpen] = useState(false);
  const [exitInfo, setExitInfo] = useState<ExitInfo | null>(null);
  const [coreVer, setCoreVer] = useState("...");
  const [xrayUpdate, setXrayUpdate] = useState<{ version: string; url: string } | null>(null);
  const [xrayUpdating, setXrayUpdating] = useState(false);
  const [xrayProgress, setXrayProgress] = useState(0);
  const [xrayCheckMsg, setXrayCheckMsg] = useState("");
  const [confirmDlg, setConfirmDlg] = useState<{ msg: string; onOk: () => void } | null>(null);
  const [bypassInput, setBypassInput] = useState("");
  const [appUpdate, setAppUpdate] = useState<string | null>(null);
  const [lastSrv, setLastSrv] = useState<Server | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const loadedRef = useRef(false);
  const [editing, setEditing] = useState<Server | null>(null);
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
        getVersion().then(setAppVer).catch(() => {});
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
        setSettings(
          await loadStore<Settings>("lr_settings", {
            routing: "lan",
            dns: "system",
            adBlock: true,
            bypassDomains: [],
            dark: false,
            autoConnect: false,
            subAutoUpdate: false,
          })
        );
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

  // notify the user when a newer desktop release (new app version / bundled core) is published
  useEffect(() => {
    invoke<string | null>("check_update")
      .then((t) => {
        if (t) setAppUpdate(t);
      })
      .catch(() => {});
  }, []);

  const showToast = useCallback((msg: string, bad = false) => {
    setToast({ msg, bad });
    setTimeout(() => setToast(null), 2600);
  }, []);

  // ─── init ───
  const doConnect = useCallback(
    async (srv: Server, silent = false) => {
      setBusy(true);
      try {
        await invoke("connect", {
          server: { ...srv, id: 0, ping: null },
          routing: settings.routing,
          dns: settings.dns,
          adBlock: settings.adBlock,
          bypassDomains: settings.bypassDomains,
        });
        setConnected(true);
        setLastSrv({ ...srv, id: 0, ping: null });
        if (!silent) showToast("Connected ✓");
        else showToast(`Auto-connected to ${srv.name}`);
      } catch (e) {
        if (!silent) showToast(String(e), true);
      }
      setBusy(false);
    },
    [settings.routing, settings.dns, settings.adBlock, settings.bypassDomains, showToast]
  );

  useEffect(() => {
    invoke<boolean>("is_connected").then(setConnected).catch(() => {});
    invoke<string>("get_core_version").then(setCoreVer).catch(() => {});
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
    // also surface any available APP update (shown as a global banner)
    invoke<string | null>("check_update")
      .then((t) => { if (t) setAppUpdate(t); })
      .catch(() => {});
  };

  useEffect(() => {
    // subscription auto-update on launch
    if (settings.subAutoUpdate && subs.length) {
      updateAllSubscriptions();
    }
    if (settings.autoConnect && !connected && !busy) {
      const srv = activeServer ?? servers[0];
      if (srv) {
        const t = setTimeout(() => doConnect(srv, true), 800);
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
      if (!xrayUpdate && !xrayUpdating) {
        checkXrayUpdate();
      }
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

  // ─── exit-ip lookup (15s) + auto-reconnect heartbeat (5s) ───
  // NOTE: live per-second stats (elapsed / speeds / totals) live in the
  // <LiveStats> child so the whole App no longer re-renders every tick.
  useEffect(() => {
    if (!connected) return;
    const check = () =>
      invoke<ExitInfo>("check_exit_ip")
        .then((j) => setExitInfo(j))
        .catch(() => {});
    const first = setTimeout(check, 1500);
    const poll = setInterval(check, 15000);

    // heartbeat: check if xray is alive every 5s; auto-reconnect on drop
    let wasDisconnected = false;
    const heartbeat = setInterval(async () => {
      try {
        const alive = await invoke<boolean>("is_connected");
        if (!alive && !wasDisconnected) {
          wasDisconnected = true;
          setConnected(false);
          showToast("Connection lost — reconnecting…", true);
          // retry every 3s until network is back
          const retry = async () => {
            const srv = lastSrv;
            if (!srv) return;
            try {
              await invoke("connect", {
                server: srv,
                routing: settings.routing,
                dns: settings.dns,
                adBlock: settings.adBlock,
                bypassDomains: settings.bypassDomains,
              });
              setConnected(true);
              wasDisconnected = false;
              showToast("Reconnected ✓");
            } catch {
              setTimeout(retry, 3000);
            }
          };
          setTimeout(retry, 3000);
        }
      } catch { /* ignore */ }
    }, 5000);

    return () => {
      clearTimeout(first);
      clearInterval(poll);
      clearInterval(heartbeat);
    };
  }, [connected, lastSrv, settings]);

  // ─── import helpers ───
  const appendServers = (list: Server[], subId?: number) => {
    if (!list.length) return showToast("No valid servers found", true);
    const tagged = list.map((s) => ({ ...s, id: ++idCounter, ...(subId ? { subId } : {}) }));
    setServers((prev) => [...prev, ...tagged]);
    setActiveId((cur) => cur ?? tagged[0].id);
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
          channel.onmessage = (srv: unknown) => {
            const s = srv as Server;
            setServers((prev) => [...prev, { ...s, id: ++idCounter, subId: sid }]);
          };
          await invoke("fetch_subscription_stream", { url, onServer: channel });
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
      channel.onmessage = (srv: unknown) => {
        const s = srv as Server;
        setServers((prev) => [...prev, { ...s, id: ++idCounter, subId: sid }]);
      };
      await invoke("fetch_subscription_stream", { url, onServer: channel });
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
        channel.onmessage = (srv: unknown) => {
          const s = srv as Server;
          setServers((prev) => [...prev, { ...s, id: ++idCounter, subId: sid }]);
        };
        await invoke("fetch_subscription_stream", { url: trimmed, onServer: channel });
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
      try {
        await invoke("disconnect");
        setConnected(false);
        setExitInfo(null);
        setLastSrv(null);
        showToast("Disconnected");
      } catch (e) {
        showToast(String(e), true);
      }
      setBusy(false);
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
          showToast(`Xray core → ${newVer} ✓  Restart app to use.`);
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

  const RoutingIcon = () => (
    <span className="route-chip">{settings.routing === "global" ? "🌍 Global" : settings.routing === "cn" ? "🇨🇳 Bypass CN" : "🏠 Bypass LAN"}</span>
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
          ⬆ New version {appUpdate} available — tap to download
        </div>
      )}

      {/* ═══════════ HOME ═══════════ */}
      {tab === "home" && (
        <>
          <header className="topbar">
            <span className="logo">🦁 LionRay</span>
            <RoutingIcon />
          </header>

          {/* node card */}
          <div className="node-card" onClick={() => setTab("servers")}>
            <div className="node-left">
              <div className="node-name">
                {connected && exitInfo?.countryCode && (
                  <span className="node-flag">{flagEmoji(exitInfo.countryCode)}</span>
                )}
                {activeServer ? activeServer.name : "Select a node"}
              </div>
              <div className="node-meta">
                {activeServer ? `****:${activeServer.port}` : "Tap here or + to add"}
              </div>
            </div>
            <div className="node-right" style={{ color: pingColor(activeServer?.ping ?? null) }}>
              {activeServer?.ping != null && activeServer.ping >= 0 ? `${activeServer.ping}ms` : ""}
              <span className="node-arrow">›</span>
            </div>
          </div>

          {/* power button */}
          <div className="power-zone">
            <div className="power-wrap">
              {connected && <div className="ring r1" />}
              {connected && <div className="ring r2" />}
              <button className={`power ${connected ? "on" : ""}`} disabled={busy} onClick={toggleConnect}>
                {busy ? <span className="power-busy">…</span> : connected ? "⏹" : "▶"}
              </button>
            </div>
            <div className={`power-state ${connected ? "on" : ""}`}>
              {connected ? "CONNECTED" : "NOT CONNECTED"}
            </div>
            <div className="power-sub">
              {connected ? "VPN tunnel active" : settings.autoConnect ? "Auto-connect enabled" : "Tap the button to connect"}
            </div>

            {connected && <LiveStats />}

            {connected && exitInfo?.query && (
              <div className="exit-chip" title={exitInfo.isp || ""}>
                <span className="exit-flag">{flagEmoji(exitInfo.countryCode)}</span>
                <b>{exitInfo.query}</b>
                <span className="exit-loc">{[exitInfo.city, exitInfo.country].filter(Boolean).join(", ")}</span>
              </div>
            )}
          </div>
        </>
      )}

      {/* ═══════════ SERVERS ═══════════ */}
      {tab === "servers" && (
        <>
          <header className="topbar">
            <button className="back-btn" onClick={() => setTab("home")}>‹</button>
            <span className="topbar-title">Nodes · {servers.length}</span>
            <div className="tb-actions">
              <button className="sel-btn" onClick={autoSelect} disabled={!servers.length || selBusy}>
                ✨ Auto Select
              </button>
              <button className="test-btn" onClick={pingAll} disabled={!servers.length}>⚡ Test</button>
            </div>
          </header>
          <div className="content">
            {servers.length === 0 ? (
              <div className="empty">
                <div className="empty-icon">📡</div>
                <div>No nodes yet</div>
                <small>Tap + to import via clipboard / QR / subscription</small>
              </div>
            ) : (
              <div className="list">
                {manualServers.length > 0 && (
                  <>
                    <div className="group-label">🔑 My Keys · {manualServers.length}</div>
                    {manualServers.map((s) => (
                      <ServerRow
                        key={s.id}
                        s={s}
                        selected={s.id === activeId}
                        onSelect={setActiveId}
                        onPing={pingOne}
                        onEdit={startEdit}
                        onShare={startShare}
                        onRemove={removeServer}
                      />
                    ))}
                  </>
                )}
                {subs.map((sub) => {
                  const srv = servers.filter((x) => x.subId === sub.id);
                  if (srv.length === 0 && !sub.loading) return null;
                  return (
                    <div key={`g-${sub.id}`}>
                      <div className="group-label">
                        <span>🔗 {sub.name} {sub.loading && <span className="loading-dots">…</span>}</span>
                        <span className="group-right">
                          <span className="group-count">{sub.loading ? "…" : srv.length}</span>
                          <button className="group-del" title="Delete whole profile" onClick={() => deleteSubscription(sub.id)}>🗑</button>
                        </span>
                      </div>
                      {srv.map((s) => (
                        <ServerRow
                          key={s.id}
                          s={s}
                          selected={s.id === activeId}
                          onSelect={setActiveId}
                          onPing={pingOne}
                          onEdit={startEdit}
                          onShare={startShare}
                          onRemove={removeServer}
                        />
                      ))}
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
            <button className="back-btn" onClick={() => setTab("home")}>‹</button>
            <span className="topbar-title">Subscriptions · {subs.length}</span>
            <span style={{ width: 46 }} />
          </header>
          <div className="content">
            {subs.length === 0 ? (
              <div className="empty">
                <div className="empty-icon">🔗</div>
                <div>No subscriptions</div>
                <small>Tap + → Subscriptions to add one</small>
              </div>
            ) : (
              <div className="list">
                {subs.map((sub) => {
                  const count = servers.filter((s) => s.subId === sub.id).length;
                  return (
                    <div key={sub.id} className="sub-card">
                      <div className="sub-head">
                        <div className="sub-name">{sub.name} {sub.loading && <span className="loading-dots">…</span>}</div>
                        <span className="sub-count">{sub.loading ? "…" : count}</span>
                      </div>
                      <div className="sub-url">{sub.url}</div>
                      <div className="sub-actions">
                        <button className="mini-btn primary" disabled={sub.loading} onClick={() => updateSubscription(sub)}>⟳ Update</button>
                        <button className="mini-btn danger" disabled={sub.loading} onClick={() => deleteSubscription(sub.id)}>🗑 Delete</button>
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
            <button className="back-btn" onClick={() => setTab("home")}>‹</button>
            <span className="topbar-title">Settings</span>
            <span style={{ width: 46 }} />
          </header>
          <div className="content">
            <div className="sec">Routing Mode</div>
            <div className="card seg-card">
              {([
                ["global", "🌍 Global"],
                ["lan", "🏠 Skip LAN"],
                ["cn", "🇨🇳 Skip CN"],
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

            <div className="sec">Security</div>
            <div className="card">
              <div className="toggle-row">
                <div>
                  <div className="kv-t">🛡️ Ad Blocker</div>
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
                  <div className="kv-t">🌐 DNS Server</div>
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
                      ⬇ Update Now
                    </button>
                    <button className="btn-secondary" onClick={checkXrayUpdate}>↻</button>
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
                    className="btn-primary m0"
                    style={{ marginTop: xrayCheckMsg ? 0 : 12 }}
                    onClick={checkXrayUpdate}
                  >
                    🔍 Check for Updates
                  </button>
                </>
              )}
            </div>

            <div className="sec">Community</div>
            <button
              className="btn-primary m0"
              style={{ marginBottom: 12 }}
              onClick={() => invoke("open_link", { url: "https://t.me/lionrayvpn" })}
            >
              💬 Join Telegram
            </button>

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
              🦁 Powered by Sett Min Paing
            </div>
          </div>
        </>
      )}

      {/* FAB */}
      {(tab === "servers" || tab === "subs") && (
        <button className="fab" onClick={() => setSheet(sheet === "menu" ? null : "menu")}>+</button>
      )}

      {/* action sheet */}
      {sheet && (
        <div className="overlay" onClick={() => setSheet(null)}>
          <div className="sheet" onClick={(e) => e.stopPropagation()}>
            {sheet === "menu" ? (
              <>
                <div className="sheet-title">Add Node</div>
                <button className="sheet-item" onClick={importFromClipboard}>
                  <span className="sheet-ico">📋</span>
                  <div><b>Import from Clipboard</b><small>Paste copied links</small></div>
                </button>
                <button className="sheet-item" onClick={() => { setSheet(null); startCamera(); }}>
                  <span className="sheet-ico">📷</span>
                  <div><b>Scan QR Code</b><small>Use camera</small></div>
                </button>
                <button className="sheet-item" onClick={() => { setSheet(null); fileRef.current?.click(); }}>
                  <span className="sheet-ico">🖼️</span>
                  <div><b>Import QR Photo</b><small>Decode saved image</small></div>
                </button>
                <button className="sheet-item" onClick={() => setSheet("sub")}>
                  <span className="sheet-ico">🔗</span>
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

      {/* QR camera */}
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
            <div className="modal-title">✎ Edit Config</div>
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
            <div className="modal-title">📤 Share "{sharing.srv.name}"</div>
            <div className="modal-body">
              <div className="uri-box">{sharing.uri}</div>
              {qrUrl && <img src={qrUrl} alt="QR" className="qr-img" />}
            </div>
            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => invoke("copy_clipboard", { text: sharing.uri }).then(() => showToast("Copied ✓"))}>
                📋 Copy
              </button>
              <button className="btn-secondary" onClick={() => (qrUrl ? setQrUrl("") : showQr())}>
                {qrUrl ? "Hide QR" : "📷 QR"}
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
          ["home", "⏻", "Home"],
          ["servers", "📡", "Nodes"],
          ["subs", "🔗", "Subs"],
          ["settings", "⚙", "Settings"],
        ] as const).map(([id, icon, label]) => (
          <button key={id} className={`nav-btn ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>
            <span className="nav-ico">{icon}</span>
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
