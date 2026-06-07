"""
System Monitor — Windows  v4.0
Arquitectura: todo en el hilo principal via root.after().
I/O pesado en ThreadPoolExecutor; resultados via root.after(0, cb).
v4: bloqueo firewall · privilegios SYSTEM/Admin · tareas programadas
    · registro Run · temp CPU · GPU · historial gráfico 24h
    · umbrales configurables · always-on-top · auto-inicio Windows
"""
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import time
import ipaddress
import ctypes
import ctypes.wintypes
import winsound
import psutil
import socket
import json
import os
import sys
import sqlite3
import subprocess
import hashlib
import csv
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import urllib.request
import urllib.error

try:
    import winreg
    _WINREG = True
except ImportError:
    _WINREG = False

# ─── Intervalos ────────────────────────────────────────────────────────────
REFRESH_METRICS  = 2_000
REFRESH_CONNS    = 5_000
VT_INTERVAL      = 15_000
TEMP_INTERVAL    = 6_000
GPU_INTERVAL     = 4_000
SCHED_INTERVAL   = 60_000
REG_INTERVAL     = 30_000
METRICS_SAVE_MS  = 10_000
EVTLOG_INTERVAL  = 30_000
DLL_INTERVAL     = 60_000
SVC_INTERVAL     = 60_000
HOSTS_INTERVAL   = 30_000
DNS_INTERVAL     = 45_000

_HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
_SAFE_DLL_DIRS = (
    "c:\\windows\\system32", "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",   "c:\\program files",
    "c:\\program files (x86)", "c:\\windows\\",
)
_EVTLOG_IDS = {4625, 4720, 4728, 4732, 7045, 1102, 4719}

# ─── Paleta ────────────────────────────────────────────────────────────────
BG       = "#1e1e1e"
FG       = "#ffffff"
ACCENT   = "#4fc3f7"
DIM      = "#888888"
BG2      = "#252526"
RED      = "#ef4444"
GREEN_OK = "#4ade80"
YELLOW   = "#facc15"
ORANGE   = "#f97316"
PURPLE   = "#a78bfa"

# ─── Puertos maliciosos conocidos ──────────────────────────────────────────
SUSPICIOUS_PORTS = frozenset({
    4444, 1337, 31337, 8888, 9001, 9050,
    1234, 5555, 6666, 7777, 6667, 6668,
})

# ─── Whitelist base ────────────────────────────────────────────────────────
WHITELIST = frozenset({
    "chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe",
    "explorer.exe", "OneDrive.exe", "discord.exe", "steam.exe",
    "pythonw.exe", "Code.exe",
})

# ─── Columnas de la tabla de conexiones ────────────────────────────────────
_C = {"proc": 17, "pid": 7, "ip": 18, "port": 7, "state": 14, "mb": 10}
_HEADER = (f"{'Proceso':<{_C['proc']}}{' PID':<{_C['pid']}}"
           f"{'IP Remota':<{_C['ip']}}{'Puerto':<{_C['port']}}"
           f"{'Estado':<{_C['state']}}MB Env.")
_SEP = "-" * sum(_C.values())

_executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="mon_bg")

_BASE     = os.path.dirname(os.path.abspath(__file__))
_CFG_PATH = os.path.join(_BASE, "config.json")
_DB_PATH  = os.path.join(_BASE, "monitor_history.db")

_TASK_NAME = "SystemMonitorApp"   # nombre en el Task Scheduler


# ─── Helpers globales ──────────────────────────────────────────────────────

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _clipboard_set(text: str) -> bool:
    try:
        CF = 13; GM = 0x0002
        k32, u32 = ctypes.windll.kernel32, ctypes.windll.user32
        k32.GlobalAlloc.restype  = ctypes.c_void_p
        k32.GlobalAlloc.argtypes = [ctypes.wintypes.UINT, ctypes.c_size_t]
        k32.GlobalLock.restype   = ctypes.c_void_p
        k32.GlobalLock.argtypes  = [ctypes.c_void_p]
        k32.GlobalUnlock.argtypes = k32.GlobalFree.argtypes = [ctypes.c_void_p]
        u32.OpenClipboard.argtypes    = [ctypes.c_void_p]
        u32.SetClipboardData.restype  = ctypes.c_void_p
        u32.SetClipboardData.argtypes = [ctypes.wintypes.UINT, ctypes.c_void_p]
        enc = (text + "\0").encode("utf-16-le")
        h = k32.GlobalAlloc(GM, len(enc))
        if not h: return False
        p = k32.GlobalLock(h)
        if not p: k32.GlobalFree(h); return False
        ctypes.memmove(p, enc, len(enc))
        k32.GlobalUnlock(h)
        if not u32.OpenClipboard(None): k32.GlobalFree(h); return False
        u32.EmptyClipboard(); u32.SetClipboardData(CF, h); u32.CloseClipboard()
        return True
    except Exception:
        return False


def _fmt_bytes(bps: float) -> str:
    if bps < 1_024:     return f"{bps:.0f} B"
    if bps < 1_048_576: return f"{bps/1_024:.1f} KB"
    return f"{bps/1_048_576:.2f} MB"


def _is_external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_loopback or a.is_private
                    or a.is_link_local or a.is_unspecified)
    except ValueError:
        return False


def _proc_name(pid: int) -> str:
    try:   return psutil.Process(pid).name()
    except: return "N/A"


def _proc_io_other(pid: int) -> int:
    try:   return getattr(psutil.Process(pid).io_counters(), "other_bytes", 0)
    except: return 0


def _load_cfg() -> dict:
    try:
        with open(_CFG_PATH) as f: return json.load(f)
    except Exception:
        return {}


def _save_cfg(cfg: dict):
    try:
        with open(_CFG_PATH, "w") as f: json.dump(cfg, f, indent=2)
    except Exception:
        pass


# ─── Bandeja del sistema ────────────────────────────────────────────────────

class _SysTray:
    _WM_TRAY = 0x0401
    _NIM_ADD = 0; _NIM_MODIFY = 1; _NIM_DELETE = 2
    _NIF_MESSAGE = 0x01; _NIF_ICON = 0x02; _NIF_TIP = 0x04; _NIF_INFO = 0x10
    _NIIF_INFO = 0x01; _NIIF_WARNING = 0x02
    _WM_LBUTTONUP = 0x0202; _WM_LBUTTONDBLCLK = 0x0203

    class _NID(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.wintypes.DWORD), ("hWnd", ctypes.wintypes.HWND),
            ("uID", ctypes.wintypes.UINT), ("uFlags", ctypes.wintypes.UINT),
            ("uCallbackMessage", ctypes.wintypes.UINT),
            ("hIcon", ctypes.wintypes.HICON),
            ("szTip", ctypes.c_wchar * 128),
            ("dwState", ctypes.wintypes.DWORD), ("dwStateMask", ctypes.wintypes.DWORD),
            ("szInfo", ctypes.c_wchar * 256), ("uTimeout", ctypes.wintypes.UINT),
            ("szInfoTitle", ctypes.c_wchar * 64), ("dwInfoFlags", ctypes.wintypes.DWORD),
        ]

    class _MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd", ctypes.wintypes.HWND), ("message", ctypes.wintypes.UINT),
            ("wParam", ctypes.wintypes.WPARAM), ("lParam", ctypes.wintypes.LPARAM),
            ("time", ctypes.wintypes.DWORD), ("pt", ctypes.wintypes.POINT),
        ]

    def __init__(self, on_show):
        self._on_show = on_show
        self._hwnd = None; self._nid = None; self.ok = False
        self._setup()

    def _setup(self):
        try:
            u32 = ctypes.windll.user32
            shell32 = ctypes.windll.shell32
            _WP = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.wintypes.HWND,
                                      ctypes.wintypes.UINT, ctypes.wintypes.WPARAM,
                                      ctypes.wintypes.LPARAM)
            def _proc(hwnd, msg, wp, lp):
                if msg == self._WM_TRAY and lp in (self._WM_LBUTTONUP,
                                                     self._WM_LBUTTONDBLCLK):
                    self._on_show()
                return u32.DefWindowProcW(hwnd, msg, wp, lp)
            self._cb = _WP(_proc)

            class _WCX(ctypes.Structure):
                _fields_ = [
                    ("cbSize", ctypes.wintypes.UINT), ("style", ctypes.wintypes.UINT),
                    ("lpfnWndProc", _WP), ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", ctypes.wintypes.HINSTANCE),
                    ("hIcon", ctypes.wintypes.HICON),
                    ("hCursor", ctypes.wintypes.HANDLE),
                    ("hbrBackground", ctypes.wintypes.HBRUSH),
                    ("lpszMenuName", ctypes.c_wchar_p),
                    ("lpszClassName", ctypes.c_wchar_p),
                    ("hIconSm", ctypes.wintypes.HICON),
                ]
            cls = "SysMonTray4"
            wc = _WCX(); wc.cbSize = ctypes.sizeof(_WCX)
            wc.lpfnWndProc = self._cb; wc.lpszClassName = cls
            u32.RegisterClassExW(ctypes.byref(wc))
            u32.CreateWindowExW.restype = ctypes.wintypes.HWND
            self._hwnd = u32.CreateWindowExW(
                0, cls, cls, 0, 0, 0, 0, 0,
                ctypes.cast(-3, ctypes.wintypes.HWND), None, None, None)
            if not self._hwnd: return
            ics = (ctypes.wintypes.HICON * 1)()
            shell32.ExtractIconExW(sys.executable, 0, None, ics, 1)
            icon = ics[0]
            if not icon:
                icl = (ctypes.wintypes.HICON * 1)()
                shell32.ExtractIconExW(
                    "C:\\Windows\\System32\\shell32.dll", 15, icl, None, 1)
                icon = icl[0]
            nid = self._NID()
            nid.cbSize = ctypes.sizeof(self._NID); nid.hWnd = self._hwnd
            nid.uID = 1; nid.uFlags = self._NIF_ICON | self._NIF_MESSAGE | self._NIF_TIP
            nid.uCallbackMessage = self._WM_TRAY
            nid.hIcon = icon; nid.szTip = "System Monitor"
            shell32.Shell_NotifyIconW(self._NIM_ADD, ctypes.byref(nid))
            self._nid = nid; self.ok = True
        except Exception:
            pass

    def notify(self, title: str, msg: str, warning: bool = False):
        if not self.ok: return
        try:
            n = self._NID()
            ctypes.memmove(ctypes.byref(n), ctypes.byref(self._nid), ctypes.sizeof(n))
            n.uFlags = self._NIF_INFO; n.szInfoTitle = title[:63]
            n.szInfo = msg[:255]
            n.dwInfoFlags = self._NIIF_WARNING if warning else self._NIIF_INFO
            ctypes.windll.shell32.Shell_NotifyIconW(self._NIM_MODIFY, ctypes.byref(n))
        except Exception:
            pass

    def poll(self):
        if not self.ok or not self._hwnd: return
        try:
            msg = self._MSG(); u32 = ctypes.windll.user32
            while u32.PeekMessageW(ctypes.byref(msg), self._hwnd, 0, 0, 1):
                u32.TranslateMessage(ctypes.byref(msg))
                u32.DispatchMessageW(ctypes.byref(msg))
        except Exception:
            pass

    def remove(self):
        if not self.ok or not self._nid: return
        try:
            ctypes.windll.shell32.Shell_NotifyIconW(
                self._NIM_DELETE, ctypes.byref(self._nid))
        except Exception:
            pass


# ─── Monitor principal ─────────────────────────────────────────────────────

class Monitor:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("System Monitor")
        self.root.configure(bg=BG)
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"780x{min(960, int(sh * 0.92))}")
        self.root.minsize(680, 540)
        self.root.resizable(True, True)

        # Config y umbrales
        self._cfg = _load_cfg()
        self._cpu_thresh = float(self._cfg.get("cpu_thresh", 90))
        self._ram_thresh = float(self._cfg.get("ram_thresh", 90))

        # Métricas de red/disco
        self._prev_net    = psutil.net_io_counters()
        self._prev_time   = time.monotonic()
        try:    self._prev_disk_io = psutil.disk_io_counters()
        except: self._prev_disk_io = None

        # Última lectura de métricas (para guardar en DB)
        self._last_cpu = self._last_ram = 0.0
        self._last_sent = self._last_recv = 0.0
        self._last_dr = self._last_dw = 0.0
        self._cpu_temp = -1.0
        self._gpu_info: dict = {}

        # Historial de red para gráfico
        self._net_sent_hist: deque = deque(maxlen=60)
        self._net_recv_hist: deque = deque(maxlen=60)

        # Bytes acumulados por PID
        self._session_bytes: dict = {}
        self._prev_io:       dict = {}

        # Conexiones
        self._suspicious_ips:  list = []
        self._suspicious_rows: list = []
        self._last_rows:       list = []

        # Alertas seguridad
        self._known_suspicious: set = set()
        self._flash_job = None
        self._cpu_alerted = self._ram_alerted = False

        # Sesión
        self._start_time   = time.monotonic()
        self._session_susp = 0

        # Whitelist persistente
        self._user_whitelist: set = set(self._cfg.get("whitelist", []))
        self._alert_procs:    set = set()

        # Resolución IP
        self._ip_info: dict = {}

        # VirusTotal
        self._vt_queue: list      = []
        self._vt_ip_cache: dict   = {}
        self._hash_vt_cache: dict = {}
        self._vt_daily: int       = 0
        self._vt_day_t: float     = time.monotonic()

        # Firma digital
        self._sig_cache: dict = {}

        # Hash ejecutables
        self._exe_hash: dict  = {}

        # Firewall blocks activos: rule_name -> {proc, exe, time}
        self._fw_blocks: dict = {}

        # Monitoreo de tareas programadas
        self._known_tasks: set | None = None

        # Monitoreo de registro Run
        self._known_reg: dict | None = None

        # Nuevas funciones v5
        self._hosts_hash       = ""
        self._known_services: set | None = None
        self._evtlog_events: list = []       # lista de dicts recientes
        self._evtlog_new: list   = []        # pendientes de mostrar
        self._dns_suspicious: list = []
        self._disk_thresh      = float(self._cfg.get("disk_thresh", 92))
        self._disk_alerted     = False
        self._compact_win      = None
        self._compact_labels: dict = {}

        # Tooltip
        self._tooltip_win = None

        # SQLite
        self._db = None
        self._init_db()

        # Tray
        self._tray: _SysTray | None = None

        self._build_ui()
        self._setup_tray()

        psutil.cpu_percent()

        self.root.after(200,             self._tick_metrics)
        self.root.after(REFRESH_CONNS,   self._tick_conns)
        self.root.after(VT_INTERVAL,     self._tick_vt)
        self.root.after(150,             self._tick_tray)
        self.root.after(TEMP_INTERVAL,   self._tick_temp)
        self.root.after(GPU_INTERVAL,    self._tick_gpu)
        self.root.after(SCHED_INTERVAL,  self._tick_sched)
        self.root.after(REG_INTERVAL,    self._tick_reg)
        self.root.after(METRICS_SAVE_MS, self._tick_save_metrics)
        self.root.after(EVTLOG_INTERVAL,  self._tick_evtlog)
        self.root.after(DLL_INTERVAL,     self._tick_dll)
        self.root.after(SVC_INTERVAL,     self._tick_services)
        self.root.after(HOSTS_INTERVAL,   self._tick_hosts)
        self.root.after(DNS_INTERVAL,     self._tick_dns)

        self.root.protocol("WM_DELETE_WINDOW", self._quit)

    # ── Init ────────────────────────────────────────────────────────────────

    def _init_db(self):
        try:
            self._db = sqlite3.connect(_DB_PATH, check_same_thread=False)
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT, proc TEXT, pid INTEGER,
                    ip TEXT, port INTEGER, state TEXT, mb REAL,
                    suspicious INTEGER, country TEXT, org TEXT
                )""")
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS metrics_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT, cpu REAL, ram REAL,
                    net_sent REAL, net_recv REAL,
                    disk_r REAL, disk_w REAL, cpu_temp REAL
                )""")
            # Migración columnas opcionales
            cols = {r[1] for r in self._db.execute("PRAGMA table_info(connections)")}
            for c, t in [("country","TEXT"),("org","TEXT")]:
                if c not in cols:
                    self._db.execute(f"ALTER TABLE connections ADD COLUMN {c} {t}")
            self._db.commit()
        except Exception:
            self._db = None

    def _setup_tray(self):
        try:
            self._tray = _SysTray(on_show=self._restore_from_tray)
        except Exception:
            self._tray = None

    def _restore_from_tray(self):
        self.root.deiconify(); self.root.lift(); self.root.focus_force()

    def _tick_tray(self):
        if self._tray: self._tray.poll()
        self.root.after(150, self._tick_tray)

    def _quit(self):
        if self._tray: self._tray.remove()
        try:   _executor.shutdown(wait=False, cancel_futures=True)
        except: pass
        try:
            if self._db: self._db.close()
        except: pass
        self.root.destroy()

    # ── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._vscroll = tk.Scrollbar(self.root, orient="vertical",
                                     bg=BG, troughcolor=BG2, activebackground=ACCENT)
        self._vscroll.pack(side="right", fill="y")
        self._canvas = tk.Canvas(self.root, bg=BG, highlightthickness=0,
                                 yscrollcommand=self._vscroll.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        self._vscroll.config(command=self._canvas.yview)
        cf = tk.Frame(self._canvas, bg=BG)
        self._cf_id = self._canvas.create_window((0, 0), window=cf, anchor="nw")
        cf.bind("<Configure>",
                lambda e: self._canvas.configure(
                    scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>",
                          lambda e: self._canvas.itemconfig(self._cf_id, width=e.width))
        self._canvas.bind_all("<MouseWheel>",
                              lambda e: self._canvas.yview_scroll(
                                  -1*(e.delta//120), "units"))
        root = cf

        # Banner alerta (overlay)
        self._alert_frame = tk.Frame(self.root, bg="#c0392b", height=50)
        inner = tk.Frame(self._alert_frame, bg="#c0392b")
        inner.pack(fill="both", expand=True)
        self._alert_lbl = tk.Label(inner, text="", font=("Segoe UI", 10, "bold"),
                                   bg="#c0392b", fg="white", anchor="w")
        self._alert_lbl.pack(side="left", padx=14, pady=10)
        tk.Button(inner, text="Descartar", font=("Segoe UI", 8),
                  bg="#922b21", fg="white", activebackground="#7b241c",
                  activeforeground="white", relief="flat", bd=0,
                  padx=8, pady=4, cursor="hand2",
                  command=self._dismiss_alert).pack(side="right", padx=(4,10), pady=8)
        tk.Button(inner, text="+ Whitelist", font=("Segoe UI", 8, "bold"),
                  bg="#1a5c2a", fg="white", activebackground="#145022",
                  activeforeground="white", relief="flat", bd=0,
                  padx=10, pady=4, cursor="hand2",
                  command=self._add_to_whitelist).pack(side="right", padx=4, pady=8)
        tk.Button(inner, text="🛡 Bloquear FW", font=("Segoe UI", 8, "bold"),
                  bg="#7c3aed", fg="white", activebackground="#6d28d9",
                  activeforeground="white", relief="flat", bd=0,
                  padx=10, pady=4, cursor="hand2",
                  command=self._block_alert_procs).pack(side="right", padx=4, pady=8)

        # Título
        tk.Label(root, text="System Monitor",
                 font=("Segoe UI", 16, "bold"), bg=BG, fg=ACCENT).pack(pady=(20,2))
        self._session_lbl = tk.Label(root, text="Sesión: 0h 00m  |  Sospechosas: 0",
                                     font=("Segoe UI", 8), bg=BG, fg=DIM)
        self._session_lbl.pack()
        tk.Frame(root, height=1, bg=DIM).pack(fill="x", padx=30, pady=(8,12))

        # Métricas grid
        grid = tk.Frame(root, bg=BG)
        grid.pack(padx=40, fill="x")
        self._labels = {}
        for i, (key, lbl) in enumerate([
            ("cpu",      "CPU"),
            ("cpu_temp", "Temp CPU"),
            ("gpu",      "GPU"),
            ("ram",      "RAM"),
            ("disk",     "Disco C:"),
            ("disk_r",   "Disco R:"),
            ("disk_w",   "Disco W:"),
            ("net_sent", "Red ↑"),
            ("net_recv", "Red ↓"),
        ]):
            tk.Label(grid, text=lbl, font=("Segoe UI", 10, "bold"),
                     bg=BG, fg=ACCENT, anchor="w", width=12,
                     ).grid(row=i, column=0, pady=4, sticky="w")
            v = tk.Label(grid, text="...", font=("Segoe UI", 10),
                         bg=BG, fg=FG, anchor="w")
            v.grid(row=i, column=1, pady=4, sticky="w")
            self._labels[key] = v
        self._ts_metrics = tk.Label(root, text="", font=("Segoe UI", 8), bg=BG, fg=DIM)
        self._ts_metrics.pack(anchor="e", padx=40)

        # Gráfico de red
        nh = tk.Frame(root, bg=BG)
        nh.pack(fill="x", padx=40, pady=(10,2))
        tk.Label(nh, text="Red — últimos 2 min",
                 font=("Segoe UI", 8, "bold"), bg=BG, fg=DIM).pack(side="left")
        for sym, col, txt in [("■", GREEN_OK, "↓ Recv  "), ("■", ACCENT, "↑ Sent  ")]:
            tk.Label(nh, text=sym, font=("Segoe UI", 9), bg=BG, fg=col).pack(side="right")
            tk.Label(nh, text=txt, font=("Segoe UI", 8), bg=BG, fg=DIM).pack(side="right")
        self._net_canvas = tk.Canvas(root, bg=BG2, height=70, highlightthickness=0)
        self._net_canvas.pack(fill="x", padx=40, pady=(0,10))

        # Top procesos
        tk.Frame(root, height=1, bg=DIM).pack(fill="x", padx=30)
        tp_h = tk.Frame(root, bg=BG)
        tp_h.pack(fill="x", padx=30, pady=(8,2))
        tk.Label(tp_h, text="Top procesos por CPU",
                 font=("Segoe UI", 10, "bold"), bg=BG, fg=ACCENT).pack(side="left")
        tf = tk.Frame(root, bg=BG2)
        tf.pack(fill="x", padx=30, pady=(0,8))
        self._top_text = tk.Text(tf, font=("Consolas", 9), bg=BG2, fg=FG,
                                  relief="flat", bd=0, height=7,
                                  state="disabled", wrap="none")
        self._top_text.pack(fill="x", padx=8, pady=4)
        for t, c in [("header", ACCENT), ("dim", DIM),
                     ("high", ORANGE), ("sys", PURPLE), ("normal", FG)]:
            self._top_text.tag_configure(t, foreground=c)

        # Conexiones
        tk.Frame(root, height=1, bg=DIM).pack(fill="x", padx=30)
        sec = tk.Frame(root, bg=BG)
        sec.pack(fill="x", padx=30, pady=(8,2))
        tk.Label(sec, text="Conexiones Externas — Anti-Troyano",
                 font=("Segoe UI", 11, "bold"), bg=BG, fg=ACCENT).pack(side="left")
        self._ts_conns = tk.Label(sec, text="(actualizando...)",
                                  font=("Segoe UI", 8), bg=BG, fg=DIM)
        self._ts_conns.pack(side="right")
        leg = tk.Frame(root, bg=BG)
        leg.pack(fill="x", padx=30, pady=(0,4))
        for txt, col in [("■ Sospechoso", RED), ("■ VT limpio", YELLOW),
                         ("■ Puerto peligroso", ORANGE), ("  hover → info", DIM)]:
            tk.Label(leg, text=txt, font=("Consolas", 8),
                     bg=BG, fg=col).pack(side="left", padx=(0,12))
        cf2 = tk.Frame(root, bg=BG2)
        cf2.pack(fill="x", padx=30, pady=(0,8))
        self._conn_text = tk.Text(cf2, font=("Consolas", 9), bg=BG2, fg=FG,
                                   insertbackground=BG2, relief="flat", bd=0,
                                   height=13, state="disabled", wrap="none")
        self._conn_text.pack(fill="x", padx=8, pady=6)
        for tag, col in [("header", ACCENT), ("dim", DIM), ("suspicious", RED),
                         ("vt_safe", YELLOW), ("port_bad", ORANGE), ("safe", FG)]:
            self._conn_text.tag_configure(tag, foreground=col)
        self._conn_text.bind("<Motion>", self._on_conn_motion)
        self._conn_text.bind("<Leave>",  self._on_conn_leave)

        # Barra de botones
        bar = tk.Frame(root, bg=BG)
        bar.pack(fill="x", padx=30, pady=(0,6))
        tk.Button(bar, text="Copiar IPs sospechosas",
                  font=("Segoe UI", 9, "bold"), bg="#3a1212", fg=RED,
                  activebackground="#5a2020", activeforeground=RED,
                  relief="flat", bd=0, padx=12, pady=6, cursor="hand2",
                  command=self._copy_suspicious).pack(side="left")
        self._susp_lbl = tk.Label(bar, text="", font=("Segoe UI", 9), bg=BG, fg=DIM)
        self._susp_lbl.pack(side="left", padx=10)

        # Botones derechos
        btn_cfg = [
            ("Salir",            DIM,      self._quit),
            ("Historial",        ACCENT,   self._open_history),
            ("Métricas 24h",     ACCENT,   self._open_metrics_history),
            ("⚙ Config",         YELLOW,   self._open_settings),
            ("📋 HTML",          GREEN_OK, self._export_html),
            ("🗺 Geo Mapa",      ACCENT,   self._open_geo_map),
            ("🔲 Compacto",      DIM,      self._open_compact),
        ]
        for txt, col, cmd in btn_cfg:
            tk.Button(bar, text=txt, font=("Segoe UI", 9), bg=BG2, fg=col,
                      activebackground="#333", relief="flat", bd=0,
                      padx=10, pady=6, cursor="hand2",
                      command=cmd).pack(side="right", padx=3)

        # Segunda barra (API VT + always-on-top + FW blocks)
        bar2 = tk.Frame(root, bg=BG)
        bar2.pack(fill="x", padx=30, pady=(0,10))
        has_key = bool(self._cfg.get("vt_api_key",""))
        self._vt_key_btn = tk.Button(
            bar2, text="API VT " + ("✓" if has_key else "✗"),
            font=("Segoe UI", 9), bg=BG2,
            fg=GREEN_OK if has_key else DIM,
            activebackground="#333", relief="flat", bd=0,
            padx=10, pady=5, cursor="hand2",
            command=self._prompt_vt_key)
        self._vt_key_btn.pack(side="left")

        self._topmost_var = tk.BooleanVar(value=False)
        tk.Checkbutton(bar2, text="📌 Siempre visible",
                       variable=self._topmost_var,
                       command=lambda: self.root.wm_attributes(
                           "-topmost", self._topmost_var.get()),
                       font=("Segoe UI", 9), bg=BG, fg=FG,
                       selectcolor=BG2, activebackground=BG,
                       relief="flat", bd=0).pack(side="left", padx=10)

        self._fw_btn = tk.Button(
            bar2, text="FW blocks: 0",
            font=("Segoe UI", 9), bg=BG2, fg=DIM,
            activebackground="#333", relief="flat", bd=0,
            padx=10, pady=5, cursor="hand2",
            command=self._open_fw_manager)
        self._fw_btn.pack(side="left")

        self._evtlog_btn = tk.Button(
            bar2, text="🔍 Eventos",
            font=("Segoe UI", 9), bg=BG2, fg=DIM,
            activebackground="#333", relief="flat", bd=0,
            padx=10, pady=5, cursor="hand2",
            command=self._open_evtlog)
        self._evtlog_btn.pack(side="left", padx=4)

        # Estado de admin
        adm_txt = "✓ Admin" if _is_admin() else "✗ Sin admin (FW limitado)"
        adm_col = GREEN_OK if _is_admin() else ORANGE
        tk.Label(bar2, text=adm_txt, font=("Segoe UI", 8),
                 bg=BG, fg=adm_col).pack(side="right", padx=10)

        # Whitelist
        tk.Frame(root, height=1, bg=DIM).pack(fill="x", padx=30, pady=(6,0))
        wh = tk.Frame(root, bg=BG)
        wh.pack(fill="x", padx=30, pady=(6,2))
        tk.Label(wh, text="Whitelist personalizada (persistente):",
                 font=("Segoe UI", 8, "bold"), bg=BG, fg=DIM).pack(side="left")
        self._wl_frame = tk.Frame(root, bg=BG)
        self._wl_frame.pack(fill="x", padx=30, pady=(0,16))
        self._refresh_whitelist_display()

    # ── Métricas ────────────────────────────────────────────────────────────

    def _tick_metrics(self):
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            try:
                dsk = psutil.disk_usage("C:\\")
                du, dt_, dp = dsk.used/1024**3, dsk.total/1024**3, dsk.percent
            except OSError:
                du = dt_ = dp = 0.0

            now = time.monotonic()
            net = psutil.net_io_counters()
            dt  = max(now - self._prev_time, 1e-6)
            sp  = max((net.bytes_sent - self._prev_net.bytes_sent) / dt, 0)
            rp  = max((net.bytes_recv - self._prev_net.bytes_recv) / dt, 0)
            self._prev_net = net; self._prev_time = now

            dr = dw = 0.0
            try:
                if self._prev_disk_io:
                    dio = psutil.disk_io_counters()
                    dr = max((dio.read_bytes  - self._prev_disk_io.read_bytes)  / dt, 0)
                    dw = max((dio.write_bytes - self._prev_disk_io.write_bytes) / dt, 0)
                    self._prev_disk_io = dio
            except Exception:
                pass

            # Guardar última lectura
            self._last_cpu = cpu; self._last_ram = mem.percent
            self._last_sent = sp; self._last_recv = rp
            self._last_dr = dr;   self._last_dw = dw

            # Colores por umbral
            cpu_fg = RED if cpu >= self._cpu_thresh else FG
            ram_fg = RED if mem.percent >= self._ram_thresh else FG

            self._labels["cpu"].config(text=f"{cpu:.1f}%", fg=cpu_fg)
            self._labels["ram"].config(
                text=(f"{mem.used/1024**3:.2f}/{mem.total/1024**3:.2f} GB"
                      f"  ({mem.percent:.1f}%)"), fg=ram_fg)
            self._labels["disk"].config(
                text=f"{du:.1f}/{dt_:.1f} GB  ({dp:.1f}%)", fg=FG)
            self._labels["disk_r"].config(text=_fmt_bytes(dr)+"/s", fg=FG)
            self._labels["disk_w"].config(text=_fmt_bytes(dw)+"/s", fg=FG)
            self._labels["net_sent"].config(text=_fmt_bytes(sp)+"/s", fg=FG)
            self._labels["net_recv"].config(text=_fmt_bytes(rp)+"/s", fg=FG)
            self._ts_metrics.config(
                text=f"metricas: {time.strftime('%H:%M:%S')}", fg=DIM)

            self._net_sent_hist.append(sp)
            self._net_recv_hist.append(rp)
            self._redraw_net_graph()

            elapsed = now - self._start_time
            h, r = divmod(int(elapsed), 3600); m, _ = divmod(r, 60)
            self._session_lbl.config(
                text=f"Sesión: {h}h {m:02d}m  |  Conexiones sospechosas: {self._session_susp}")

            self._check_resource_alerts(cpu, mem.percent, dp)
            self._update_top_procs()
        except Exception as e:
            self._ts_metrics.config(text=f"Error: {e}", fg=RED)
        self.root.after(REFRESH_METRICS, self._tick_metrics)

    def _check_resource_alerts(self, cpu: float, ram: float, disk: float = 0.0):
        if cpu >= self._cpu_thresh and not self._cpu_alerted:
            self._cpu_alerted = True
            if self._tray:
                self._tray.notify("⚠ CPU alta", f"CPU al {cpu:.0f}%", warning=True)
        elif cpu < self._cpu_thresh - 5:
            self._cpu_alerted = False
        if ram >= self._ram_thresh and not self._ram_alerted:
            self._ram_alerted = True
            if self._tray:
                self._tray.notify("⚠ RAM alta", f"RAM al {ram:.0f}%", warning=True)
        elif ram < self._ram_thresh - 5:
            self._ram_alerted = False
        if disk >= self._disk_thresh and not self._disk_alerted:
            self._disk_alerted = True
            if self._tray:
                self._tray.notify("⚠ Disco lleno", f"C: al {disk:.0f}%", warning=True)
        elif disk < self._disk_thresh - 3:
            self._disk_alerted = False

    def _redraw_net_graph(self):
        try:
            c = self._net_canvas; c.delete("all")
            w, h = c.winfo_width(), c.winfo_height()
            if w < 10 or h < 10: return
            sent = list(self._net_sent_hist)
            recv = list(self._net_recv_hist)
            if not sent and not recv: return
            peak = max(max(sent, default=0), max(recv, default=0), 1)
            PX, PY = 2, 4; gh = h - PY*2
            for frac in (0.25, 0.5, 0.75):
                gy = int(h - PY - frac*gh)
                c.create_line(PX, gy, w-PX, gy, fill="#2d2d2d", dash=(2,4))
            def _pts(s):
                n = len(s)
                if n < 2: return []
                r = []
                for i, v in enumerate(s):
                    r.extend([int(PX+i*(w-2*PX)/(n-1)),
                               int(h-PY-(v/peak)*gh)])
                return r
            pr, ps = _pts(recv), _pts(sent)
            if len(pr) >= 4: c.create_line(*pr, fill=GREEN_OK, width=1.5, smooth=True)
            if len(ps) >= 4: c.create_line(*ps, fill=ACCENT,   width=1.5, smooth=True)
            c.create_text(w-4, 3, text=_fmt_bytes(peak)+"/s",
                          anchor="ne", fill=DIM, font=("Consolas", 7))
        except Exception:
            pass

    def _update_top_procs(self):
        try:
            procs = sorted(
                [p.info for p in psutil.process_iter(
                    ["pid","name","cpu_percent","memory_percent","username","create_time"])
                 if p.info.get("cpu_percent") is not None],
                key=lambda x: x.get("cpu_percent") or 0, reverse=True)
            w = self._top_text
            w.config(state="normal"); w.delete("1.0","end")
            hdr = f"{'Proceso':<21}{'PID':<7}{'CPU%':>6}  {'RAM%':>6}  {'Uptime':<10}  Usuario"
            w.insert("end", hdr+"\n", "header")
            w.insert("end", "-"*len(hdr)+"\n", "dim")
            now = time.time()
            for p in procs[:5]:
                name  = str(p.get("name") or "N/A")[:20]
                pid   = str(p.get("pid")  or "")
                cpu   = p.get("cpu_percent") or 0.0
                ram   = p.get("memory_percent") or 0.0
                uname = str(p.get("username") or "")
                is_sys = any(k in uname.upper() for k in ("SYSTEM","AUTHORITY"))
                short_u = uname.split("\\")[-1][:14] if uname else ""
                ct = p.get("create_time") or now
                up_s = int(now - ct)
                if up_s < 3600:   up = f"{up_s//60}m{up_s%60:02d}s"
                elif up_s < 86400: up = f"{up_s//3600}h{(up_s%3600)//60:02d}m"
                else:              up = f"{up_s//86400}d{(up_s%86400)//3600:02d}h"
                line = f"{name:<21}{pid:<7}{cpu:>6.1f}  {ram:>6.1f}  {up:<10}  {short_u}"
                tag = "sys" if is_sys else ("high" if cpu > 40 else "normal")
                w.insert("end", line+"\n", tag)
            w.config(state="disabled")
        except Exception:
            pass

    # ── Temp CPU ────────────────────────────────────────────────────────────

    def _tick_temp(self):
        fut = _executor.submit(self._bg_cpu_temp)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_temp_done, f))
        self.root.after(TEMP_INTERVAL, self._tick_temp)

    @staticmethod
    def _bg_cpu_temp() -> float:
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WmiObject -Namespace root\\wmi "
                 "-Class MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue"
                 " | Select-Object -First 1 -ExpandProperty CurrentTemperature"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW)
            raw = r.stdout.strip()
            if raw and raw.lstrip("-").isdigit():
                return round(int(raw) / 10.0 - 273.15, 1)
        except Exception:
            pass
        return -1.0

    def _on_temp_done(self, future):
        try:
            t = future.result()
            self._cpu_temp = t
            if t >= 0:
                col = RED if t > 85 else (ORANGE if t > 70 else FG)
                self._labels["cpu_temp"].config(text=f"{t:.1f} °C", fg=col)
            else:
                self._labels["cpu_temp"].config(text="N/D", fg=DIM)
        except Exception:
            pass

    # ── GPU ─────────────────────────────────────────────────────────────────

    def _tick_gpu(self):
        fut = _executor.submit(self._bg_gpu_info)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_gpu_done, f))
        self.root.after(GPU_INTERVAL, self._tick_gpu)

    @staticmethod
    def _bg_gpu_info() -> dict:
        # Intento 1: nvidia-smi
        try:
            r = subprocess.run(
                ["nvidia-smi",
                 "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW)
            if r.returncode == 0 and r.stdout.strip():
                p = [x.strip() for x in r.stdout.strip().split(",")]
                if len(p) >= 5:
                    return {"vendor": "NVIDIA", "name": p[0],
                            "util": float(p[1]), "mem_used": float(p[2]),
                            "mem_total": float(p[3]), "temp": float(p[4])}
        except FileNotFoundError:
            pass
        except Exception:
            pass
        # Intento 2: WMI (nombre y VRAM solamente)
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WmiObject Win32_VideoController "
                 "| Select-Object -First 1 Name,AdapterRAM "
                 "| ForEach-Object { $_.Name + '|' + $_.AdapterRAM }"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW)
            out = r.stdout.strip()
            if out and "|" in out:
                name, vram = out.split("|", 1)
                vram_mb = int(vram.strip() or 0) // 1_048_576
                return {"vendor": "WMI", "name": name.strip(),
                        "vram_mb": vram_mb}
        except Exception:
            pass
        return {}

    def _on_gpu_done(self, future):
        try:
            info = future.result()
            self._gpu_info = info
            if not info:
                self._labels["gpu"].config(text="N/D", fg=DIM)
                return
            if info.get("vendor") == "NVIDIA":
                col = RED if info["temp"] > 85 else FG
                text = (f"{info['util']:.0f}%  "
                        f"{info['mem_used']:.0f}/{info['mem_total']:.0f} MB  "
                        f"{info['temp']:.0f}°C  [{info['name']}]")
                self._labels["gpu"].config(text=text, fg=col)
            else:
                vram = info.get("vram_mb", 0)
                self._labels["gpu"].config(
                    text=f"{info['name']}  {vram} MB VRAM", fg=DIM)
        except Exception:
            pass

    # ── Guardar métricas en DB ───────────────────────────────────────────────

    def _tick_save_metrics(self):
        try:
            if self._db:
                self._db.execute(
                    "INSERT INTO metrics_history "
                    "(timestamp,cpu,ram,net_sent,net_recv,disk_r,disk_w,cpu_temp) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (time.strftime("%Y-%m-%d %H:%M:%S"),
                     self._last_cpu, self._last_ram,
                     self._last_sent, self._last_recv,
                     self._last_dr, self._last_dw, self._cpu_temp))
                self._db.execute(
                    "DELETE FROM metrics_history "
                    "WHERE timestamp < datetime('now','-24 hours')")
                self._db.commit()
        except Exception:
            pass
        self.root.after(METRICS_SAVE_MS, self._tick_save_metrics)

    # ── Tareas programadas ──────────────────────────────────────────────────

    def _tick_sched(self):
        fut = _executor.submit(self._bg_sched_tasks)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_sched_done, f))
        self.root.after(SCHED_INTERVAL, self._tick_sched)

    @staticmethod
    def _bg_sched_tasks() -> set:
        try:
            r = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW)
            tasks = set()
            for line in r.stdout.splitlines()[1:]:
                line = line.strip().strip('"')
                if line:
                    tasks.add(line.split('","')[0])
            return tasks
        except Exception:
            return set()

    def _on_sched_done(self, future):
        try:
            current = future.result()
            if self._known_tasks is None:
                self._known_tasks = current; return
            new = current - self._known_tasks
            if new:
                self._known_tasks = current
                names = ", ".join(list(new)[:3])
                if self._tray:
                    self._tray.notify("⚠ Nueva tarea programada",
                                      names, warning=True)
                self._susp_lbl.config(
                    text=f"  Nueva tarea: {names}", fg=ORANGE)
        except Exception:
            pass

    # ── Registro Run/RunOnce ────────────────────────────────────────────────

    def _tick_reg(self):
        if not _WINREG:
            return
        fut = _executor.submit(self._bg_reg_keys)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_reg_done, f))
        self.root.after(REG_INTERVAL, self._tick_reg)

    @staticmethod
    def _bg_reg_keys() -> dict:
        result = {}
        if not _WINREG:
            return result
        paths = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        for hive, path in paths:
            try:
                key = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        result[f"{path}\\{name}"] = str(val)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                pass
        return result

    def _on_reg_done(self, future):
        try:
            current = future.result()
            if self._known_reg is None:
                self._known_reg = current; return
            new_keys = set(current) - set(self._known_reg)
            if new_keys:
                self._known_reg = current
                short = [k.split("\\")[-1] for k in list(new_keys)[:3]]
                if self._tray:
                    self._tray.notify("⚠ Nueva clave Run detectada",
                                      ", ".join(short), warning=True)
                self._susp_lbl.config(
                    text=f"  Reg Run nuevo: {', '.join(short)}", fg=ORANGE)
        except Exception:
            pass

    # ── Conexiones ──────────────────────────────────────────────────────────

    def _tick_conns(self):
        try:
            rows, susp_ips = self._collect_conns()
            self._suspicious_ips  = susp_ips
            self._suspicious_rows = [r for r in rows if r["suspicious"] or r["port_bad"]]
            self._last_rows       = rows
            self._render_conns(rows, len(susp_ips))
            self._check_alerts(rows)
            self._save_to_history(rows)
            for r in rows: self._resolve_ip_async(r["ip"])
            for ip in susp_ips: self._enqueue_vt("ip", ip)
            for r in rows:
                if r["suspicious"] and r["pid"]: self._enqueue_hash_check(r["pid"])
        except Exception as e:
            self._ts_conns.config(text=f"Error: {e}", fg=RED)
        self.root.after(REFRESH_CONNS, self._tick_conns)

    def _collect_conns(self):
        try:
            raw = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError):
            self._ts_conns.config(
                text="Sin permisos — ejecuta como Administrador", fg=RED)
            return [], []
        except Exception:
            return [], []
        rows = []; seen_ips = {}
        for c in raw:
            if not c.raddr: continue
            ip = c.raddr.ip
            if not _is_external(ip): continue
            if c.status not in ("ESTABLISHED","LISTEN"): continue
            pid  = c.pid or 0
            name = _proc_name(pid) if pid else "N/A"
            curr = _proc_io_other(pid)
            prev = self._prev_io.get(pid, curr)
            self._prev_io[pid] = curr
            self._session_bytes[pid] = (
                self._session_bytes.get(pid, 0) + max(curr-prev, 0))
            port_bad  = c.raddr.port in SUSPICIOUS_PORTS
            suspicious = ((name not in WHITELIST and name not in self._user_whitelist)
                          or port_bad)
            if suspicious: seen_ips[ip] = None
            # Proceso padre
            parent_name = ""
            try:
                par = psutil.Process(pid).parent()
                parent_name = par.name() if par else ""
            except Exception:
                pass
            # Privilegios
            uname = ""; elevated = False
            try:
                uname = psutil.Process(pid).username() or ""
                elevated = any(k in uname.upper()
                               for k in ("SYSTEM","NT AUTHORITY"))
            except Exception:
                pass
            rows.append({
                "proc": name, "pid": pid, "ip": ip,
                "port": c.raddr.port, "state": c.status,
                "mb": self._session_bytes.get(pid,0)/1024**2,
                "suspicious": suspicious, "port_bad": port_bad,
                "parent": parent_name,
                "user": uname, "elevated": elevated,
            })
        rows.sort(key=lambda r: (0 if (r["suspicious"] or r["port_bad"]) else 1,
                                  r["proc"].lower()))
        return rows[:10], list(seen_ips)

    def _render_conns(self, rows: list, susp_count: int):
        w = self._conn_text
        w.config(state="normal"); w.delete("1.0","end")
        w.insert("end", _HEADER+"\n", "header")
        w.insert("end", _SEP+"\n",    "dim")
        if not rows:
            w.insert("end","  Sin conexiones externas.\n","dim")
        else:
            for r in rows:
                line = (f"{r['proc'][:_C['proc']-1]:<{_C['proc']}}"
                        f"{str(r['pid']):<{_C['pid']}}"
                        f"{r['ip'][:_C['ip']-1]:<{_C['ip']}}"
                        f"{str(r['port']):<{_C['port']}}"
                        f"{r['state']:<{_C['state']}}"
                        f"{r['mb']:.2f}")
                if r["port_bad"] and not r["suspicious"]:
                    tag = "port_bad"
                elif r["suspicious"]:
                    vt = self._vt_ip_cache.get(r["ip"])
                    if (vt and not vt.get("pending") and "error" not in vt
                            and vt.get("malicious",0) == 0
                            and vt.get("harmless",0) > 0):
                        tag = "vt_safe"
                    else:
                        tag = "suspicious"
                else:
                    tag = "safe"
                w.insert("end", line+"\n", tag)
        w.config(state="disabled")
        self._ts_conns.config(
            text=f"conexiones: {time.strftime('%H:%M:%S')}", fg=DIM)
        if susp_count:
            self._susp_lbl.config(
                text=f"  {susp_count} IP sospechosa{'s' if susp_count>1 else ''}",
                fg=RED)
        else:
            self._susp_lbl.config(text="  Sin sospechosos", fg=GREEN_OK)

    # ── Firewall ────────────────────────────────────────────────────────────

    def _block_alert_procs(self):
        if not self._alert_procs:
            return
        blocked = []
        for proc_name in self._alert_procs:
            # Buscar PID activo
            pid = next((r["pid"] for r in self._last_rows
                        if r["proc"] == proc_name and r["pid"]), 0)
            ok, msg = self._apply_fw_block(proc_name, pid)
            if ok:
                blocked.append(proc_name)
        if blocked:
            self._dismiss_alert()
            self._update_fw_btn()

    def _apply_fw_block(self, proc_name: str, pid: int) -> tuple:
        rule = f"SysMon_{proc_name}_{int(time.time())}"
        exe  = ""
        try:
            exe = psutil.Process(pid).exe() if pid else ""
        except Exception:
            pass
        cmd = ["netsh","advfirewall","firewall","add","rule",
               f"name={rule}", "dir=out", "action=block", "enable=yes",
               "profile=any"]
        if exe:
            cmd.append(f"program={exe}")
        else:
            # Sin exe conocido: bloquear por nombre de programa si es posible
            return False, "No se pudo obtener ruta del ejecutable"
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            if r.returncode == 0:
                self._fw_blocks[rule] = {
                    "proc": proc_name, "exe": exe,
                    "time": time.strftime("%H:%M:%S")}
                return True, rule
            else:
                return False, r.stderr.strip()
        except Exception as e:
            return False, str(e)

    def _remove_fw_block(self, rule: str):
        try:
            subprocess.run(
                ["netsh","advfirewall","firewall","delete","rule",f"name={rule}"],
                capture_output=True, timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass
        self._fw_blocks.pop(rule, None)
        self._update_fw_btn()

    def _update_fw_btn(self):
        n = len(self._fw_blocks)
        col = PURPLE if n else DIM
        self._fw_btn.config(text=f"FW blocks: {n}", fg=col)

    def _open_fw_manager(self):
        try:
            if hasattr(self,"_fw_win") and self._fw_win.winfo_exists():
                self._fw_win.lift(); return
        except Exception:
            pass
        win = tk.Toplevel(self.root)
        win.title("Reglas de Firewall activas")
        win.geometry("620x380"); win.configure(bg=BG)
        self._fw_win = win

        tk.Label(win, text="Reglas de bloqueo creadas por System Monitor",
                 font=("Segoe UI",10,"bold"), bg=BG, fg=ACCENT).pack(pady=(14,8))

        def _refresh():
            for w in frame.winfo_children(): w.destroy()
            if not self._fw_blocks:
                tk.Label(frame, text="Sin reglas activas.",
                         font=("Segoe UI",9), bg=BG, fg=DIM).pack(pady=20)
                return
            hdr = tk.Frame(frame, bg=BG2)
            hdr.pack(fill="x", padx=8, pady=(0,2))
            for t, w in [("Proceso",18),("Hora",8),("Ejecutable",38)]:
                tk.Label(hdr, text=t, font=("Consolas",8,"bold"),
                         bg=BG2, fg=ACCENT, width=w, anchor="w").pack(side="left")
            for rule, info in list(self._fw_blocks.items()):
                row = tk.Frame(frame, bg=BG)
                row.pack(fill="x", padx=8, pady=1)
                tk.Label(row, text=info["proc"][:17], font=("Consolas",8),
                         bg=BG, fg=FG, width=18, anchor="w").pack(side="left")
                tk.Label(row, text=info["time"], font=("Consolas",8),
                         bg=BG, fg=DIM, width=8, anchor="w").pack(side="left")
                tk.Label(row, text=info["exe"][:36], font=("Consolas",8),
                         bg=BG, fg=DIM, width=38, anchor="w").pack(side="left")
                tk.Button(row, text="Quitar", font=("Segoe UI",7),
                          bg="#3a1212", fg=RED, relief="flat", bd=0,
                          padx=6, cursor="hand2",
                          command=lambda r=rule: [self._remove_fw_block(r),
                                                   _refresh()]).pack(side="right",padx=4)

        tk.Button(win, text="Eliminar todas", font=("Segoe UI",8),
                  bg="#3a1212", fg=RED, relief="flat", bd=0,
                  padx=10, pady=4, cursor="hand2",
                  command=lambda: [
                      [self._remove_fw_block(r) for r in list(self._fw_blocks)],
                      _refresh()]).pack(anchor="e", padx=16)

        frame = tk.Frame(win, bg=BG)
        frame.pack(fill="both", expand=True, padx=16, pady=8)
        _refresh()

    # ── Historial conexiones ─────────────────────────────────────────────────

    def _save_to_history(self, rows: list):
        if not self._db: return
        try:
            susp = [r for r in rows if r["suspicious"] or r["port_bad"]]
            if susp:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                for r in susp:
                    info = self._ip_info.get(r["ip"]) or {}
                    self._db.execute(
                        "INSERT INTO connections "
                        "(timestamp,proc,pid,ip,port,state,mb,suspicious,country,org) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (ts,r["proc"],r["pid"],r["ip"],r["port"],
                         r["state"],r["mb"],1,
                         info.get("country",""),info.get("org","")))
                self._db.commit()
                self._session_susp += len(susp)
        except Exception:
            pass

    def _open_history(self):
        try:
            if hasattr(self,"_hist_win") and self._hist_win.winfo_exists():
                self._hist_win.lift(); self._load_history(); return
        except Exception:
            pass
        win = tk.Toplevel(self.root)
        win.title("Historial de Conexiones Sospechosas")
        win.geometry("980x540"); win.configure(bg=BG); win.minsize(600,300)
        self._hist_win = win
        fb = tk.Frame(win, bg=BG)
        fb.pack(fill="x", padx=16, pady=(14,6))
        tk.Label(fb, text="Filtrar:", font=("Segoe UI",9), bg=BG, fg=FG).pack(side="left")
        self._hist_filter = tk.StringVar()
        self._hist_filter.trace_add("write", lambda *_: self._load_history())
        tk.Entry(fb, textvariable=self._hist_filter, font=("Consolas",9),
                 bg=BG2, fg=FG, insertbackground=FG,
                 relief="flat", width=28).pack(side="left", padx=8)
        tk.Button(fb, text="Actualizar", font=("Segoe UI",8),
                  bg=BG2, fg=ACCENT, relief="flat", cursor="hand2",
                  command=self._load_history).pack(side="left")
        tk.Button(fb, text="Exportar CSV", font=("Segoe UI",8),
                  bg=BG2, fg=GREEN_OK, relief="flat", cursor="hand2",
                  command=self._export_csv).pack(side="left", padx=6)
        tk.Button(fb, text="Limpiar", font=("Segoe UI",8),
                  bg="#3a1212", fg=RED, relief="flat", cursor="hand2",
                  command=self._clear_history).pack(side="right")
        tf = tk.Frame(win, bg=BG2)
        tf.pack(fill="both", expand=True, padx=16, pady=(0,14))
        ys = tk.Scrollbar(tf, orient="vertical", bg=BG, troughcolor=BG2)
        ys.pack(side="right", fill="y")
        self._hist_text = tk.Text(tf, font=("Consolas",9), bg=BG2, fg=FG,
                                   relief="flat", bd=0, state="disabled",
                                   yscrollcommand=ys.set, wrap="none")
        self._hist_text.pack(fill="both", expand=True, padx=4, pady=4)
        ys.config(command=self._hist_text.yview)
        self._hist_text.tag_configure("header", foreground=ACCENT)
        self._hist_text.tag_configure("row",    foreground=RED)
        self._hist_text.tag_configure("dim",    foreground=DIM)
        self._load_history()

    def _load_history(self):
        try:
            if not (hasattr(self,"_hist_text") and self._hist_win.winfo_exists()):
                return
        except Exception:
            return
        if not self._db: return
        try:
            flt = self._hist_filter.get().strip().lower()
            q = ("SELECT timestamp,proc,pid,ip,port,state,mb,country,org "
                 "FROM connections "
                 +("WHERE LOWER(proc) LIKE ? OR LOWER(ip) LIKE ? " if flt else "")
                 +"ORDER BY id DESC LIMIT 200")
            rows = self._db.execute(q, (f"%{flt}%",f"%{flt}%") if flt else ()).fetchall()
            w = self._hist_text
            w.config(state="normal"); w.delete("1.0","end")
            hdr = (f"{'Timestamp':<20}{'Proceso':<18}{'PID':<7}"
                   f"{'IP':<18}{'Puerto':<7}{'Estado':<14}{'MB':>7}"
                   f"  {'País':<5}  Org")
            w.insert("end", hdr+"\n", "header")
            w.insert("end", "-"*100+"\n", "dim")
            for ts,proc,pid,ip,port,state,mb,country,org in rows:
                line = (f"{str(ts):<20}{str(proc)[:17]:<18}{str(pid):<7}"
                        f"{str(ip):<18}{str(port):<7}{str(state):<14}"
                        f"{float(mb):>7.2f}  {str(country or ''):<5}  "
                        f"{str(org or '')[:28]}")
                w.insert("end", line+"\n", "row")
            if not rows: w.insert("end","  (sin registros)\n","dim")
            w.config(state="disabled")
        except Exception:
            pass

    def _export_csv(self):
        if not self._db: return
        try:
            path = filedialog.asksaveasfilename(
                parent=self._hist_win, defaultextension=".csv",
                filetypes=[("CSV","*.csv")], initialfile="monitor_history.csv")
            if not path: return
            rows = self._db.execute(
                "SELECT timestamp,proc,pid,ip,port,state,mb,country,org "
                "FROM connections ORDER BY id DESC LIMIT 5000").fetchall()
            with open(path,"w",newline="",encoding="utf-8-sig") as f:
                wr = csv.writer(f)
                wr.writerow(["timestamp","proc","pid","ip","port",
                             "state","mb","country","org"])
                wr.writerows(rows)
            messagebox.showinfo("Exportar CSV",
                                f"Exportado: {len(rows)} registros",
                                parent=self._hist_win)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self._hist_win)

    def _clear_history(self):
        if not self._db: return
        if not messagebox.askyesno("Limpiar","¿Borrar todo el historial?",
                                   parent=self._hist_win): return
        try:
            self._db.execute("DELETE FROM connections")
            self._db.commit(); self._session_susp = 0; self._load_history()
        except Exception:
            pass

    # ── Historial gráfico 24h ───────────────────────────────────────────────

    def _open_metrics_history(self):
        try:
            if hasattr(self,"_mhist_win") and self._mhist_win.winfo_exists():
                self._mhist_win.lift(); self._draw_metrics_history(); return
        except Exception:
            pass
        win = tk.Toplevel(self.root)
        win.title("Historial de Métricas — últimas 24h")
        win.geometry("860x640"); win.configure(bg=BG)
        self._mhist_win = win

        tk.Button(win, text="↺ Actualizar", font=("Segoe UI",9),
                  bg=BG2, fg=ACCENT, relief="flat", bd=0,
                  padx=10, pady=4, cursor="hand2",
                  command=self._draw_metrics_history).pack(anchor="e", padx=16, pady=8)

        scroll_frame = tk.Frame(win, bg=BG)
        scroll_frame.pack(fill="both", expand=True)
        ys = tk.Scrollbar(scroll_frame, orient="vertical", bg=BG, troughcolor=BG2)
        ys.pack(side="right", fill="y")
        self._mhist_canvas_scroll = tk.Canvas(
            scroll_frame, bg=BG, highlightthickness=0,
            yscrollcommand=ys.set)
        self._mhist_canvas_scroll.pack(side="left", fill="both", expand=True)
        ys.config(command=self._mhist_canvas_scroll.yview)

        self._mhist_inner = tk.Frame(self._mhist_canvas_scroll, bg=BG)
        _id = self._mhist_canvas_scroll.create_window(
            (0,0), window=self._mhist_inner, anchor="nw")
        self._mhist_inner.bind(
            "<Configure>",
            lambda e: self._mhist_canvas_scroll.configure(
                scrollregion=self._mhist_canvas_scroll.bbox("all")))
        self._mhist_canvas_scroll.bind(
            "<Configure>",
            lambda e: self._mhist_canvas_scroll.itemconfig(_id, width=e.width))
        self._mhist_canvas_scroll.bind_all(
            "<MouseWheel>",
            lambda e: self._mhist_canvas_scroll.yview_scroll(
                -1*(e.delta//120),"units"))

        self._draw_metrics_history()

    def _draw_metrics_history(self):
        if not hasattr(self,"_mhist_inner"): return
        if not self._db: return
        for w in self._mhist_inner.winfo_children(): w.destroy()

        try:
            rows = self._db.execute(
                "SELECT cpu,ram,net_sent,net_recv,disk_r,disk_w,cpu_temp "
                "FROM metrics_history ORDER BY id ASC").fetchall()
        except Exception:
            return
        if not rows: return

        metrics = [
            ("CPU %",      [r[0] for r in rows], 100, ACCENT),
            ("RAM %",      [r[1] for r in rows], 100, GREEN_OK),
            ("Red ↑ KB/s", [r[2]/1024 for r in rows], None, YELLOW),
            ("Red ↓ KB/s", [r[3]/1024 for r in rows], None, ORANGE),
            ("Disco R KB/s",[r[4]/1024 for r in rows], None, PURPLE),
            ("Temp CPU °C", [r[6] if r[6] and r[6]>=0 else 0
                             for r in rows], None, RED),
        ]
        for label, data, ymax, color in metrics:
            self._draw_mini_graph(self._mhist_inner, label, data, ymax, color)

    def _draw_mini_graph(self, parent, label: str, data: list,
                          ymax: float | None, color: str):
        fr = tk.Frame(parent, bg=BG)
        fr.pack(fill="x", padx=20, pady=(4,0))
        tk.Label(fr, text=label, font=("Segoe UI",8,"bold"),
                 bg=BG, fg=color).pack(anchor="w")
        c = tk.Canvas(fr, bg=BG2, height=80, highlightthickness=0)
        c.pack(fill="x", pady=(2,8))

        def _draw(event=None):
            c.delete("all")
            w = c.winfo_width(); h = c.winfo_height()
            if w < 10 or not data: return
            peak = ymax or max(max(data), 1)
            PX, PY = 4, 4; gh = h - PY*2
            # grid
            for frac in (0.25,0.5,0.75):
                gy = int(h-PY-frac*gh)
                c.create_line(PX,gy,w-PX,gy,fill="#2d2d2d",dash=(2,4))
                if frac == 0.5:
                    c.create_text(PX,gy,text=f"{peak*frac:.0f}",
                                  anchor="sw",fill=DIM,font=("Consolas",6))
            n = len(data)
            pts = []
            for i,v in enumerate(data):
                pts.extend([int(PX+i*(w-2*PX)/max(n-1,1)),
                             int(h-PY-(min(v,peak)/peak)*gh)])
            if len(pts) >= 4:
                c.create_line(*pts, fill=color, width=1.5, smooth=True)
            # peak label
            c.create_text(w-4,3,text=f"max {max(data):.1f}",
                          anchor="ne",fill=DIM,font=("Consolas",6))

        c.bind("<Configure>", _draw)
        c.update_idletasks()
        _draw()

    # ── Configuración ───────────────────────────────────────────────────────

    def _open_settings(self):
        try:
            if hasattr(self,"_cfg_win") and self._cfg_win.winfo_exists():
                self._cfg_win.lift(); return
        except Exception:
            pass
        win = tk.Toplevel(self.root)
        win.title("Configuración")
        win.geometry("440x380"); win.configure(bg=BG)
        win.resizable(False, False)
        self._cfg_win = win

        def _sep(text):
            tk.Frame(win, height=1, bg=DIM).pack(fill="x", padx=20, pady=(14,0))
            tk.Label(win, text=text, font=("Segoe UI",9,"bold"),
                     bg=BG, fg=ACCENT).pack(anchor="w", padx=20, pady=(4,0))

        def _row(parent, label, var, width=8):
            f = tk.Frame(parent, bg=BG)
            f.pack(fill="x", padx=24, pady=4)
            tk.Label(f, text=label, font=("Segoe UI",9),
                     bg=BG, fg=FG, width=22, anchor="w").pack(side="left")
            tk.Entry(f, textvariable=var, font=("Consolas",9),
                     bg=BG2, fg=FG, insertbackground=FG,
                     relief="flat", width=width).pack(side="left")

        # Umbrales
        _sep("Alertas de recursos")
        v_cpu  = tk.StringVar(value=str(int(self._cpu_thresh)))
        v_ram  = tk.StringVar(value=str(int(self._ram_thresh)))
        v_disk = tk.StringVar(value=str(int(self._disk_thresh)))
        _row(win, "Umbral CPU (%):",   v_cpu)
        _row(win, "Umbral RAM (%):",   v_ram)
        _row(win, "Umbral Disco (%):", v_disk)

        # API VirusTotal
        _sep("VirusTotal")
        v_vt = tk.StringVar(value=self._cfg.get("vt_api_key",""))
        _row(win, "API Key:", v_vt, width=36)

        # Auto-inicio
        _sep("Sistema")
        auto_var = tk.BooleanVar(value=self._is_autostart_enabled())
        f_auto = tk.Frame(win, bg=BG)
        f_auto.pack(fill="x", padx=24, pady=6)
        tk.Checkbutton(f_auto, text="Iniciar con Windows (Task Scheduler)",
                       variable=auto_var, font=("Segoe UI",9),
                       bg=BG, fg=FG, selectcolor=BG2,
                       activebackground=BG, relief="flat").pack(side="left")

        def _save():
            try:
                self._cpu_thresh  = max(1.0, min(100.0, float(v_cpu.get())))
                self._ram_thresh  = max(1.0, min(100.0, float(v_ram.get())))
                self._disk_thresh = max(1.0, min(100.0, float(v_disk.get())))
            except ValueError:
                pass
            self._cfg["cpu_thresh"]  = self._cpu_thresh
            self._cfg["ram_thresh"]  = self._ram_thresh
            self._cfg["disk_thresh"] = self._disk_thresh
            key = v_vt.get().strip()
            self._cfg["vt_api_key"] = key
            self._vt_key_btn.config(
                text="API VT " + ("✓" if key else "✗"),
                fg=GREEN_OK if key else DIM)
            _save_cfg(self._cfg)
            # Auto-inicio
            if auto_var.get(): self._enable_autostart()
            else:               self._disable_autostart()
            win.destroy()
            messagebox.showinfo("Config", "Configuración guardada.", parent=self.root)

        bbar = tk.Frame(win, bg=BG)
        bbar.pack(fill="x", padx=20, pady=16)
        tk.Button(bbar, text="Guardar", font=("Segoe UI",9,"bold"),
                  bg=ACCENT, fg=BG, activebackground="#38b2e0",
                  relief="flat", bd=0, padx=16, pady=6,
                  cursor="hand2", command=_save).pack(side="right")
        tk.Button(bbar, text="Cancelar", font=("Segoe UI",9),
                  bg=BG2, fg=DIM, relief="flat", bd=0,
                  padx=12, pady=6, cursor="hand2",
                  command=win.destroy).pack(side="right", padx=8)

    # ── Auto-inicio ─────────────────────────────────────────────────────────

    def _is_autostart_enabled(self) -> bool:
        try:
            r = subprocess.run(
                ["schtasks","/query","/tn",_TASK_NAME,"/fo","LIST"],
                capture_output=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW)
            return r.returncode == 0
        except Exception:
            return False

    def _enable_autostart(self):
        try:
            script = os.path.abspath(__file__)
            subprocess.run([
                "schtasks","/create","/tn",_TASK_NAME,
                "/tr", f'"{sys.executable}" "{script}"',
                "/sc","onlogon","/rl","HIGHEST","/f"
            ], capture_output=True, timeout=10,
               creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    def _disable_autostart(self):
        try:
            subprocess.run(
                ["schtasks","/delete","/tn",_TASK_NAME,"/f"],
                capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    # ── Alertas ─────────────────────────────────────────────────────────────

    def _check_alerts(self, rows: list):
        current = {r["proc"] for r in rows if r["suspicious"] or r["port_bad"]}
        self._known_suspicious &= current
        new_procs = current - self._known_suspicious
        if new_procs:
            self._known_suspicious |= new_procs
            self._trigger_alert(new_procs, rows)

    def _trigger_alert(self, new_procs: set, rows: list):
        self._alert_procs = new_procs.copy()
        details = [f"{r['proc']}  →  {r['ip']}:{r['port']}"
                   for r in rows if r["proc"] in new_procs]
        self._alert_lbl.config(
            text=f"⚠  PROCESO SOSPECHOSO:  {'   |   '.join(details[:3])}")
        self._alert_frame.place(x=0, y=0, relwidth=1.0, height=50)
        self._alert_frame.lift()
        if self._tray:
            self._tray.notify("⚠ Proceso sospechoso",
                              " | ".join(details[:2]), warning=True)
        try:    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            try: winsound.Beep(900,250)
            except Exception: pass
        self._flash_title(6)

    def _flash_title(self, remaining: int, warning: bool = True):
        if self._flash_job is not None:
            self.root.after_cancel(self._flash_job)
        if remaining <= 0:
            self.root.title("System Monitor  ⚠"); return
        self.root.title("⚠  ALERTA — PROCESO SOSPECHOSO  ⚠"
                        if warning else "System Monitor")
        self._flash_job = self.root.after(
            500, self._flash_title, remaining-1, not warning)

    def _dismiss_alert(self):
        self._alert_frame.place_forget()
        if self._flash_job is not None:
            self.root.after_cancel(self._flash_job)
            self._flash_job = None
        self.root.title("System Monitor")

    def _add_to_whitelist(self):
        if self._alert_procs:
            self._user_whitelist   |= self._alert_procs
            self._known_suspicious -= self._alert_procs
            self._alert_procs = set()
            self._cfg["whitelist"] = list(self._user_whitelist)
            _save_cfg(self._cfg)
            self._refresh_whitelist_display()
        self._dismiss_alert()

    def _remove_from_whitelist(self, name: str):
        self._user_whitelist.discard(name)
        self._cfg["whitelist"] = list(self._user_whitelist)
        _save_cfg(self._cfg)
        self._refresh_whitelist_display()

    def _refresh_whitelist_display(self):
        for w in self._wl_frame.winfo_children(): w.destroy()
        if not self._user_whitelist:
            tk.Label(self._wl_frame, text="(sin procesos agregados)",
                     font=("Segoe UI",8), bg=BG, fg=DIM).pack(side="left")
            return
        for name in sorted(self._user_whitelist):
            tag = tk.Frame(self._wl_frame, bg="#1a3a1a", padx=2, pady=1)
            tag.pack(side="left", padx=(0,6), pady=2)
            tk.Label(tag, text=name, font=("Consolas",8),
                     bg="#1a3a1a", fg=GREEN_OK).pack(side="left", padx=(6,2))
            tk.Button(tag, text="x", font=("Segoe UI",7,"bold"),
                      bg="#1a3a1a", fg=DIM,
                      activebackground="#2a4a2a", activeforeground=RED,
                      relief="flat", bd=0, cursor="hand2",
                      command=lambda n=name: self._remove_from_whitelist(n),
                      ).pack(side="left", padx=(0,4))

    # ── Copiar ──────────────────────────────────────────────────────────────

    def _copy_suspicious(self):
        ips = list(self._suspicious_ips); rows = list(self._suspicious_rows)
        if not ips:
            self._susp_lbl.config(text="  No hay IPs sospechosas", fg=DIM); return
        ok = _clipboard_set(self._build_report(ips, rows))
        self._susp_lbl.config(
            text=f"  {len(ips)} IP(s) copiadas" if ok else "  Error portapapeles",
            fg=GREEN_OK if ok else RED)

    @staticmethod
    def _build_report(ips: list, rows: list) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S"); sep="="*60; sep2="-"*60
        hdr = f"{'Proceso':<17}{'PID':<7}{'IP Remota':<18}{'Puerto':<8}{'Estado':<14}MB"
        lines = [sep,"  SYSTEM MONITOR - Conexiones Sospechosas",
                 f"  {ts}",sep,"",hdr,sep2]
        for r in rows:
            lines.append(f"{r['proc'][:16]:<17}{str(r['pid']):<7}{r['ip']:<18}"
                         f"{str(r['port']):<8}{r['state']:<14}{r['mb']:.2f}")
        lines += ["",sep2,"IPs para VirusTotal:",""]
        lines += [f"  {ip}" for ip in ips]
        lines += ["",sep]
        return "\n".join(lines)

    # ── Resolución hostname/ASN/país ─────────────────────────────────────────

    def _resolve_ip_async(self, ip: str):
        if ip in self._ip_info: return
        self._ip_info[ip] = {"host":"...","org":"...","country":"...","pending":True}
        fut = _executor.submit(self._bg_resolve_ip, ip)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_resolve_done, ip, f))

    @staticmethod
    def _bg_resolve_ip(ip: str) -> dict:
        res = {"host": ip, "org": "", "country": "", "lat": None, "lon": None}
        try:    res["host"] = socket.gethostbyaddr(ip)[0]
        except: pass
        try:
            req = urllib.request.Request(
                f"https://ipinfo.io/{ip}/json",
                headers={"User-Agent":"system-monitor/1.0"})
            with urllib.request.urlopen(req, timeout=6) as r:
                d = json.loads(r.read())
            res["org"]     = d.get("org","")
            res["country"] = d.get("country","")
            loc = d.get("loc","")
            if loc and "," in loc:
                la, lo = loc.split(",", 1)
                res["lat"] = float(la); res["lon"] = float(lo)
        except Exception:
            pass
        return res

    def _on_resolve_done(self, ip: str, future):
        try:    self._ip_info[ip] = {**future.result(), "pending":False}
        except: self._ip_info[ip] = {"host":ip,"org":"","country":"","pending":False}

    # ── VirusTotal ──────────────────────────────────────────────────────────

    def _prompt_vt_key(self):
        key = simpledialog.askstring(
            "VirusTotal API Key",
            "Ingresá tu API key de VirusTotal:",
            parent=self.root,
            initialvalue=self._cfg.get("vt_api_key",""))
        if key is None: return
        key = key.strip()
        self._cfg["vt_api_key"] = key; _save_cfg(self._cfg)
        self._vt_key_btn.config(
            text="API VT "+("✓" if key else "✗"),
            fg=GREEN_OK if key else DIM)

    def _enqueue_vt(self, kind: str, val: str, extra: str = ""):
        cache = self._vt_ip_cache if kind=="ip" else self._hash_vt_cache
        if val not in cache and not any(
                i[0]==kind and i[1]==val for i in self._vt_queue):
            self._vt_queue.append((kind,val,extra))

    def _tick_vt(self):
        try:   self._vt_drain()
        except: pass
        self.root.after(VT_INTERVAL, self._tick_vt)

    def _vt_drain(self):
        api_key = self._cfg.get("vt_api_key","").strip()
        if not api_key or not self._vt_queue: return
        if time.monotonic()-self._vt_day_t > 86_400:
            self._vt_daily = 0; self._vt_day_t = time.monotonic()
        if self._vt_daily >= 75: return
        kind, val, _ = self._vt_queue.pop(0)
        cache = self._vt_ip_cache if kind=="ip" else self._hash_vt_cache
        if val in cache and not cache[val].get("pending"): return
        cache[val] = {"pending":True}; self._vt_daily += 1
        fut = _executor.submit(self._bg_vt_lookup, kind, val, api_key)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_vt_done, kind, val, f))

    @staticmethod
    def _bg_vt_lookup(kind: str, val: str, api_key: str) -> dict:
        ep  = "ip_addresses" if kind=="ip" else "files"
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/{ep}/{val}",
            headers={"x-apikey":api_key,"User-Agent":"system-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=12) as r:
            d = json.loads(r.read())
        s = d["data"]["attributes"]["last_analysis_stats"]
        return {k:s.get(k,0) for k in ("malicious","suspicious","harmless","undetected")}

    def _on_vt_done(self, kind: str, val: str, future):
        cache = self._vt_ip_cache if kind=="ip" else self._hash_vt_cache
        try:    cache[val] = future.result()
        except Exception as e: cache[val] = {"error":str(e)[:60]}
        if self._last_rows:
            self._render_conns(self._last_rows, len(self._suspicious_ips))

    # ── Firma digital ────────────────────────────────────────────────────────

    def _check_sig_async(self, exe: str):
        if exe in self._sig_cache: return
        self._sig_cache[exe] = {"pending":True,"signed":None,"publisher":""}
        fut = _executor.submit(self._bg_check_sig, exe)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_sig_done, exe, f))

    @staticmethod
    def _bg_check_sig(exe: str) -> dict:
        try:
            r = subprocess.run(
                ["sigcheck.exe","-nobanner","-accepteula","-q",exe],
                capture_output=True, text=True, timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW)
            out = r.stdout+r.stderr
            if "Verified:" in out:
                signed = "Unsigned" not in out; pub = ""
                for l in out.splitlines():
                    if l.strip().startswith("Publisher:"):
                        pub=l.split(":",1)[1].strip(); break
                return {"signed":signed,"publisher":pub}
        except FileNotFoundError: pass
        except Exception: pass
        try:
            esc = exe.replace("'","''")
            ps  = (f"$s=(Get-AuthenticodeSignature '{esc}');"
                   "$s.Status.ToString()+'|'+"
                   "($s.SignerCertificate.Subject -replace '.*CN=([^,]+).*','$1')")
            r = subprocess.run(
                ["powershell","-NoProfile","-Command",ps],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW)
            out = r.stdout.strip()
            if "|" in out:
                status,pub = out.split("|",1)
                return {"signed":status.strip()=="Valid","publisher":pub.strip()}
        except Exception: pass
        return {"signed":None,"publisher":""}

    def _on_sig_done(self, exe: str, future):
        try:    self._sig_cache[exe] = {**future.result(),"pending":False}
        except: self._sig_cache[exe] = {"signed":None,"publisher":"","pending":False}

    def _get_sig_line(self, pid: int) -> str:
        try:    exe = psutil.Process(pid).exe()
        except: return "Firma: N/A"
        c = self._sig_cache.get(exe)
        if c is None: self._check_sig_async(exe); return "Firma: verificando..."
        if c.get("pending"): return "Firma: verificando..."
        s=c.get("signed"); pub=c.get("publisher","")
        if s is True:  return f"Firma: OK  {pub}" if pub else "Firma: firmado"
        if s is False: return "Firma: NO firmado ⚠"
        return "Firma: no verificado"

    # ── Hash SHA-256 + VT ────────────────────────────────────────────────────

    def _enqueue_hash_check(self, pid: int):
        if pid in self._exe_hash:
            h = self._exe_hash[pid]
            if h: self._enqueue_vt("hash",h)
            return
        self._exe_hash[pid] = None
        fut = _executor.submit(self._bg_compute_hash, pid)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_hash_done, pid, f))

    @staticmethod
    def _bg_compute_hash(pid: int) -> str:
        try:
            exe = psutil.Process(pid).exe()
            sha = hashlib.sha256()
            with open(exe,"rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): sha.update(chunk)
            return sha.hexdigest()
        except Exception:
            return ""

    def _on_hash_done(self, pid: int, future):
        try:
            h = future.result(); self._exe_hash[pid] = h
            if h: self._enqueue_vt("hash",h)
        except: self._exe_hash[pid] = ""

    def _get_hash_vt_line(self, pid: int) -> str:
        h = self._exe_hash.get(pid)
        if h is None: return "Hash VT: calculando..."
        if not h:     return "Hash VT: no disponible"
        vt = self._hash_vt_cache.get(h)
        if vt is None:          return f"Hash: {h[:16]}...  VT: pendiente"
        if vt.get("pending"):   return f"Hash: {h[:16]}...  VT: consultando..."
        if "error" in vt:       return f"Hash: {h[:16]}...  VT: error"
        m=vt.get("malicious",0); ok=vt.get("harmless",0)
        col_hint = " ⚠" if m>0 else " ✓"
        return f"Hash: {h[:16]}...  VT: {m} mal / {ok} ok{col_hint}"

    # ── Tooltip ──────────────────────────────────────────────────────────────

    def _on_conn_motion(self, event):
        try:
            idx = self._conn_text.index(f"@{event.x},{event.y}")
            row_idx = int(idx.split(".")[0]) - 3
            if 0 <= row_idx < len(self._last_rows):
                self._show_tooltip(event, self._last_rows[row_idx])
            else:
                self._hide_tooltip()
        except Exception:
            self._hide_tooltip()

    def _on_conn_leave(self, _e): self._hide_tooltip()

    def _show_tooltip(self, event, row: dict):
        ip = row["ip"]; pid = row["pid"]
        info = self._ip_info.get(ip) or {}
        host    = info.get("host","resolviendo...")
        org     = info.get("org","...")
        country = info.get("country","...")
        vt = self._vt_ip_cache.get(ip)
        if vt is None:           vt_l = "VT IP: sin consultar"
        elif vt.get("pending"):  vt_l = "VT IP: consultando..."
        elif "error" in vt:      vt_l = f"VT IP: error — {vt['error']}"
        else:
            m=vt.get("malicious",0); h=vt.get("harmless",0); u=vt.get("undetected",0)
            vt_l = f"VT IP: {m} mal / {h} ok / {u} undet"
        lines = [
            f"IP:      {ip}" + ("  ⚠ PUERTO MALICIOSO" if row.get("port_bad") else ""),
            f"País:    {country}",
            f"Host:    {host}",
            f"Org:     {org}",
            vt_l,
            self._get_hash_vt_line(pid),
            self._get_sig_line(pid),
            f"Padre:   {row.get('parent','N/A')}",
            f"Usuario: {row.get('user','N/A')}" +
            ("  [SYSTEM]" if row.get("elevated") else ""),
            self._get_uptime_line(pid),
        ]
        try:
            if self._tooltip_win is None or not self._tooltip_win.winfo_exists():
                self._tooltip_win = tk.Toplevel(self.root)
                self._tooltip_win.wm_overrideredirect(True)
                self._tooltip_win.wm_attributes("-topmost",True)
                self._tooltip_lbl = tk.Label(
                    self._tooltip_win, font=("Consolas",8),
                    bg="#2a2a2a", fg=FG, relief="flat", bd=0,
                    padx=10, pady=7, justify="left", anchor="w")
                self._tooltip_lbl.pack()
            self._tooltip_lbl.config(text="\n".join(lines))
            self._tooltip_win.geometry(
                f"+{event.x_root+16}+{event.y_root+10}")
            self._tooltip_win.lift()
        except Exception:
            self._tooltip_win = None

    def _hide_tooltip(self):
        try:
            if self._tooltip_win is not None:
                self._tooltip_win.destroy(); self._tooltip_win = None
        except Exception:
            self._tooltip_win = None

    # ── Uptime proceso ───────────────────────────────────────────────────────

    @staticmethod
    def _get_uptime_line(pid: int) -> str:
        try:
            ct = psutil.Process(pid).create_time()
            up = int(time.time() - ct)
            if up < 3600:   s = f"{up//60}m {up%60}s"
            elif up < 86400: s = f"{up//3600}h {(up%3600)//60}m"
            else:            s = f"{up//86400}d {(up%86400)//3600}h"
            return f"Uptime:  {s}"
        except Exception:
            return "Uptime:  N/A"

    # ── Event Log Windows ────────────────────────────────────────────────────

    def _tick_evtlog(self):
        fut = _executor.submit(self._bg_evtlog)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_evtlog_done, f))
        self.root.after(EVTLOG_INTERVAL, self._tick_evtlog)

    @staticmethod
    def _bg_evtlog() -> list:
        ids_str = ",".join(str(i) for i in _EVTLOG_IDS)
        ps_cmd = (
            f"$ids=@({ids_str});"
            "Get-WinEvent -FilterHashtable @{LogName='Security','System';"
            f"Id=$ids}} -MaxEvents 30 -ErrorAction SilentlyContinue"
            " | Select-Object Id,TimeCreated,"
            "@{N='Msg';E={$_.Message.Substring(0,[Math]::Min(180,$_.Message.Length))}}"
            " | ForEach-Object { $_.Id.ToString()+'|'+$_.TimeCreated.ToString('s')+'|'+$_.Msg }"
        )
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=12,
                creationflags=subprocess.CREATE_NO_WINDOW)
            events = []
            for line in r.stdout.splitlines():
                parts = line.split("|", 2)
                if len(parts) == 3:
                    eid, ts, msg = parts
                    events.append({"id": eid.strip(), "ts": ts.strip(),
                                   "msg": msg.strip()[:160]})
            return events
        except Exception:
            return []

    def _on_evtlog_done(self, future):
        try:
            events = future.result()
            if not events: return
            prev_ts = {e["ts"] for e in self._evtlog_events}
            new = [e for e in events if e["ts"] not in prev_ts]
            self._evtlog_events = events
            if new:
                self._evtlog_new.extend(new)
                label_map = {
                    "4625":"Logon fallido","4720":"Usuario creado",
                    "4728":"Grupo modificado","4732":"Grupo modificado",
                    "7045":"Servicio instalado","1102":"Log borrado","4719":"Auditoria cambiada"
                }
                for e in new[:2]:
                    lbl = label_map.get(e["id"], f"Evento {e['id']}")
                    if self._tray:
                        self._tray.notify(f"⚠ {lbl}", e["msg"][:100], warning=True)
                if hasattr(self,"_evtlog_btn"):
                    self._evtlog_btn.config(fg=RED,
                                            text=f"🔍 Eventos ({len(self._evtlog_new)} nuevos)")
        except Exception:
            pass

    def _open_evtlog(self):
        self._evtlog_new.clear()
        if hasattr(self,"_evtlog_btn"):
            self._evtlog_btn.config(fg=DIM, text="🔍 Eventos")
        try:
            if hasattr(self,"_evtlog_win") and self._evtlog_win.winfo_exists():
                self._evtlog_win.lift(); self._refresh_evtlog(); return
        except Exception: pass
        win = tk.Toplevel(self.root)
        win.title("Event Log — Eventos de Seguridad")
        win.geometry("900x480"); win.configure(bg=BG)
        self._evtlog_win = win
        tk.Label(win, text="Event Log  (Security + System)",
                 font=("Segoe UI",10,"bold"), bg=BG, fg=ACCENT).pack(pady=(12,4))
        tk.Button(win, text="↺ Actualizar", font=("Segoe UI",8),
                  bg=BG2, fg=ACCENT, relief="flat", bd=0, padx=8,
                  cursor="hand2", command=self._refresh_evtlog).pack(anchor="e", padx=16)
        tf = tk.Frame(win, bg=BG2)
        tf.pack(fill="both", expand=True, padx=16, pady=(0,14))
        ys = tk.Scrollbar(tf, orient="vertical", bg=BG, troughcolor=BG2)
        ys.pack(side="right", fill="y")
        self._evtlog_text = tk.Text(tf, font=("Consolas",8), bg=BG2, fg=FG,
                                    relief="flat", bd=0, state="disabled",
                                    yscrollcommand=ys.set, wrap="none")
        self._evtlog_text.pack(fill="both", expand=True, padx=4, pady=4)
        ys.config(command=self._evtlog_text.yview)
        for tag, col in [("header",ACCENT),("warn",ORANGE),("crit",RED),("dim",DIM)]:
            self._evtlog_text.tag_configure(tag, foreground=col)
        self._refresh_evtlog()

    def _refresh_evtlog(self):
        try:
            if not (hasattr(self,"_evtlog_text") and self._evtlog_win.winfo_exists()): return
        except Exception: return
        w = self._evtlog_text
        w.config(state="normal"); w.delete("1.0","end")
        crit_ids = {"7045","1102","4720","4719"}
        hdr = f"{'ID':<6}{'Timestamp':<22}Mensaje"
        w.insert("end", hdr+"\n", "header")
        w.insert("end", "-"*90+"\n", "dim")
        if not self._evtlog_events:
            w.insert("end","  (sin eventos — requiere permisos de Admin)\n","dim")
        for e in self._evtlog_events:
            line = f"{e['id']:<6}{e['ts']:<22}{e['msg'][:60]}"
            tag = "crit" if e["id"] in crit_ids else "warn"
            w.insert("end", line+"\n", tag)
        w.config(state="disabled")

    # ── DLL injection detection ──────────────────────────────────────────────

    def _tick_dll(self):
        susp_pids = [r["pid"] for r in self._last_rows
                     if r.get("suspicious") and r.get("pid")]
        if susp_pids:
            fut = _executor.submit(self._bg_scan_dlls, susp_pids)
            fut.add_done_callback(
                lambda f: self.root.after(0, self._on_dll_done, f))
        self.root.after(DLL_INTERVAL, self._tick_dll)

    @staticmethod
    def _bg_scan_dlls(pids: list) -> list:
        findings = []
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                exe_dir = os.path.dirname(proc.exe()).lower()
                for m in proc.memory_maps():
                    path = m.path.lower() if hasattr(m,"path") else ""
                    if not path.endswith(".dll"): continue
                    safe = any(path.startswith(d) for d in _SAFE_DLL_DIRS)
                    if not safe and not path.startswith(exe_dir):
                        findings.append({
                            "pid": pid, "proc": proc.name(),
                            "dll": m.path[:80]})
            except Exception:
                pass
        return findings

    def _on_dll_done(self, future):
        try:
            findings = future.result()
            if findings:
                procs = {f["proc"] for f in findings}
                if self._tray:
                    self._tray.notify("⚠ DLL sospechosa detectada",
                                      ", ".join(list(procs)[:3]), warning=True)
        except Exception:
            pass

    # ── Monitor de servicios ─────────────────────────────────────────────────

    def _tick_services(self):
        fut = _executor.submit(self._bg_scan_services)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_services_done, f))
        self.root.after(SVC_INTERVAL, self._tick_services)

    @staticmethod
    def _bg_scan_services() -> set:
        try:
            r = subprocess.run(
                ["sc","query","state=","all"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW)
            svcs = set()
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("SERVICE_NAME:"):
                    svcs.add(line.split(":",1)[1].strip())
            return svcs
        except Exception:
            return set()

    def _on_services_done(self, future):
        try:
            current = future.result()
            if self._known_services is None:
                self._known_services = current; return
            new = current - self._known_services
            if new:
                self._known_services = current
                if self._tray:
                    self._tray.notify("⚠ Nuevo servicio detectado",
                                      ", ".join(list(new)[:3]), warning=True)
                self._susp_lbl.config(
                    text=f"  Nuevo servicio: {', '.join(list(new)[:2])}",
                    fg=ORANGE)
        except Exception:
            pass

    # ── Integridad de hosts file ─────────────────────────────────────────────

    def _tick_hosts(self):
        fut = _executor.submit(self._bg_hash_hosts)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_hosts_done, f))
        self.root.after(HOSTS_INTERVAL, self._tick_hosts)

    @staticmethod
    def _bg_hash_hosts() -> str:
        try:
            with open(_HOSTS_PATH, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""

    def _on_hosts_done(self, future):
        try:
            h = future.result()
            if not h: return
            if not self._hosts_hash:
                self._hosts_hash = h; return
            if h != self._hosts_hash:
                self._hosts_hash = h
                if self._tray:
                    self._tray.notify("⚠ Hosts file modificado",
                                      _HOSTS_PATH, warning=True)
                self._susp_lbl.config(text="  ⚠ hosts file cambiado!", fg=RED)
        except Exception:
            pass

    # ── DNS sospechoso ───────────────────────────────────────────────────────

    def _tick_dns(self):
        fut = _executor.submit(self._bg_scan_dns)
        fut.add_done_callback(
            lambda f: self.root.after(0, self._on_dns_done, f))
        self.root.after(DNS_INTERVAL, self._tick_dns)

    @staticmethod
    def _bg_scan_dns() -> list:
        _BAD_TLD = {".ru",".cn",".tk",".xyz",".top",".pw",".cc",".su"}
        _KEYWORDS = {"payload","c2","shell","bot","rat","malware","exploit","cmd"}
        suspicious = []
        try:
            r = subprocess.run(
                ["ipconfig","/displaydns"],
                capture_output=True, text=True, timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW)
            for line in r.stdout.splitlines():
                if "Nombre de registro" in line or "Record Name" in line:
                    domain = line.split(":",1)[-1].strip().lower().rstrip(".")
                    bad = (any(domain.endswith(t) for t in _BAD_TLD)
                           or any(k in domain for k in _KEYWORDS))
                    if bad:
                        suspicious.append(domain)
        except Exception:
            pass
        return list(dict.fromkeys(suspicious))

    def _on_dns_done(self, future):
        try:
            found = future.result()
            new = [d for d in found if d not in self._dns_suspicious]
            if new:
                self._dns_suspicious.extend(new)
                if self._tray:
                    self._tray.notify("⚠ DNS sospechoso",
                                      ", ".join(new[:3]), warning=True)
        except Exception:
            pass

    # ── Mapa geográfico ──────────────────────────────────────────────────────

    # Continentes simplificados (lon, lat)
    _CONTINENTS = [
        [(-168,70),(-140,60),(-125,50),(-120,35),(-110,22),(-85,15),(-75,8),
         (-60,6),(-52,56),(-55,68),(-80,80),(-168,70)],
        [(-80,12),(-60,15),(-35,0),(-35,-35),(-65,-55),(-75,-45),(-80,-20),(-80,12)],
        [(-10,36),(30,36),(35,47),(30,72),(-10,60),(-10,36)],
        [(-17,14),(-18,4),(0,-4),(35,-35),(50,-30),(50,12),(40,15),(11,38),(-5,36),(-17,14)],
        [(30,72),(55,27),(75,15),(100,10),(120,10),(140,40),(148,50),(135,72),(30,72)],
        [(115,-22),(140,-15),(150,-22),(150,-40),(140,-40),(115,-35),(115,-22)],
    ]

    def _open_geo_map(self):
        try:
            if hasattr(self,"_geo_win") and self._geo_win.winfo_exists():
                self._geo_win.lift(); self._redraw_geo(); return
        except Exception: pass
        win = tk.Toplevel(self.root)
        win.title("Mapa Geográfico de Conexiones")
        win.geometry("820x440"); win.configure(bg=BG)
        self._geo_win = win
        tk.Label(win, text="Mapa de Conexiones Activas (posición aproximada)",
                 font=("Segoe UI",9,"bold"), bg=BG, fg=ACCENT).pack(pady=(10,4))
        tk.Button(win, text="↺ Actualizar", font=("Segoe UI",8),
                  bg=BG2, fg=ACCENT, relief="flat", bd=0, padx=8, cursor="hand2",
                  command=self._redraw_geo).pack(anchor="e", padx=16)
        self._geo_canvas = tk.Canvas(win, bg="#0d1b2a", highlightthickness=0)
        self._geo_canvas.pack(fill="both", expand=True, padx=16, pady=(0,10))
        self._geo_canvas.bind("<Configure>", lambda e: self._redraw_geo())
        win.after(200, self._redraw_geo)

    def _redraw_geo(self):
        if not hasattr(self,"_geo_canvas"): return
        try:
            if not self._geo_win.winfo_exists(): return
        except Exception: return
        c = self._geo_canvas; c.delete("all")
        W = c.winfo_width(); H = c.winfo_height()
        if W < 10 or H < 10: return

        def _proj(lon, lat):
            x = int((lon + 180) / 360 * W)
            y = int((90 - lat) / 180 * H)
            return x, y

        # Grid lat/lon
        for lat in range(-60, 90, 30):
            y = int((90-lat)/180*H)
            c.create_line(0,y,W,y,fill="#112233",dash=(2,6))
        for lon in range(-180,181,60):
            x = int((lon+180)/360*W)
            c.create_line(x,0,x,H,fill="#112233",dash=(2,6))
            c.create_text(x+2,H-8,text=f"{lon}°",fill="#224",font=("Consolas",6),anchor="w")

        # Continentes
        for cont in self._CONTINENTS:
            pts = []
            for lon,lat in cont:
                pts.extend(_proj(lon,lat))
            if len(pts) >= 6:
                c.create_polygon(*pts, fill="#1a3a2a", outline="#2d5a3d", width=1)

        # IPs conocidas
        now_ips = {r["ip"] for r in self._last_rows}
        for ip, info in self._ip_info.items():
            lat = info.get("lat"); lon = info.get("lon")
            if lat is None or lon is None: continue
            x, y = _proj(lon, lat)
            susp = ip in {r["ip"] for r in self._last_rows if r.get("suspicious")}
            col = RED if susp else (YELLOW if ip in now_ips else GREEN_OK)
            r = 5 if ip in now_ips else 3
            c.create_oval(x-r,y-r,x+r,y+r, fill=col, outline="", tags="ip")
            cname = info.get("country","")
            c.create_text(x+6,y, text=f"{ip[:15]} {cname}",
                          fill=col, font=("Consolas",6), anchor="w")

        # Leyenda
        for sym, col, lbl in [(RED,"■","Sospechoso"),(YELLOW,"■","Conectado"),(GREEN_OK,"■","Conocido")]:
            pass
        c.create_text(8,8, text="■ Sospechoso", fill=RED, font=("Consolas",7), anchor="nw")
        c.create_text(8,18, text="■ Activo",     fill=YELLOW, font=("Consolas",7), anchor="nw")
        c.create_text(8,28, text="■ Conocido",   fill=GREEN_OK, font=("Consolas",7), anchor="nw")

    # ── Reporte HTML ─────────────────────────────────────────────────────────

    def _export_html(self):
        path = filedialog.asksaveasfilename(
            parent=self.root, defaultextension=".html",
            filetypes=[("HTML","*.html")], initialfile="monitor_report.html")
        if not path: return
        try:
            html = self._build_html_report()
            with open(path,"w",encoding="utf-8") as f: f.write(html)
            messagebox.showinfo("Reporte HTML", f"Guardado en:\n{path}", parent=self.root)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root)

    def _build_html_report(self) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        css = """body{background:#1e1e1e;color:#fff;font-family:Consolas,monospace;padding:20px}
h2{color:#4fc3f7}h3{color:#4ade80}table{border-collapse:collapse;width:100%;margin-bottom:20px}
th{background:#252526;color:#4fc3f7;padding:6px 10px;text-align:left}
td{padding:5px 10px;border-bottom:1px solid #333}
tr.susp td{color:#ef4444}.ok{color:#4ade80}.warn{color:#facc15}.crit{color:#ef4444}
.dim{color:#888}.badge{display:inline-block;padding:2px 8px;border-radius:3px;
font-size:11px;background:#252526}"""
        rows_html = ""
        for r in self._last_rows:
            cls = "susp" if (r.get("suspicious") or r.get("port_bad")) else ""
            info = self._ip_info.get(r["ip"]) or {}
            vt = self._vt_ip_cache.get(r["ip"])
            vt_s = "—"
            if vt and not vt.get("pending") and "error" not in vt:
                m = vt.get("malicious",0)
                vt_s = f'<span class="{"crit" if m else "ok"}">{m} mal</span>'
            rows_html += (f'<tr class="{cls}"><td>{r["proc"]}</td><td>{r["pid"]}</td>'
                          f'<td>{r["ip"]}</td><td>{r["port"]}</td><td>{r["state"]}</td>'
                          f'<td>{info.get("country","")}</td><td>{info.get("org","")[:30]}</td>'
                          f'<td>{vt_s}</td></tr>\n')
        fw_html = ""
        for rule, info in self._fw_blocks.items():
            fw_html += f'<tr><td>{info["proc"]}</td><td>{info["exe"][:60]}</td><td>{info["time"]}</td></tr>\n'
        evtlog_html = ""
        label_map = {"4625":"Logon fallido","4720":"Usuario creado","7045":"Servicio instalado",
                     "1102":"Log borrado","4719":"Auditoría cambiada"}
        for e in self._evtlog_events[:30]:
            lbl = label_map.get(e["id"],f"ID {e['id']}")
            cls = "crit" if e["id"] in {"7045","1102","4720","4719"} else "warn"
            evtlog_html += (f'<tr><td class="{cls}">{e["id"]}</td>'
                            f'<td class="{cls}">{lbl}</td>'
                            f'<td>{e["ts"]}</td><td>{e["msg"][:80]}</td></tr>\n')
        history_html = ""
        if self._db:
            try:
                hist_rows = self._db.execute(
                    "SELECT timestamp,proc,ip,port,state,country FROM connections "
                    "ORDER BY id DESC LIMIT 50").fetchall()
                for ts2,proc,ip,port,state,country in hist_rows:
                    history_html += (f'<tr class="susp"><td>{ts2}</td><td>{proc}</td>'
                                     f'<td>{ip}</td><td>{port}</td><td>{state}</td>'
                                     f'<td>{country or ""}</td></tr>\n')
            except Exception: pass
        gpu_s = "N/D"
        if self._gpu_info:
            if self._gpu_info.get("vendor")=="NVIDIA":
                gpu_s = (f"{self._gpu_info['name']}  {self._gpu_info['util']:.0f}%  "
                         f"{self._gpu_info['mem_used']:.0f}/{self._gpu_info['mem_total']:.0f}MB  "
                         f"{self._gpu_info['temp']:.0f}°C")
            else:
                gpu_s = f"{self._gpu_info.get('name','')}  {self._gpu_info.get('vram_mb',0)} MB"
        temp_s = f"{self._cpu_temp:.1f} °C" if self._cpu_temp >= 0 else "N/D"
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>System Monitor — Reporte {ts}</title>
<style>{css}</style></head><body>
<h2>System Monitor — Reporte de Seguridad</h2>
<p class="dim">Generado: {ts}</p>
<h3>Estado del sistema</h3>
<table><tr><th>Métrica</th><th>Valor</th></tr>
<tr><td>CPU</td><td>{self._last_cpu:.1f}%</td></tr>
<tr><td>RAM</td><td>{self._last_ram:.1f}%</td></tr>
<tr><td>GPU</td><td>{gpu_s}</td></tr>
<tr><td>Temp CPU</td><td>{temp_s}</td></tr>
<tr><td>Red ↑</td><td>{_fmt_bytes(self._last_sent)}/s</td></tr>
<tr><td>Red ↓</td><td>{_fmt_bytes(self._last_recv)}/s</td></tr>
<tr><td>Conexiones sospechosas (sesión)</td><td class="crit">{self._session_susp}</td></tr>
<tr><td>Reglas FW activas</td><td>{len(self._fw_blocks)}</td></tr>
</table>
<h3>Conexiones activas</h3>
<table><tr><th>Proceso</th><th>PID</th><th>IP</th><th>Puerto</th>
<th>Estado</th><th>País</th><th>Org</th><th>VirusTotal</th></tr>
{rows_html}</table>
<h3>Reglas de Firewall (System Monitor)</h3>
<table><tr><th>Proceso</th><th>Ejecutable</th><th>Hora</th></tr>
{fw_html if fw_html else '<tr><td colspan="3" class="dim">Sin reglas activas</td></tr>'}</table>
<h3>Event Log reciente</h3>
<table><tr><th>ID</th><th>Evento</th><th>Timestamp</th><th>Detalle</th></tr>
{evtlog_html if evtlog_html else '<tr><td colspan="4" class="dim">Sin eventos</td></tr>'}</table>
<h3>Historial de conexiones sospechosas (últimas 50)</h3>
<table><tr><th>Timestamp</th><th>Proceso</th><th>IP</th>
<th>Puerto</th><th>Estado</th><th>País</th></tr>
{history_html if history_html else '<tr><td colspan="6" class="dim">Sin registros</td></tr>'}</table>
<h3>Whitelist personalizada</h3>
<p>{', '.join(sorted(self._user_whitelist)) or '(vacía)'}</p>
</body></html>"""

    # ── Modo compacto ─────────────────────────────────────────────────────────

    def _open_compact(self):
        try:
            if self._compact_win and self._compact_win.winfo_exists():
                self._compact_win.destroy(); self._compact_win = None; return
        except Exception: pass
        win = tk.Toplevel(self.root)
        win.wm_overrideredirect(True)
        win.wm_attributes("-topmost", True)
        win.geometry("280x100+40+40")
        win.configure(bg="#111111")
        self._compact_win = win

        # Drag
        self._cwin_dx = self._cwin_dy = 0
        def _start_drag(e): self._cwin_dx=e.x; self._cwin_dy=e.y
        def _do_drag(e):
            x = win.winfo_x()+e.x-self._cwin_dx
            y = win.winfo_y()+e.y-self._cwin_dy
            win.geometry(f"+{x}+{y}")
        win.bind("<ButtonPress-1>",  _start_drag)
        win.bind("<B1-Motion>",      _do_drag)

        # Close button
        tk.Button(win, text="✕", font=("Segoe UI",7), bg="#111", fg=DIM,
                  relief="flat", bd=0, cursor="hand2",
                  command=lambda: [win.destroy(),
                                   setattr(self,"_compact_win",None)]
                  ).place(relx=1.0, x=-4, y=2, anchor="ne")

        tk.Label(win, text="System Monitor", font=("Segoe UI",7,"bold"),
                 bg="#111", fg=DIM).pack(pady=(4,2))

        row_f = tk.Frame(win, bg="#111")
        row_f.pack(fill="x", padx=8)
        self._compact_labels = {}
        for key, lbl, col in [("cpu","CPU",ACCENT),("ram","RAM",GREEN_OK),
                               ("net","Red",YELLOW),("thr","Amenazas",RED)]:
            f = tk.Frame(row_f, bg="#1a1a1a", padx=6, pady=4)
            f.pack(side="left", expand=True, fill="both", padx=2)
            tk.Label(f, text=lbl, font=("Segoe UI",7), bg="#1a1a1a", fg=DIM).pack()
            v = tk.Label(f, text="...", font=("Consolas",9,"bold"), bg="#1a1a1a", fg=col)
            v.pack()
            self._compact_labels[key] = v

        self._tick_compact()

    def _tick_compact(self):
        try:
            if not self._compact_win or not self._compact_win.winfo_exists(): return
            cl = self._compact_labels
            cpu = self._last_cpu; ram = self._last_ram
            cl["cpu"].config(text=f"{cpu:.0f}%",
                             fg=RED if cpu>=self._cpu_thresh else ACCENT)
            cl["ram"].config(text=f"{ram:.0f}%",
                             fg=RED if ram>=self._ram_thresh else GREEN_OK)
            net = self._last_sent + self._last_recv
            cl["net"].config(text=_fmt_bytes(net)+"/s")
            cl["thr"].config(text=str(self._session_susp),
                             fg=RED if self._session_susp else DIM)
            self._compact_win.after(2000, self._tick_compact)
        except Exception:
            pass


# ─── Entrada ───────────────────────────────────────────────────────────────

def main():
    try:
        root = tk.Tk()
        Monitor(root)
        root.mainloop()
    except Exception as e:
        try:    messagebox.showerror("System Monitor — Error fatal", str(e))
        except: pass
        raise


if __name__ == "__main__":
    main()
