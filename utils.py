"""Shared constants and pure helper functions."""
import ctypes
import ctypes.wintypes
import ipaddress
import json
import os
import psutil

BASE     = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(BASE, "config.json")
DB_PATH  = os.path.join(BASE, "monitor_history.db")

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"

SAFE_DLL_DIRS = (
    "c:\\windows\\system32", "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",   "c:\\program files",
    "c:\\program files (x86)", "c:\\windows\\",
)

EVTLOG_IDS = {4625, 4720, 4728, 4732, 7045, 1102, 4719}

SUSPICIOUS_PORTS = frozenset({
    4444, 1337, 31337, 8888, 9001, 9050,
    1234, 5555, 6666, 7777, 6667, 6668,
})

WHITELIST = frozenset({
    "chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe",
    "explorer.exe", "OneDrive.exe", "discord.exe", "steam.exe",
    "pythonw.exe", "Code.exe",
})


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def clipboard_set(text: str) -> bool:
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


def fmt_bytes(bps: float) -> str:
    if bps < 1_024:     return f"{bps:.0f} B"
    if bps < 1_048_576: return f"{bps/1_024:.1f} KB"
    return f"{bps/1_048_576:.2f} MB"


def is_external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_loopback or a.is_private
                    or a.is_link_local or a.is_unspecified)
    except ValueError:
        return False


def proc_name(pid: int) -> str:
    try:   return psutil.Process(pid).name()
    except: return "N/A"


def proc_io_other(pid: int) -> int:
    try:   return getattr(psutil.Process(pid).io_counters(), "other_bytes", 0)
    except: return 0


def load_cfg() -> dict:
    try:
        with open(CFG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_cfg(cfg: dict):
    try:
        with open(CFG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass
