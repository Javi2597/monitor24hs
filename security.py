"""Security scanning — all blocking I/O, designed for ThreadPoolExecutor."""
import hashlib
import os
import subprocess

import psutil

import utils

try:
    import winreg as _winreg
    WINREG = True
except ImportError:
    _winreg = None
    WINREG = False


# ── CPU temperature ──────────────────────────────────────────────────────────

def cpu_temp() -> float:
    # Intento 1: Performance counters — no requiere admin, valores en Kelvin
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation"
             " -ErrorAction SilentlyContinue"
             " | Measure-Object -Property Temperature -Maximum"
             " | Select-Object -ExpandProperty Maximum"],
            capture_output=True, text=True, timeout=6,
            creationflags=subprocess.CREATE_NO_WINDOW)
        raw = r.stdout.strip()
        if raw and raw.replace(".", "", 1).lstrip("-").isdigit():
            k = float(raw)
            if k > 200:
                return round(k - 273.15, 1)
    except Exception:
        pass
    # Intento 2: MSAcpi WMI — requiere admin, décimas de Kelvin
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-WmiObject -Namespace root\\wmi "
             "-Class MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue"
             " | Measure-Object -Property CurrentTemperature -Maximum"
             " | Select-Object -ExpandProperty Maximum"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW)
        raw = r.stdout.strip()
        if raw and raw.lstrip("-").replace(".", "", 1).isdigit():
            return round(float(raw) / 10.0 - 273.15, 1)
    except Exception:
        pass
    # Intento 3: LibreHardwareMonitor WMI — si está corriendo
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-WmiObject -Namespace root\\LibreHardwareMonitor -Class Sensor"
             " -Filter \"SensorType='Temperature'\""
             " -ErrorAction SilentlyContinue"
             " | Where-Object { $_.Name -match 'CPU|Core|Package' }"
             " | Measure-Object -Property Value -Maximum"
             " | Select-Object -ExpandProperty Maximum"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW)
        raw = r.stdout.strip()
        if raw and raw.replace(".", "", 1).lstrip("-").isdigit():
            v = float(raw)
            if 0 < v < 150:
                return round(v, 1)
    except Exception:
        pass
    return -1.0


# ── GPU ──────────────────────────────────────────────────────────────────────

def gpu_info() -> dict:
    # NVIDIA via nvidia-smi
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
    # WMI fallback (nombre + VRAM)
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
            return {"vendor": "WMI", "name": name.strip(), "vram_mb": vram_mb}
    except Exception:
        pass
    return {}


# ── Scheduled tasks ──────────────────────────────────────────────────────────

def sched_tasks() -> set:
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


# ── Registry Run keys ─────────────────────────────────────────────────────────

def reg_keys() -> dict:
    result = {}
    if not WINREG:
        return result
    paths = [
        (_winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (_winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (_winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (_winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, path in paths:
        try:
            key = _winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, val, _ = _winreg.EnumValue(key, i)
                    result[f"{path}\\{name}"] = str(val)
                    i += 1
                except OSError:
                    break
            _winreg.CloseKey(key)
        except Exception:
            pass
    return result


# ── DLL injection detection ───────────────────────────────────────────────────

def scan_dlls(pids: list) -> list:
    findings = []
    for pid in pids:
        try:
            proc    = psutil.Process(pid)
            exe_dir = os.path.dirname(proc.exe()).lower()
            for m in proc.memory_maps():
                path = m.path.lower() if hasattr(m, "path") else ""
                if not path.endswith(".dll"):
                    continue
                safe = any(path.startswith(d) for d in utils.SAFE_DLL_DIRS)
                if not safe and not path.startswith(exe_dir):
                    findings.append({"pid": pid, "proc": proc.name(),
                                     "dll": m.path[:80]})
        except Exception:
            pass
    return findings


# ── Windows services ──────────────────────────────────────────────────────────

def scan_services() -> set:
    try:
        r = subprocess.run(
            ["sc", "query", "state=", "all"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW)
        svcs = set()
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                svcs.add(line.split(":", 1)[1].strip())
        return svcs
    except Exception:
        return set()


# ── Hosts file integrity ──────────────────────────────────────────────────────

def hash_hosts() -> str:
    try:
        with open(utils.HOSTS_PATH, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""


# ── DNS cache scan ────────────────────────────────────────────────────────────

def scan_dns() -> list:
    _BAD_TLD  = {".ru", ".cn", ".tk", ".xyz", ".top", ".pw", ".cc", ".su"}
    _KEYWORDS = {"payload", "c2", "shell", "bot", "rat", "malware", "exploit", "cmd"}
    suspicious = []
    try:
        r = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW)
        for line in r.stdout.splitlines():
            if "Nombre de registro" in line or "Record Name" in line:
                domain = line.split(":", 1)[-1].strip().lower().rstrip(".")
                bad = (any(domain.endswith(t) for t in _BAD_TLD)
                       or any(k in domain for k in _KEYWORDS))
                if bad:
                    suspicious.append(domain)
    except Exception:
        pass
    return list(dict.fromkeys(suspicious))


# ── Windows Event Log ─────────────────────────────────────────────────────────

def evtlog() -> list:
    ids_str = ",".join(str(i) for i in utils.EVTLOG_IDS)
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


# ── Executable hash ───────────────────────────────────────────────────────────

def compute_hash(pid: int) -> str:
    try:
        exe = psutil.Process(pid).exe()
        sha = hashlib.sha256()
        with open(exe, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception:
        return ""


# ── Digital signature ─────────────────────────────────────────────────────────

def check_sig(exe: str) -> dict:
    try:
        r = subprocess.run(
            ["sigcheck.exe", "-nobanner", "-accepteula", "-q", exe],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW)
        out = r.stdout + r.stderr
        if "Verified:" in out:
            signed = "Unsigned" not in out
            pub = ""
            for line in out.splitlines():
                if line.strip().startswith("Publisher:"):
                    pub = line.split(":", 1)[1].strip()
                    break
            return {"signed": signed, "publisher": pub}
    except FileNotFoundError:
        pass
    except Exception:
        pass
    try:
        # Ruta pasada por stdin para evitar inyección en el comando PowerShell
        ps = ("$exe = $input | Out-String -NoNewline;"
              "$s = Get-AuthenticodeSignature $exe;"
              "$s.Status.ToString() + '|' +"
              "($s.SignerCertificate.Subject -replace '.*CN=([^,]+).*','$1')")
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            input=exe, capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW)
        out = r.stdout.strip()
        if "|" in out:
            status, pub = out.split("|", 1)
            return {"signed": status.strip() == "Valid", "publisher": pub.strip()}
    except Exception:
        pass
    return {"signed": None, "publisher": ""}
