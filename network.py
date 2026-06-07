"""Network monitoring and IP intelligence — blocking I/O for ThreadPoolExecutor."""
import ipaddress
import json
import socket
import ssl
import time
import urllib.request
import urllib.error

import psutil

import utils

_SSL_CTX = ssl.create_default_context()


def collect_conns(session_bytes: dict, prev_io: dict,
                  user_whitelist: set) -> tuple:
    """Return (rows, susp_ips). Raises psutil.AccessDenied if no permissions."""
    raw = psutil.net_connections(kind="tcp")
    rows = []
    seen_ips = {}
    for c in raw:
        if not c.raddr:
            continue
        ip = c.raddr.ip
        if not utils.is_external(ip):
            continue
        if c.status not in ("ESTABLISHED", "LISTEN"):
            continue
        pid  = c.pid or 0
        name = utils.proc_name(pid) if pid else "N/A"
        curr = utils.proc_io_other(pid)
        prev = prev_io.get(pid, curr)
        prev_io[pid] = curr
        session_bytes[pid] = session_bytes.get(pid, 0) + max(curr - prev, 0)
        port_bad   = c.raddr.port in utils.SUSPICIOUS_PORTS
        suspicious = (name not in utils.WHITELIST and name not in user_whitelist) or port_bad
        if suspicious:
            seen_ips[ip] = None
        parent_name = ""
        try:
            par = psutil.Process(pid).parent()
            parent_name = par.name() if par else ""
        except Exception:
            pass
        uname = ""
        elevated = False
        try:
            uname = psutil.Process(pid).username() or ""
            elevated = any(k in uname.upper() for k in ("SYSTEM", "NT AUTHORITY"))
        except Exception:
            pass
        rows.append({
            "proc": name, "pid": pid, "ip": ip,
            "port": c.raddr.port, "state": c.status,
            "mb": session_bytes.get(pid, 0) / 1024 ** 2,
            "suspicious": suspicious, "port_bad": port_bad,
            "parent": parent_name, "user": uname, "elevated": elevated,
        })
    rows.sort(key=lambda r: (0 if (r["suspicious"] or r["port_bad"]) else 1,
                              r["proc"].lower()))
    return rows[:10], list(seen_ips)


def resolve_ip(ip: str) -> dict:
    res = {"host": ip, "org": "", "country": "", "lat": None, "lon": None}
    try:
        ipaddress.ip_address(ip)  # valida que sea IP legítima antes de la petición
    except ValueError:
        return res
    try:
        res["host"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    try:
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip}/json",
            headers={"User-Agent": "system-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=6, context=_SSL_CTX) as r:
            d = json.loads(r.read())
        res["org"]     = d.get("org", "")
        res["country"] = d.get("country", "")
        loc = d.get("loc", "")
        if loc and "," in loc:
            la, lo = loc.split(",", 1)
            res["lat"] = float(la)
            res["lon"] = float(lo)
    except Exception:
        pass
    return res


def vt_lookup(kind: str, val: str, api_key: str) -> dict:
    ep  = "ip_addresses" if kind == "ip" else "files"
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/{ep}/{val}",
        headers={"x-apikey": api_key, "User-Agent": "system-monitor/1.0"})
    with urllib.request.urlopen(req, timeout=12, context=_SSL_CTX) as r:
        d = json.loads(r.read())
    s = d["data"]["attributes"]["last_analysis_stats"]
    return {k: s.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")}


def build_report(ips: list, rows: list) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    sep  = "=" * 60
    sep2 = "-" * 60
    hdr  = f"{'Proceso':<17}{'PID':<7}{'IP Remota':<18}{'Puerto':<8}{'Estado':<14}MB"
    lines = [sep, "  SYSTEM MONITOR - Conexiones Sospechosas",
             f"  {ts}", sep, "", hdr, sep2]
    for r in rows:
        lines.append(
            f"{r['proc'][:16]:<17}{str(r['pid']):<7}{r['ip']:<18}"
            f"{str(r['port']):<8}{r['state']:<14}{r['mb']:.2f}")
    lines += ["", sep2, "IPs para VirusTotal:", ""]
    lines += [f"  {ip}" for ip in ips]
    lines += ["", sep]
    return "\n".join(lines)
