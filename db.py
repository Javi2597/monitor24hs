"""SQLite persistence — connections history and metrics."""
import csv
import sqlite3
import time


class HistoryDB:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False)
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
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(connections)")}
        for col, typ in [("country", "TEXT"), ("org", "TEXT")]:
            if col not in cols:
                self._db.execute(f"ALTER TABLE connections ADD COLUMN {col} {typ}")
        self._db.commit()

    # ── Connections ──────────────────────────────────────────────────────────

    def save_connections(self, rows: list, ip_info: dict) -> int:
        susp = [r for r in rows if r.get("suspicious") or r.get("port_bad")]
        if not susp:
            return 0
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        for r in susp:
            info = ip_info.get(r["ip"]) or {}
            self._db.execute(
                "INSERT INTO connections "
                "(timestamp,proc,pid,ip,port,state,mb,suspicious,country,org) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (ts, r["proc"], r["pid"], r["ip"], r["port"],
                 r["state"], r["mb"], 1,
                 info.get("country", ""), info.get("org", "")))
        self._db.commit()
        return len(susp)

    def load_connections(self, filter_text: str = "", limit: int = 200) -> list:
        if filter_text:
            flt = filter_text.strip().lower()
            return self._db.execute(
                "SELECT timestamp,proc,pid,ip,port,state,mb,country,org "
                "FROM connections "
                "WHERE LOWER(proc) LIKE ? OR LOWER(ip) LIKE ? "
                "ORDER BY id DESC LIMIT ?",
                (f"%{flt}%", f"%{flt}%", limit)).fetchall()
        return self._db.execute(
            "SELECT timestamp,proc,pid,ip,port,state,mb,country,org "
            "FROM connections ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()

    def load_recent_connections(self, limit: int = 50) -> list:
        return self._db.execute(
            "SELECT timestamp,proc,ip,port,state,country "
            "FROM connections ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()

    def clear_connections(self):
        self._db.execute("DELETE FROM connections")
        self._db.commit()

    def export_csv(self, path: str) -> int:
        rows = self._db.execute(
            "SELECT timestamp,proc,pid,ip,port,state,mb,country,org "
            "FROM connections ORDER BY id DESC LIMIT 5000").fetchall()
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            wr = csv.writer(f)
            wr.writerow(["timestamp", "proc", "pid", "ip", "port",
                         "state", "mb", "country", "org"])
            wr.writerows(rows)
        return len(rows)

    # ── Metrics ──────────────────────────────────────────────────────────────

    def save_metrics(self, cpu: float, ram: float, net_sent: float,
                     net_recv: float, disk_r: float, disk_w: float,
                     cpu_temp: float):
        self._db.execute(
            "INSERT INTO metrics_history "
            "(timestamp,cpu,ram,net_sent,net_recv,disk_r,disk_w,cpu_temp) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (time.strftime("%Y-%m-%d %H:%M:%S"),
             cpu, ram, net_sent, net_recv, disk_r, disk_w, cpu_temp))
        self._db.commit()

    def trim_old_metrics(self):
        self._db.execute(
            "DELETE FROM metrics_history "
            "WHERE timestamp < datetime('now','-24 hours')")
        self._db.commit()

    def load_metrics(self) -> list:
        return self._db.execute(
            "SELECT cpu,ram,net_sent,net_recv,disk_r,disk_w,cpu_temp "
            "FROM metrics_history ORDER BY id ASC").fetchall()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def close(self):
        try:
            self._db.close()
        except Exception:
            pass
