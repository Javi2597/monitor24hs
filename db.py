"""SQLite persistence — connections history and metrics."""
import csv
import sqlite3
import threading
import time

_ALLOWED_COLS = {"country": "TEXT", "org": "TEXT"}


class HistoryDB:
    def __init__(self, path: str):
        # check_same_thread=False permite que hilos del ThreadPoolExecutor llamen
        # a métodos de lectura, pero todas las escrituras se protegen con _lock
        # para serializar acceso concurrente y evitar "database is locked".
        # WAL (Write-Ahead Log) permite lecturas concurrentes sin bloquear
        # escrituras, al contrario del modo journal por defecto (DELETE).
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
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
        # Migración no destructiva: añade columnas nuevas si la BD fue creada con
        # una versión anterior del esquema. PRAGMA table_info devuelve una fila por
        # columna; el campo [1] es el nombre. ALTER TABLE en SQLite no admite
        # parámetros, de ahí el f-string con valores validados contra _ALLOWED_COLS.
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(connections)")}
        for col, typ in _ALLOWED_COLS.items():
            if col not in cols:
                # col y typ provienen de _ALLOWED_COLS — no hay entrada de usuario
                self._db.execute(f"ALTER TABLE connections ADD COLUMN {col} {typ}")
        self._db.commit()

    # ── Connections ──────────────────────────────────────────────────────────

    def save_connections(self, rows: list, ip_info: dict) -> int:
        susp = [r for r in rows if r.get("suspicious") or r.get("port_bad")]
        if not susp:
            return 0
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
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
        with self._lock:
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
        with self._lock:
            return self._db.execute(
                "SELECT timestamp,proc,ip,port,state,country "
                "FROM connections ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()

    def clear_connections(self):
        with self._lock:
            self._db.execute("DELETE FROM connections")
            self._db.commit()

    def export_csv(self, path: str) -> int:
        with self._lock:
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
        with self._lock:
            self._db.execute(
                "INSERT INTO metrics_history "
                "(timestamp,cpu,ram,net_sent,net_recv,disk_r,disk_w,cpu_temp) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (time.strftime("%Y-%m-%d %H:%M:%S"),
                 cpu, ram, net_sent, net_recv, disk_r, disk_w, cpu_temp))
            self._db.commit()

    def trim_old_metrics(self):
        with self._lock:
            self._db.execute(
                "DELETE FROM metrics_history "
                "WHERE timestamp < datetime('now','-24 hours')")
            self._db.commit()

    def load_metrics(self) -> list:
        with self._lock:
            return self._db.execute(
                "SELECT cpu,ram,net_sent,net_recv,disk_r,disk_w,cpu_temp "
                "FROM metrics_history ORDER BY id ASC").fetchall()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def close(self):
        try:
            self._db.close()
        except Exception:
            pass
