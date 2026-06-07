# System Monitor

Monitor de seguridad en tiempo real para Windows. Detecta conexiones sospechosas, analiza procesos, consulta VirusTotal y permite bloquear amenazas directamente desde la interfaz.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Windows](https://img.shields.io/badge/Windows-10%2F11-blue) ![License](https://img.shields.io/badge/License-MIT-green)

---

## Funcionalidades

### Métricas del sistema
- CPU, RAM, Disco, temperatura CPU y GPU en tiempo real
- Gráfico de red en vivo (últimos 2 minutos)
- Top 5 procesos por uso de CPU

### Seguridad de red
- Monitor de conexiones TCP externas con detección de procesos sospechosos
- Whitelist personalizada y persistente
- Detección de puertos maliciosos conocidos (4444, 1337, 31337, etc.)
- Integración con **VirusTotal API** — consulta IPs y hash SHA-256 de ejecutables
- Resolución de hostname + geolocalización (país, organización)
- Mapa geográfico de conexiones activas
- Bloqueo de procesos via firewall de Windows con un clic

### Seguridad del sistema
- Monitoreo del registro `Run`/`RunOnce` (detecta nuevas claves de auto-inicio)
- Monitoreo de tareas programadas y servicios de Windows
- Integridad del archivo `hosts` (hash SHA-256)
- Escaneo de cache DNS (detecta dominios con TLDs sospechosos)
- Lectura del Event Log de Windows (logon fallido, usuario creado, servicio instalado, log borrado, etc.)
- Detección de DLL injection en procesos sospechosos
- Verificación de firma digital de ejecutables

### Reportes y persistencia
- Historial de conexiones sospechosas en SQLite (24h de métricas)
- Exportar reporte HTML y CSV
- Icono en bandeja del sistema con notificaciones toast
- Widget compacto flotante siempre visible
- Auto-inicio con Windows via Task Scheduler

---

## Requisitos

- Windows 10 / 11
- Python 3.10 o superior
- Ejecutar como **Administrador** para acceder a conexiones de red, firewall y Event Log

### Dependencias

```bash
pip install psutil
```

> El resto de módulos (`tkinter`, `sqlite3`, `winreg`, `ctypes`, `subprocess`) vienen incluidos con Python en Windows.

---

## Instalación

```bash
git clone https://github.com/tu-usuario/system-monitor.git
cd system-monitor
pip install psutil
copy config.example.json config.json
python monitor.py
```

---

## Configuración

Edita `config.json` (creado a partir de `config.example.json`):

```json
{
  "vt_api_key": "TU_API_KEY_AQUI",
  "whitelist": [],
  "cpu_thresh": 90,
  "ram_thresh": 90,
  "disk_thresh": 92
}
```

| Campo | Descripción |
|---|---|
| `vt_api_key` | API key gratuita de [VirusTotal](https://www.virustotal.com) para consultar IPs y hashes |
| `whitelist` | Procesos que no se marcan como sospechosos (se puede gestionar desde la UI) |
| `cpu_thresh` | Porcentaje de CPU a partir del cual se dispara una alerta |
| `ram_thresh` | Porcentaje de RAM a partir del cual se dispara una alerta |
| `disk_thresh` | Porcentaje de disco a partir del cual se dispara una alerta |

> `config.json` está excluido del repositorio para proteger tu API key. Nunca lo subas.

---

## Advertencias

- El programa crea reglas de salida en el **Firewall de Windows** cuando se usa el botón "Bloquear FW". Estas reglas se pueden ver y eliminar desde el gestor de firewall integrado en la app.
- El módulo de detección de DLL escanea los mapas de memoria de procesos activos. Requiere permisos elevados.
- El límite de la API gratuita de VirusTotal es de **500 consultas/día** (el programa aplica un límite interno de 75/día para no agotarla).

---

## Licencia

MIT
