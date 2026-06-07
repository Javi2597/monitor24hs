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
- **No requiere Administrador** — funciona con privilegios de usuario estándar

### Dependencias

```bash
pip install psutil
```

> El resto de módulos (`tkinter`, `sqlite3`, `winreg`, `ctypes`, `subprocess`) vienen incluidos con Python en Windows.

---

## Instalación

```bash
git clone https://github.com/Javi2597/monitor24hs.git
cd monitor24hs
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
> Al guardar la configuración, el programa restringe automáticamente los permisos del archivo al usuario actual mediante `icacls`.

---

## Arquitectura

El código está separado en módulos especializados:

| Módulo | Responsabilidad |
|---|---|
| `monitor.py` | UI principal, orquestación y bucle de eventos Tkinter |
| `security.py` | Escaneos bloqueantes: temperatura, GPU, registro, DLLs, servicios, firmas |
| `network.py` | I/O de red: conexiones TCP, resolución de IPs, consultas VirusTotal |
| `db.py` | Persistencia SQLite: historial de conexiones y métricas de 24 h |
| `utils.py` | Constantes, helpers puros y lectura/escritura de configuración |

Todo el I/O pesado se ejecuta en un `ThreadPoolExecutor` y los resultados se despachan al hilo principal via `root.after(0, callback)`.

---

## Advertencias

- El programa crea reglas de salida en el **Firewall de Windows** cuando se usa el botón "Bloquear FW". Estas reglas se pueden ver y eliminar desde el gestor de firewall integrado en la app.
- La detección de DLL injection escanea los mapas de memoria de procesos activos; puede no tener acceso a procesos de sistema sin permisos elevados.
- El límite de la API gratuita de VirusTotal es de **500 consultas/día** (el programa aplica un límite interno de 75/día para no agotarla).
- `sigcheck.exe` (Sysinternals) es opcional. Si está presente en `C:\Tools\` o `C:\Program Files\Sysinternals\`, se usa para verificar firmas digitales; si no, se usa `Get-AuthenticodeSignature` de PowerShell como fallback.

---

## Seguridad

El proyecto fue sometido a una auditoría de seguridad interna. Los principales controles implementados son:

| Área | Control |
|---|---|
| Inyección de comandos | Rutas de ejecutables pasadas por `stdin` a PowerShell, nunca interpoladas en el comando |
| XSS en reportes HTML | Todos los valores de datos externos pasan por `html.escape()` antes de insertarse |
| Reglas de firewall | Nombres de proceso sanitizados con regex `[^A-Za-z0-9._-]` antes de pasar a `netsh` |
| Privilegios de inicio | Auto-inicio registrado sin `/rl HIGHEST` — nivel de usuario estándar |
| Peticiones HTTPS | Contexto SSL explícito (`ssl.create_default_context()`) en todas las llamadas de red |
| Concurrencia en BD | `threading.Lock` + `PRAGMA journal_mode=WAL` en todas las operaciones SQLite |
| API key en reposo | Permisos del archivo `config.json` restringidos al usuario actual via `icacls` |
| Herramientas externas | `sigcheck.exe` y `nvidia-smi` resueltos desde rutas absolutas conocidas, no desde `PATH` |
| API key en la UI | Campo de entrada con `show="*"` y botón de revelar; no se prerrellena en texto claro |

---

## Licencia

MIT
