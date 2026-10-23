# PortScan

<img alt="python-logo" width="180" src="https://raw.githubusercontent.com/Sup3r-Us3r/PortScan/master/Screenshots/python-logo.png">

### Ver más en:
* [Python](https://www.python.org/)
* [Arch Linux](https://www.archlinux.org/)

### Capturas del proyecto:

![Spyquiz.py][screenshot1]

![Url.py][screenshot2]

![Inicio][screenshot3]

[screenshot1]:https://raw.githubusercontent.com/Sup3r-Us3r/PortScan/master/Screenshots/1.png
[screenshot2]:https://raw.githubusercontent.com/Sup3r-Us3r/PortScan/master/Screenshots/2.png
[screenshot3]:https://raw.githubusercontent.com/Sup3r-Us3r/PortScan/master/Screenshots/3.png

### Acerca del proyecto

> **PortScan.py** permite verificar puertos abiertos y cerrados de forma rápida.  
> Pide un host que puede ser `IP LOCAL`, `IP EXTERNA` o `SITIO WEB` y lo convierte automáticamente a su dirección IP.  
> También solicita un puerto inicial y final, o un único puerto si así lo deseas.  
> Desarrollado originalmente en Python 3.5 en Arch Linux y ahora modernizado a Python 3.9+ con muchas mejoras.

**Autor original:** [Sup3r-Us3r](https://github.com/Sup3r-Us3r)  
**Mejoras y mantenimiento:** Giancarlo

---

## Novedades y mejoras (v2.0)

Esta versión incluye mejoras completas respecto al original:

- **Python 3.9+** con tipado y buenas prácticas
- **Interfaz 100% en español**, consistente
- **Escaneo paralelo** con hilos (`ThreadPoolExecutor`) - configurable hasta 1000 workers
- **Protocolos TCP y UDP** (`--proto tcp|udp`)
- **Detección de servicios** por puerto (SSH, HTTP, HTTPS, MySQL, PostgreSQL, Redis, MongoDB, etc.)
- **Presets de puertos** (`--preset comunes|web|bases|admin`)
- **Exportación a CSV y JSON** con estructura completa
- **Soporte IPv4 e IPv6** (resolución automática)
- **Timeout configurable** por conexión
- **Barra de progreso** visual en tiempo real
- **CLI con argparse** + modo interactivo
- **Múltiples hosts** separados por coma
- **Modo silencioso** (`-q`) para solo puertos abiertos
- **Colores ANSI seguros** (se desactivan al redireccionar salida)
- **Manejo robusto** de excepciones y `KeyboardInterrupt`

---

## Instalación y uso

### Requisitos
- Python 3.9 o superior
- No requiere dependencias externas (solo biblioteca estándar)

### Instalación
```sh
$ git clone https://github.com/Sup3r-Us3r/PortScan.git
$ cd PortScan
$ chmod +x portscan.py
```

### Modo interactivo
```sh
$ python portscan.py
```
El programa mostrará un menú con opciones:
1. Escanear puertos (con selección de protocolo, preset o rango personalizado)
2. Ver presets disponibles
3. Salir

### Modo línea de comandos (CLI)

```sh
# Escanear puertos 1-1024 en ejemplo.com (TCP)
$ python portscan.py --host ejemplo.com --ports 1-1024

# Escanear puerto único con timeout personalizado
$ python portscan.py -H 192.168.1.1 -p 80 -t 0.5

# Usar preset "comunes" (~200 puertos) y guardar en JSON
$ python portscan.py -H google.com --preset comunes -o resultados.json

# Múltiples hosts, protocolo UDP, salida CSV
$ python portscan.py -H google.com,github.com -p 53,123,161 --proto udp -o udp.csv

# Preset web + modo silencioso (solo muestra puertos abiertos)
$ python portscan.py -H 127.0.0.1 --preset web -q

# Rango mixto y exportación JSON
$ python portscan.py -H 10.0.0.1 -p 22,80,443,8080-8090 -o reporte.json
```

### Parámetros CLI

| Parámetro | Descripción |
|-----------|-------------|
| `-H, --host` | Host/IP o dominio. Múltiples separados por coma. |
| `-p, --ports` | Rango `inicio-fin`, puerto único `80`, lista `22,80,443` o mixto `1-100,8080`. |
| `--preset` | Preset de puertos: `comunes`, `web`, `bases`, `admin` (requiere `-H`). |
| `-t, --timeout` | Timeout por conexión en segundos. Por defecto `1.0`. |
| `-w, --workers` | Hilos paralelos. Por defecto `100`. |
| `--proto` | Protocolo: `tcp` o `udp`. Por defecto `tcp`. |
| `-o, --output` | Archivo de salida `.csv` o `.json`. |
| `-q, --quiet` | Salida reducida: solo resumen y puertos abiertos. |
| `--no-progress` | Deshabilitar barra de progreso. |
| `--version` | Mostrar versión y salir. |

### Formato de puertos (-p)
```
80              → puerto único
1-1024          → rango inclusivo
22,80,443       → lista de puertos
1-100,8080,9000 → mixto
```

### Presets disponibles
| Preset | Descripción | Cantidad |
|--------|-------------|----------|
| `comunes` | Puertos más usados (servicios, web, DB, admin) | ~200 |
| `web` | Puertos web/proxy típicos | 12 |
| `bases` | Bases de datos comunes | 10 |
| `admin` | Administración remota (SSH, RDP, VNC, SNMP) | ~15 |

---

## Ejemplos de salida

### JSON (estructurado)
```json
{
  "host": "127.0.0.1",
  "ip": "127.0.0.1",
  "protocolo": "tcp",
  "inicio": "2026-10-23T13:35:08",
  "duracion": 1.03,
  "puertos_escaneados": 100,
  "puertos_abiertos": 2,
  "resultados": [
    {"puerto": 22, "abierto": true, "servicio": "ssh", "protocolo": "tcp"},
    {"puerto": 80, "abierto": true, "servicio": "http", "protocolo": "tcp"}
  ]
}
```

### CSV (tabular)
```csv
host,ip,protocolo,puerto,estado,servicio
127.0.0.1,127.0.0.1,tcp,22,abierto,ssh
127.0.0.1,127.0.0.1,tcp,80,abierto,http
```

---

## Dependencias
Python 3.9+ (biblioteca estándar: `socket`, `argparse`, `csv`, `json`, `concurrent.futures`, `dataclasses`)

---

## Licencia

GNU GPL v3. Ver archivo `LICENSE`.

---

## Contribuciones

Sugerencias y mejoras son bienvenidas. Mantén el código en español y con manejo de errores claro.