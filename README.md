# PortScan

<p align="center">
  <span style="background: #fff3cd; color: #856404; padding: 0.5rem 1rem; border-radius: 4px; font-weight: bold;">
    ⚠️ Solo para uso autorizado — No escanear redes sin permiso explícito por escrito
  </span>
</p>

---

Escáner de puertos TCP/UDP en español para auditorías de red autorizadas.

## ¿Qué hace?

PortScan permite verificar puertos abiertos y cerrados en un host. Convierte nombres de dominio a IPs, soporta protocolos TCP y UDP, y detecta servicios conocidos (SSH, HTTP, MySQL, etc.) por puerto.

## Requisitos

- Python 3.9 o superior
- No requiere dependencias externas (solo biblioteca estándar)

## Instalación

```sh
git clone https://github.com/gmolina75/PortScan.git
cd PortScan
```

## Uso

### Modo interactivo (sin argumentos)

```sh
portscan.bat
```

Muestra un menú con opciones: escanear puertos, ver presets o salir. Pide host, protocolo, rango de puertos y timeout.

### Modo línea de comandos

```sh
# Escanear puertos 1-1024 en un host
portscan.bat -H 192.168.1.1 -p 1-1024

# Puerto único con timeout personalizado
portscan.bat -H google.com -p 80 -t 0.5

# Usar preset de puertos comunes y guardar en JSON
portscan.bat -H 127.0.0.1 --preset comunes -o resultados.json

# Múltiples hosts separados por coma
portscan.bat -H google.com,github.com -p 22,80,443

# Protocolo UDP
portscan.bat -H 127.0.0.1 -p 53,123 --proto udp

# Salida silenciosa (solo puertos abiertos)
portscan.bat -H ejemplo.com --preset web -q
```

### Parámetros

| Parámetro | Descripción |
|-----------|-------------|
| `-H, --host` | Host, IP o dominio. Varios separados por coma. |
| `-p, --ports` | Rango `1-1024`, único `80`, lista `22,80,443` o mixto. |
| `--preset` | Preset de puertos: `comunes`, `web`, `bases`, `admin`. |
| `-t, --timeout` | Timeout por conexión en segundos (por defecto 1.0). |
| `-w, --workers` | Hilos paralelos (por defecto 100). |
| `--proto` | Protocolo: `tcp` o `udp` (por defecto tcp). |
| `-o, --output` | Archivo de salida `.csv` o `.json`. |
| `-q, --quiet` | Solo muestra puertos abiertos. |
| `--no-progress` | Deshabilitar barra de progreso. |
| `--version` | Mostrar versión. |

### Presets disponibles

| Preset | Cantidad | Uso típico |
|--------|----------|------------|
| `comunes` | ~200 | Servicios, web, bases de datos, administración |
| `web` | 12 | Puertos HTTP/HTTPS/proxy |
| `bases` | 10 | MySQL, PostgreSQL, Redis, MongoDB, etc. |
| `admin` | ~15 | SSH, RDP, VNC, SNMP |

## Exportación

Los resultados se guardan automáticamente en el formato que indiques por la extensión del archivo:

- **JSON** (`-o resultados.json`): estructurado con metadatos y lista de puertos
- **CSV** (`-o resultados.csv`): tabla plana con columnas host, ip, protocolo, puerto, estado, servicio

## Licencia

GNU GPL v3. Ver archivo `LICENSE`.