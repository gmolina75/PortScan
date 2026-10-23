# Documentación Técnica - PortScan v2.0

## Resumen de cambios principales

### Código
- Reescritura completa a Python 3.9+ con type hints (`from __future__ import annotations`)
- Estructura modular con dataclasses: `Resultado`, `Reporte`
- Escaneo paralelo con `ThreadPoolExecutor` (configurable via `-w/--workers`)
- Protocolos soportados: **TCP** (connect scan) y **UDP** (datagram + timeout)
- Manejo de excepciones robusto (`ValueError`, `OSError`, `KeyboardInterrupt`)
- Uso de `socket.socket` con context manager implícito (`try/finally` para close)
- Resolución de host dual: IPv4 + IPv6 automática
- Colores ANSI con detección de TTY (`sys.stdout.isatty()`)
- Barra de progreso Unicode en tiempo real

### Funcionalidades nuevas
- **Modo CLI** con argparse completo + epilog de ejemplos
- **Modo interactivo** con menús, presets y validación
- **Soporte múltiples hosts** separados por coma
- **Presets** de puertos: `comunes` (~200), `web` (12), `bases` (10), `admin` (~15)
- **Detección de servicios** por puerto (diccionario de 100+ servicios IANA comunes)
- **Exportación CSV y JSON** automática por extensión de archivo
- **Timeout configurable** por conexión (`-t/--timeout`)
- **Modo silencioso** (`-q/--quiet`) para solo puertos abiertos
- **Progreso opcional** (`--no-progress`)
- **Codificación UTF-8 forzada** en Windows (`-X utf8` o wrapper)

### Seguridad
- No ejecuta comandos del sistema (`os.system` eliminado)
- Validación estricta de entrada (rangos 1-65535, tipos, límites)
- Sin dependencias externas
- Timeouts en todas las operaciones de red

## Arquitectura

```
main() → parse_args()
  ├─ args presentes → cli_mode() → scan() → exportar() → imprimir_resumen()
  └─ sin args      → interactive_mode() → _escaneo_interactivo() → scan()
                                                   → exportar() → imprimir_resumen()

scan() → ThreadPoolExecutor → scan_port() [paralelo]
  scan_port() → socket.connect_ex() (TCP) | sendto/recv (UDP)
    → Resultado(puerto, abierto, servicio, protocolo)

exportar() → _exportar_csv() | _exportar_json()
```

### Clases y funciones clave

| Símbolo | Tipo | Descripción |
|---------|------|-------------|
| `Resultado` | `@dataclass` | Puerto, estado, servicio, protocolo |
| `Reporte` | `@dataclass` | Metadatos + lista de `Resultado` |
| `scan_port()` | `Callable` | Escanea 1 puerto, retorna `Resultado` |
| `scan()` | `Callable` | Paraleliza con `ThreadPoolExecutor` |
| `resolve_host()` | `Callable` | IPv4/IPv6 dual, retorna (ip, version) |
| `parse_ports()` | `Callable` | Convierte string CLI a `List[int]` |
| `exportar()` | `Callable` | Dispatcher CSV/JSON por extensión |

## Pruebas rápidas

```bash
# Compilar (validación sintaxis)
python -m py_compile portscan.py

# CLI básico
python -X utf8 portscan.py -H 127.0.0.1 -p 1-100 -t 0.5 -w 50 -q -o test.json

# Preset web + CSV
python -X utf8 portscan.py -H 127.0.0.1 --preset web -o test_web.csv

# Múltiples hosts + UDP
python -X utf8 portscan.py -H 127.0.0.1,::1 -p 53,123 --proto udp

# Interactivo
python -X utf8 portscan.py
```

## Dependencias
- Python 3.9+
- Solo biblioteca estándar:
  - `argparse`, `socket`, `sys`, `time`, `csv`, `json`
  - `concurrent.futures`, `dataclasses`, `datetime`, `pathlib`, `typing`
  - `io`, `contextlib` (para UTF-8 en Windows)

## Próximas mejoras sugeridas
- [ ] Escaneo SYN stealth (requiere root/raw sockets)
- [ ] Detección de banner/versión de servicio (grab banner)
- [ ] Exportación XML/Nmap-compatible
- [ ] Escaneo de rango IPv6 completo
- [ ] Interfaz web simple (FastAPI + WebSocket)
- [ ] Configuración vía archivo YAML/TOML
- [ ] Logging a archivo rotativo
- [ ] Tests unitarios con pytest

## Archivos del proyecto

```
PortScan-master/
├── portscan.py       # Código principal (v2.0)
├── README.md         # Documentación usuario
├── DOC_TECNICA.md    # Este archivo
├── LICENSE           # GPL v3
├── .gitignore        # Estándar Python
└── test_*.json/csv   # Archivos de prueba (generados)
```