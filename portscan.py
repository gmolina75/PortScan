#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortScan - Escáner de puertos TCP/UDP en español

Escanea un rango de puertos TCP o UDP en un host, resolviendo nombres a IP.
Muestra puertos abiertos/cerrados con colores, detección de servicios,
escaneo paralelo y exportación a CSV o JSON.

Características:
- Python 3.9+, sin dependencias externas
- Interfaz 100% en español
- Escaneo paralelo con hilos (threads)
- Protocolos TCP y UDP
- Detección de servicios conocidos por puerto
- Presets de puertos comunes (top-100, top-1000, comunes)
- Exportación a CSV y JSON
- Soporte IPv4 e IPv6
- Timeout configurable, modo silencioso, barra de progreso
- CLI con argparse + modo interactivo
- Colores ANSI seguros (se desactivan al redirectar salida)
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

VERSION = "2.0"

# ---------------------------------------------------------------------------
# Colores
# ---------------------------------------------------------------------------

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    @staticmethod
    def enabled() -> bool:
        try:
            return sys.stdout.isatty()
        except Exception:
            return False

    @classmethod
    def c(cls, code: str, text: str) -> str:
        return f"{code}{text}{cls.RESET}" if cls.enabled() else text


def msg(color: str, text: str) -> str:
    """Atajo para mensajes con color."""
    return Colors.c(color, text)


# ---------------------------------------------------------------------------
# Datos
# ---------------------------------------------------------------------------

@dataclass
class Resultado:
    """Resultado del escaneo de un puerto."""
    puerto: int
    abierto: bool
    servicio: str = "desconocido"
    protocolo: str = "tcp"


@dataclass
class Reporte:
    """Informe completo de un escaneo."""
    host: str
    ip: str
    protocolo: str
    inicio: str
    duracion: float
    puertos_escaneados: int
    puertos_abiertos: int
    resultados: List[Resultado] = field(default_factory=list)


# Servicios conocidos por puerto (los más relevantes)
SERVICIOS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    26: "rsftp", 37: "rquotad", 53: "dns", 69: "tftp", 70: "gopher",
    80: "http", 81: "http-alt", 88: "kerberos-sec", 110: "pop3",
    111: "rpcbind", 113: "ident", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    139: "netbios-ssn", 143: "imap2", 161: "snmp", 162: "snmptrap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    500: "isakmp", 512: "exec", 513: "login", 514: "syslog",
    515: "printer", 530: "courier", 543: "klogin", 544: "kshell",
    554: "rtsp", 563: "nntps", 587: "submission", 590: "rfb",
    631: "ipp", 636: "ldaps", 646: "lpr", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "ms-sql-s", 1521: "oracle-tns",
    1723: "pptp", 1755: "mms-hp", 2049: "nfs", 2121: "xmlconnect",
    3128: "squid", 3306: "mysql", 3389: "ms-wbt-server",
    4899: "vnc", 5060: "sip", 5061: "sips", 5432: "postgresql",
    5440: "postgresql", 5900: "vnc", 5901: "vnc-1", 5902: "vnc-2",
    5903: "vnc-3", 5904: "vnc-4", 5905: "vnc-5",
    6000: "x11", 6001: "x11-1", 6379: "redis", 8000: "http-alt",
    8008: "blackice", 8080: "http-proxy", 8081: "blackice-2",
    8090: "http-teranext", 8443: "https-alt", 8888: "alt-http",
    9000: "irdmi", 9050: "tor-ssocks", 9090: "zephyr-cl",
    9200: "elasticsearch", 9300: "elasticsearch", 11211: "memcached",
    15672: "rabbitmq", 27017: "mongod",
}

# Presets de puertos
PRESETS = {
    "comunes": [
        20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389,
        443, 445, 465, 512, 513, 514, 515, 548, 554, 587, 590, 631,
        636, 993, 995, 1080, 1433, 1521, 1723, 2049, 3128, 3306,
        3389, 4899, 5000, 5001, 5002, 5003, 5004, 5005, 5006,
        5007, 5008, 5009, 5030, 5060, 5061, 5190, 5191, 5222,
        5432, 5440, 5800, 5900, 5901, 5902, 5903, 5904, 5905,
        6000, 6379, 7001, 7100, 7200, 7300, 7400, 7443, 7444,
        7547, 8000, 8008, 8014, 8042, 8043, 8045, 8080, 8081,
        8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
        8091, 8092, 8093, 8118, 8180, 8222, 8333, 8443, 8500,
        8649, 8888, 8889, 9000, 9001, 9002, 9009, 9050, 9060,
        9071, 9080, 9090, 9091, 9200, 9300, 10000, 10443,
        11211, 12345, 15672, 16384, 20000, 32768, 50000,
        55555, 59999, 65000,
    ],
    "web": [80, 443, 8080, 8443, 8000, 8888, 8008, 8009, 8899, 81, 8081, 8444],
    "bases": [3306, 5432, 1433, 1521, 6379, 27017, 9200, 11211, 9042, 24816],
    "admin": [22, 3389, 5900, 5901, 4899, 23, 2323, 161, 2049, 3389, 5432, 9100, 9101, 9102, 9103],
}


def servicio_de(puerto: int) -> str:
    return SERVICIOS.get(puerto, "desconocido")


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def banner() -> None:
    art = r"""
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █████╗ ██╗   ██╗██████╗  █████╗ ██████╗  █████╗ 
  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔══██║
  ███████║██║   ██║██████╔╝██║  ██║██████╔╝███████║
  ██╔══██║██║   ██║██╔══██╗██║  ██║██╔══██╗██╔══██║
  ██║  ██║╚██████╔╝██║  ██║ █████╔╝██║  ██║██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"""
    print(msg(Colors.BLUE, art))
    print(msg(Colors.CYAN, f"═══ Aurora PortScan v{VERSION} — Escáner de Puertos Profesional ═══"))
    print()


# ---------------------------------------------------------------------------
# Resolución de hosts
# ---------------------------------------------------------------------------

def resolve_host(host: str) -> Tuple[str, int]:
    """
    Resuelve host a IP.
    Retorna (ip, version) donde version es 4 o 6.
    """
    try:
        # Intento primero IPv4
        ip = socket.gethostbyname(host)
        return ip, 4
    except socket.gaierror:
        pass
    # Intento IPv6
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6)
        if infos:
            return infos[0][4][0], 6
    except socket.gaierror:
        pass
    raise ValueError(f"Host inválido o sin resolución: {host}")


# ---------------------------------------------------------------------------
# Detección de IPs locales y públicas
# ---------------------------------------------------------------------------

def ip_local() -> Optional[str]:
    """
    Obtiene la IP local de la máquina mediante un socket UDP.
    No envía datos reales, solo determina la interfaz usada para llegar a internet.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip
    except OSError:
        return None


def ip_publica() -> Optional[str]:
    """
    Obtiene la IP pública consultando un servicio externo.
    Requiere conexión a internet.
    """
    import urllib.request
    urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ident.me",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PortScan/2.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read().decode("utf-8").strip()
                if ip:
                    return ip
        except Exception:
            continue
    return None


def ips_en_red(base_ip: str) -> List[str]:
    """
    Dado '192.168.100.0', retorna lista de IPs del .1 al .254.
    Solo funciona para IPv4.
    """
    partes = base_ip.split(".")
    if len(partes) != 4:
        raise ValueError("IP debe ser IPv4 (ej: 192.168.100.0)")
    try:
        a, b, c, d = (int(p) for p in partes)
    except ValueError:
        raise ValueError("Componentes de IP deben ser numéricos")
    if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255 and 0 <= d <= 255):
        raise ValueError("Componentes de IP fuera de rango (0-255)")
    if d != 0:
        raise ValueError("El último octeto debe ser 0 para escanear toda la red (ej: 192.168.100.0)")
    base = f"{a}.{b}.{c}."
    return [base + str(i) for i in range(1, 255)]


# ---------------------------------------------------------------------------
# Escaneo
# ---------------------------------------------------------------------------

def scan_port(ip: str, port: int, timeout: float = 1.0,
              protocolo: str = "tcp", ip_version: int = 4) -> Resultado:
    """
    Escanea un solo puerto.
    Devuelve Resultado con estado abierto/cerrado.
    """
    if ip_version == 6:
        af = socket.AF_INET6
        addr = (ip, port)
    else:
        af = socket.AF_INET
        addr = (ip, port)

    try:
        if protocolo == "tcp":
            sock = socket.socket(af, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                result = sock.connect_ex(addr)
                abierto = result == 0
            finally:
                sock.close()
        else:  # udp: envío de paquete y espera de respuesta/timeout
            sock = socket.socket(af, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                # Un paquete vacío a un puerto UDP; si el puerto no existe,
                # se espera ICMP port unreachable (en Linux) o timeout.
                sock.sendto(b"", addr)
                try:
                    sock.recv(1024)
                    abierto = True
                except socket.timeout:
                    # En Windows/IPv4 no hay ICMP, se marca como "filtrante"
                    abierto = False
            finally:
                sock.close()
    except OSError:
        abierto = False

    return Resultado(puerto=port, abierto=abierto,
                     servicio=servicio_de(port), protocolo=protocolo)


def scan(ip: str, puertos: List[int], timeout: float = 1.0,
         workers: int = 100, protocolo: str = "tcp",
         ip_version: int = 4, verbose: bool = True,
         quiet: bool = False,
         progress: bool = True) -> Tuple[List[Resultado], float]:
    """
    Escanea una lista de puertos en paralelo.
    Devuelve (lista de resultados, duración en segundos).
    """
    inicio = time.time()
    resultados: List[Resultado] = []
    total = len(puertos)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futuros = {
            pool.submit(scan_port, ip, p, timeout, protocolo, ip_version): p
            for p in puertos
        }
        completados = 0
        for futuro in as_completed(futuros):
            r = futuro.result()
            resultados.append(r)
            completados += 1
            if verbose and progress and not quiet:
                bar = progress_bar(completados, total)
                try:
                    print(f"\r{msg(Colors.CYAN, f'Escaneando [{bar} ]')} "
                          f"{completados}/{total}", end="", flush=True)
                except UnicodeEncodeError:
                    print(f"\rEscaneando [{bar} ] {completados}/{total}", end="", flush=True)
            # Mostrar abiertos al vuelo (solo en modo detallado o quiet)
            if r.abierto and (not verbose or quiet):
                try:
                    print(f"\n{msg(Colors.WHITE, '▼▶')} Puerto {r.puerto} "
                          f"{msg(Colors.GREEN, 'ABIERTO')} "
                          f"({r.servicio})")
                except UnicodeEncodeError:
                    print(f"\nPuerto {r.puerto} ABIERTO ({r.servicio})")

    if verbose and progress and not quiet:
        print()  # salto de línea tras la barra

    # Ordenar por puerto
    resultados.sort(key=lambda r: r.puerto)
    duracion = time.time() - inicio
    return resultados, duracion


def progress_bar(actual: int, total: int, width: int = 20) -> str:
    """Devuelve una barra de progreso simple."""
    llenos = int(width * actual / max(total, 1))
    return "█" * llenos + "░" * (width - llenos)


def ports_from_range(start: int, end: int) -> List[int]:
    if start > end:
        start, end = end, start
    start = max(1, start)
    end = min(65535, end)
    return list(range(start, end + 1))


def parse_ports(ports_str: str) -> List[int]:
    """
    Interpreta -p como:
      80            -> puerto único
      1-1024        -> rango
      22,80,443     -> lista
      1-100,8080    -> mixto
    """
    puertos: List[int] = []
    for parte in ports_str.split(","):
        parte = parte.strip()
        if not parte:
            continue
        if "-" in parte:
            a, b = parte.split("-", 1)
            puertos.extend(range(int(a), int(b) + 1))
        else:
            puertos.append(int(parte))
    # Eliminar duplicados y ordenar
    return sorted(set(puertos))


# ---------------------------------------------------------------------------
# Exportación
# ---------------------------------------------------------------------------

def exportar(reporte: Reporte, path: Path) -> None:
    """Guarda el reporte en CSV, JSON o HTML según la extensión."""
    sufijo = path.suffix.lower()
    if sufijo == ".json":
        _exportar_json(reporte, path)
    elif sufijo == ".html":
        _exportar_html(reporte, path)
    else:
        _exportar_csv(reporte, path)


def _exportar_csv(reporte: Reporte, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "ip", "protocolo", "puerto", "estado", "servicio"])
        w.writerow([reporte.host, reporte.ip, reporte.protocolo, "", "", ""])
        for r in reporte.resultados:
            w.writerow([reporte.host, reporte.ip, r.protocolo,
                        r.puerto, "abierto" if r.abierto else "cerrado",
                        r.servicio])
    print(msg(Colors.GREEN, f"Resultados guardados en: {path}"))


def _exportar_json(reporte: Reporte, path: Path) -> None:
    data = asdict(reporte)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(msg(Colors.GREEN, f"Resultados guardados en: {path}"))


def _exportar_html(reporte: Reporte, path: Path) -> None:
    """Genera un informe HTML bonito y compartible."""
    from html import escape
    
    abiertos = [r for r in reporte.resultados if r.abierto]
    cerrados = [r for r in reporte.resultados if not r.abierto]
    
    # Agrupar por host si hay múltiples
    hosts_data = {}
    for r in reporte.resultados:
        key = f"{reporte.host} ({reporte.ip})"
        if key not in hosts_data:
            hosts_data[key] = {"abiertos": [], "cerrados": []}
        if r.abierto:
            hosts_data[key]["abiertos"].append(r)
        else:
            hosts_data[key]["cerrados"].append(r)
    
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Informe PortScan - {escape(reporte.host)}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0f0f23 100%);
    color: #e8e8e8;
    margin: 0;
    padding: 40px 20px;
    min-height: 100vh;
  }}
  .container {{
    max-width: 900px;
    margin: 0 auto;
    background: rgba(20, 20, 40, 0.95);
    border-radius: 16px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255, 100, 100, 0.1);
    overflow: hidden;
    border: 1px solid rgba(255, 100, 100, 0.15);
  }}
  .header {{
    background: linear-gradient(90deg, #ff4444 0%, #ff6b6b 50%, #ff4444 100%);
    padding: 40px;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: url("data:image/svg+xml,%3Csvg viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cdefs%3E%3Cpattern id='grid' width='10' height='10' patternUnits='userSpaceOnUse'%3E%3Cpath d='M 10 0 L 0 0 0 10' fill='none' stroke='rgba(255,255,255,0.05)' stroke-width='0.5'/%3E%3C/pattern%3E%3C/defs%3E%3Crect width='100' height='100' fill='url(%23grid)'/%3E%3C/svg%3E");
    opacity: 0.5;
  }}
  .header h1 {{
    margin: 0;
    font-size: 2.5rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    position: relative;
    z-index: 1;
    text-shadow: 0 2px 10px rgba(0,0,0,0.3);
  }}
  .header .subtitle {{
    margin: 10px 0 0;
    font-size: 1.1rem;
    opacity: 0.9;
    font-weight: 300;
    position: relative;
    z-index: 1;
  }}
  .header .version {{
    display: inline-block;
    margin-top: 12px;
    padding: 6px 16px;
    background: rgba(255,255,255,0.15);
    border-radius: 20px;
    font-size: 0.85rem;
    font-weight: 600;
    position: relative;
    z-index: 1;
  }}
  .content {{ padding: 40px; }}
  .section {{
    margin-bottom: 40px;
    padding-bottom: 30px;
    border-bottom: 1px solid rgba(255, 100, 100, 0.1);
  }}
  .section:last-child {{ border-bottom: none; margin-bottom: 0; }}
  .section-title {{
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 1.3rem;
    font-weight: 600;
    color: #ff6b6b;
    margin-bottom: 20px;
  }}
  .section-title::before {{
    content: '';
    width: 4px;
    height: 24px;
    background: linear-gradient(180deg, #ff4444, #ff6b6b);
    border-radius: 2px;
  }}
  .info-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 8px;
  }}
  .info-card {{
    background: rgba(255, 68, 68, 0.08);
    border: 1px solid rgba(255, 68, 68, 0.15);
    border-radius: 10px;
    padding: 18px 20px;
    transition: transform 0.2s, box-shadow 0.2s;
  }}
  .info-card:hover {{
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(255, 68, 68, 0.15);
  }}
  .info-label {{
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #aaa;
    margin-bottom: 6px;
    font-weight: 600;
  }}
  .info-value {{
    font-size: 1.25rem;
    font-weight: 700;
    color: #fff;
    font-family: 'SF Mono', 'Fira Code', monospace;
  }}
  .info-value.open {{ color: #4ade80; }}
  .info-value.closed {{ color: #f87171; }}
  .info-value.duration {{ color: #fbbf24; }}
  .port-table {{ width: 100%; border-collapse: collapse; }}
  .port-table th {{
    text-align: left;
    padding: 14px 16px;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #888;
    font-weight: 600;
    border-bottom: 2px solid rgba(255, 68, 68, 0.2);
    background: rgba(255, 68, 68, 0.05);
  }}
  .port-table td {{
    padding: 14px 16px;
    border-bottom: 1px solid rgba(255, 68, 68, 0.08);
    font-size: 0.9rem;
  }}
  .port-table tr:last-child td {{ border-bottom: none; }}
  .port-table tr:hover td {{ background: rgba(255, 68, 68, 0.05); }}
  .port-table .port {{ font-family: 'SF Mono', 'Fira Code', monospace; font-weight: 600; }}
  .port-table .service {{ color: #bbb; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem; }}
  .status {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  .status.open {{ background: rgba(74, 222, 128, 0.15); color: #4ade80; }}
  .status.closed {{ background: rgba(248, 113, 113, 0.15); color: #f87171; }}
  .status::before {{
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
  }}
  .status.open::before {{ background: #4ade80; box-shadow: 0 0 8px #4ade80; }}
  .status.closed::before {{ background: #f87171; box-shadow: 0 0 8px #f87171; }}
  .empty-state {{
    text-align: center;
    padding: 40px;
    color: #666;
    font-style: italic;
  }}
  .empty-state svg {{ width: 48px; height: 48px; margin-bottom: 12px; opacity: 0.5; }}
  .tabs {{
    display: flex;
    gap: 4px;
    margin-bottom: 20px;
    background: rgba(255, 68, 68, 0.05);
    padding: 4px;
    border-radius: 8px;
  }}
  .tab {{
    flex: 1;
    padding: 12px 20px;
    border: none;
    background: transparent;
    color: #888;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    border-radius: 6px;
    transition: all 0.2s;
  }}
  .tab.active {{
    background: #ff4444;
    color: white;
    box-shadow: 0 2px 8px rgba(255, 68, 68, 0.3);
  }}
  .tab:not(.active):hover {{ color: #ccc; background: rgba(255, 255, 255, 0.03); }}
  .tab-panel {{ display: none; }}
  .tab-panel.active {{ display: block; animation: fadeIn 0.2s ease; }}
  @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(4px); }} to {{ opacity: 1; transform: translateY(0); }} }}
  .footer {{
    padding: 24px 40px;
    background: rgba(0, 0, 0, 0.2);
    text-align: center;
    font-size: 0.8rem;
    color: #666;
    border-top: 1px solid rgba(255, 68, 68, 0.1);
  }}
  .footer a {{ color: #ff6b6b; text-decoration: none; }}
  .footer a:hover {{ text-decoration: underline; }}
  @media print {{
    body {{ background: white; color: #333; }}
    .container {{ box-shadow: none; border: 1px solid #ddd; }}
    .header {{ background: #ff4444 !important; -webkit-print-color-adjust: exact; }}
    .info-card {{ border: 1px solid #ddd; background: #fafafa; }}
    .port-table th {{ background: #f0f0f0 !important; -webkit-print-color-adjust: exact; }}
  }}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔍 Informe de Escaneo PortScan</h1>
      <div class="subtitle">Análisis de puertos {escape(reporte.protocolo.upper())} — {escape(reporte.host)}</div>
      <div class="version">PortScan v{VERSION} · Generado el {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}</div>
    </div>
    
    <div class="content">
      <div class="section">
        <h2 class="section-title">Resumen del Escaneo</h2>
        <div class="info-grid">
          <div class="info-card">
            <div class="info-label">Host Objetivo</div>
            <div class="info-value">{escape(reporte.host)}</div>
          </div>
          <div class="info-card">
            <div class="info-label">Dirección IP</div>
            <div class="info-value">{escape(reporte.ip)}</div>
          </div>
          <div class="info-card">
            <div class="info-label">Protocolo</div>
            <div class="info-value">{escape(reporte.protocolo.upper())}</div>
          </div>
          <div class="info-card">
            <div class="info-label">Puertos Escaneados</div>
            <div class="info-value">{reporte.puertos_escaneados}</div>
          </div>
          <div class="info-card">
            <div class="info-label">Puertos Abiertos</div>
            <div class="info-value open">{len(abiertos)}</div>
          </div>
          <div class="info-card">
            <div class="info-label">Puertos Cerrados</div>
            <div class="info-value closed">{len(cerrados)}</div>
          </div>
          <div class="info-card">
            <div class="info-label">Duración</div>
            <div class="info-value duration">{reporte.duracion:.2f}s</div>
          </div>
          <div class="info-card">
            <div class="info-label">Inicio</div>
            <div class="info-value">{escape(reporte.inicio)}</div>
          </div>
        </div>
      </div>
      
      <div class="section">
        <h2 class="section-title">Puertos Abiertos ({len(abiertos)})</h2>
        {'<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><p>No se encontraron puertos abiertos</p></div>' if not abiertos else f'''
        <div class="tabs">
          <button class="tab active" onclick="showTab(this, 'abiertos')">Abiertos ({len(abiertos)})</button>
          <button class="tab" onclick="showTab(this, 'cerrados')">Cerrados ({len(cerrados)})</button>
        </div>
        <div class="tab-panel active" id="panel-abiertos">
          <table class="port-table">
            <thead>
              <tr>
                <th>Puerto</th>
                <th>Servicio</th>
                <th>Estado</th>
              </tr>
            </thead>
            <tbody>
              {''.join(f'<tr><td class="port">{r.puerto}</td><td class="service">{escape(r.servicio)}</td><td><span class="status open">Abierto</span></td></tr>' for r in abiertos)}
            </tbody>
          </table>
        </div>
        <div class="tab-panel" id="panel-cerrados">
          <table class="port-table">
            <thead>
              <tr>
                <th>Puerto</th>
                <th>Servicio</th>
                <th>Estado</th>
              </tr>
            </thead>
            <tbody>
              {''.join(f'<tr><td class="port">{r.puerto}</td><td class="service">{escape(r.servicio)}</td><td><span class="status closed">Cerrado</span></td></tr>' for r in cerrados[:500])}
              {'<tr><td colspan="3" style="text-align:center; color:#888; padding:20px;">... y ' + str(len(cerrados) - 500) + ' puertos cerrados más</td></tr>' if len(cerrados) > 500 else ''}
            </tbody>
          </table>
        </div>
        '''}
      </div>
    </div>
    
    <div class="footer">
      Generado por <strong>PortScan v{VERSION}</strong> — Escáner de puertos TCP/UDP profesional<br>
      <a href="https://github.com/gmolina75/PortScan" target="_blank">github.com/gmolina75/PortScan</a> · 
      Uso autorizado únicamente en redes propias o con permiso explícito
    </div>
  </div>
  
  <script>
    function showTab(btn, panelId) {{
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('panel-' + panelId).classList.add('active');
    }}
  </script>
</body>
</html>
"""
    with path.open("w", encoding="utf-8") as f:
        f.write(html)
    print(msg(Colors.GREEN, f"Informe HTML guardado en: {path}"))


def nombre_archivo_auto(host: str, protocolo: str) -> Path:
    seguro = host.replace(".", "_").replace(":", "_")[:40]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"scan_{seguro}_{protocolo}_{ts}.json")


# ---------------------------------------------------------------------------
# Resumen
# ---------------------------------------------------------------------------

def imprimir_resumen(reporte: Reporte, quiet: bool = False) -> None:
    abiertos = [r for r in reporte.resultados if r.abierto]
    print()
    print(msg(Colors.MAGENTA, "═" * 50))
    print(msg(Colors.MAGENTA, f" Escaneo finalizado: {reporte.host} ({reporte.ip})"))
    print(msg(Colors.MAGENTA, "═" * 50))
    print(f"  Protocolo:          {reporte.protocolo.upper()}")
    print(f"  Puertos escaneados: {reporte.puertos_escaneados}")
    print(f"  Puertos abiertos:   {len(abiertos)}")
    print(f"  Duración:           {reporte.duracion:.2f}s")
    print(f"  Inicio:             {reporte.inicio}")
    if abiertos and not quiet:
        print(msg(Colors.GREEN, "  Puertos abiertos:"))
        for r in abiertos:
            print(f"    {msg(Colors.GREEN, '●')} {r.puerto:<6} {r.servicio}")
    print()


# ---------------------------------------------------------------------------
# Modos
# ---------------------------------------------------------------------------

def _input(prompt: str, default: Optional[str] = None) -> str:
    """input con valor por defecto y manejo de Ctrl+C/EOF."""
    suf = f" [{default}]" if default else ""
    try:
        v = input(prompt + suf + " ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nSaliendo...")
        sys.exit(0)
    return v or (default or "")


def interactive_mode() -> None:
    banner()
    while True:
        print(msg(Colors.RED, "Opciones:"))
        print(f"  {msg(Colors.GREEN, '[1]')} Escanear puertos")
        print(f"  {msg(Colors.GREEN, '[2]')} Ver presets disponibles")
        print(f"  {msg(Colors.GREEN, '[3]')} Salir")
        opcion = _input(f"\n{msg(Colors.YELLOW, '▬▶')} Elige una opción")

        if opcion == "1":
            _escaneo_interactivo()
            if _input(msg(Colors.RED, "¿Desea hacer otro escaneo? (s/n)"), "n") != "s":
                break
        elif opcion == "2":
            print("\nPresets disponibles:")
            for nombre, lista in PRESETS.items():
                print(f"  {msg(Colors.CYAN, nombre):<10} ({len(lista)} puertos)")
        elif opcion == "3":
            print("Saliendo...")
            sys.exit(0)
        else:
            print(msg(Colors.RED, "Opción inválida"))
            time.sleep(1)


def _escaneo_interactivo() -> None:
    try:
        host = _input(f"\n{msg(Colors.RED, 'Digite un host (IP o dominio): ')}, "
                      "requiere al menos 1 carácter").strip()
        if not host:
            raise ValueError("Host no puede estar vacío")
        ip, ip_version = resolve_host(host)
        print(f"{msg(Colors.RED, 'Detectado IP ▬▶')} {msg(Colors.CYAN, ip)} "
              f"(IPv{ip_version})\n")

        proto = _input(msg(Colors.RED, "Protocolo (tcp/udp)"), "tcp").lower()
        if proto not in ("tcp", "udp"):
            print(msg(Colors.YELLOW, "Protocolo no reconocido, usando tcp"))
            proto = "tcp"

        preset = _input(msg(Colors.RED, "Preset (comunes/web/bases/admin o vacío): ")).lower()
        if preset in PRESETS:
            puertos = PRESETS[preset]
            print(msg(Colors.CYAN, f"Usando preset '{preset}': {len(puertos)} puertos"))
        else:
            pi = _input(msg(Colors.RED, "Puerto inicial (ej: 80)"), "80")
            pf = _input(msg(Colors.RED, "Puerto final (ej: 443)"), "443")
            try:
                pi_i, pf_i = int(pi), int(pf)
            except ValueError:
                print(msg(Colors.RED, "Puerto inicial/final inválido, usando 80-443"))
                pi_i, pf_i = 80, 443
            puertos = ports_from_range(pi_i, pf_i)

        timeout = _input(msg(Colors.RED, "Timeout en segundos"), "1")
        try:
            timeout_f = float(timeout)
        except ValueError:
            timeout_f = 1.0

        workers = _input(msg(Colors.RED, "Hilos paralelos"), "100")
        try:
            workers_i = max(1, int(workers))
        except ValueError:
            workers_i = 100

        print(f"\n{msg(Colors.YELLOW, 'Iniciando el escaneamiento')} "
              f"{msg(Colors.GREEN, '...')}\n")
        resultados, duracion = scan(
            ip, puertos, timeout=timeout_f, workers=workers_i,
            protocolo=proto, ip_version=ip_version
        )
        reporte = Reporte(
            host=host, ip=ip, protocolo=proto,
            inicio=datetime.now().isoformat(timespec="seconds"),
            duracion=duracion, puertos_escaneados=len(puertos),
            puertos_abiertos=sum(1 for r in resultados if r.abierto),
            resultados=resultados,
        )
        imprimir_resumen(reporte)

        guardar = _input(msg(Colors.RED, "¿Guardar resultados? (s/n)"), "s")
        if guardar.lower() == "s":
            fmt = _input(msg(Colors.RED, "Formato (json/csv/html)"), "html").lower()
            if fmt not in ("json", "csv", "html"):
                fmt = "html"
            nombre = nombre_archivo_auto(host, proto)
            if fmt == "csv":
                nombre = Path(str(nombre).replace(".json", ".csv"))
            elif fmt == "html":
                nombre = Path(str(nombre).replace(".json", ".html"))
            exportar(reporte, nombre)
    except ValueError as ve:
        print(msg(Colors.RED, str(ve)))
        time.sleep(1)
    except KeyboardInterrupt:
        print("\nEscaneo interrumpido por el usuario.")


def cli_mode(args: argparse.Namespace) -> None:
    try:
        puertos = parse_ports(args.ports)
        if not puertos:
            print(msg(Colors.RED, "Lista de puertos vacía"), file=sys.stderr)
            sys.exit(1)
        hosts = [h.strip() for h in args.host.split(",") if h.strip()]
        for host in hosts:
            ip, ip_version = resolve_host(host)
            print(f"{msg(Colors.CYAN, 'Escaneando')} {host} -> {ip} "
                  f"(IPv{ip_version}, {args.proto.upper()}, {len(puertos)} puertos)")
            resultados, duracion = scan(
                ip, puertos, timeout=args.timeout, workers=args.workers,
                protocolo=args.proto, ip_version=ip_version,
                quiet=args.quiet
            )
            reporte = Reporte(
                host=host, ip=ip, protocolo=args.proto,
                inicio=datetime.now().isoformat(timespec="seconds"),
                duracion=duracion, puertos_escaneados=len(puertos),
                puertos_abiertos=sum(1 for r in resultados if r.abierto),
                resultados=resultados,
            )
            imprimir_resumen(reporte, quiet=args.quiet)
            if args.output:
                exportar(reporte, Path(args.output))
    except ValueError as e:
        print(msg(Colors.RED, f"Error: {e}"), file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="PortScan - Escáner de puertos TCP/UDP en español",
        prog="portscan.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""ejemplos:
  python portscan.py -H 192.168.1.1 -p 1-1024
  python portscan.py -H google.com -p 22,80,443 --proto tcp -o resultados.csv
  python portscan.py -H 127.0.0.1 --preset comunes -o out.json
  python portscan.py -H [::1] -p 80 --proto udp -q""",
    )
    p.add_argument("-H", "--host", help="Host/IP o dominio (varios separados por coma)")
    p.add_argument("-p", "--ports", help="Rango 1-1024, único 80, lista 22,80,443 o mixto")
    p.add_argument("--preset", choices=list(PRESETS.keys()),
                   help="Usar preset de puertos (requiere -H)")
    p.add_argument("-t", "--timeout", type=float, default=1.0,
                   help="Timeout por conexión en segundos [1.0]")
    p.add_argument("-w", "--workers", type=int, default=100,
                   help="Hilos paralelos [100]")
    p.add_argument("--proto", choices=["tcp", "udp"], default="tcp",
                   help="Protocolo a escanear [tcp]")
    p.add_argument("-o", "--output", help="Archivo de salida (.csv, .json o .html)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Salida reducida: solo resumen de abiertos")
    p.add_argument("--no-progress", action="store_true",
                   help="Deshabilitar barra de progreso")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {VERSION}")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    if (args.host and (args.ports or args.preset)) or (args.ports or args.preset):
        banner()
        if not args.ports and args.preset:
            # Convertir preset en lista (se resuelve en cli_mode si no hay -p)
            args.ports = ",".join(map(str, PRESETS[args.preset]))
        if args.host:
            cli_mode(args)
        else:
            print(msg(Colors.RED, "Falta -H/--host"), file=sys.stderr)
            sys.exit(1)
    else:
        interactive_mode()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrumpido por el usuario.")
        sys.exit(130)
