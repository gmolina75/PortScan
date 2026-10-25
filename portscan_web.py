#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortScan Web - Interfaz web headless (Flask) para PortScan

Uso:
  python portscan_web.py
  Abre http://localhost:5000 en el navegador
  o realiza peticiones POST directamente a http://localhost:5000
"""

import io
import sys
from datetime import datetime
from typing import List

from flask import Flask, render_template_string, request

# Forzar codificación UTF-8 para evitar problemas en Windows
try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass

# Importar la lógica central de portscan
from portscan import (
    resolve_host, scan, parse_ports, Reporte, PRESETS,
    ip_local, ip_publica, ips_en_red
)

app = Flask(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PortScan Web</title>
<style>
  body { font-family: Arial, sans-serif; background: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
  .container { max-width: 700px; margin: 0 auto; background: #1e1e1e; padding: 25px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.5); }
  h1 { color: #1e90ff; margin-top: 0; }
  .disclaimer { background: #332b00; color: #ffd700; padding: 10px; border-radius: 4px; font-size: 0.9em; margin-bottom: 20px; border-left: 4px solid #ffd700; }
  .ips { background: #1a3a1a; border: 1px solid #4caf50; padding: 12px; border-radius: 6px; margin-bottom: 20px; font-size: 0.9em; }
  .ips span { color: #81c784; font-weight: bold; }
  .ips .label { color: #bbb; }
  label { display: block; margin-top: 15px; font-weight: bold; color: #bbb; }
  input, select { width: 100%; padding: 10px; margin-top: 5px; box-sizing: border-box; background: #2d2d2d; color: #fff; border: 1px solid #444; border-radius: 4px; }
  input:focus, select:focus { border-color: #1e90ff; outline: none; }
  .row { display: flex; gap: 15px; }
  .col { flex: 1; }
  button { background: #1e90ff; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; margin-top: 20px; width: 100%; font-weight: bold; }
  button:hover { background: #0066cc; }
  button.secondary { background: #555; }
  button.secondary:hover { background: #666; }
  #result { margin-top: 25px; background: #0d0d0d; padding: 15px; border-radius: 6px; font-family: monospace; white-space: pre-wrap; word-break: break-all; border: 1px solid #333; max-height: 500px; overflow-y: auto; }
  .port-open { color: #51cf66; }
  .port-closed { color: #ff6b6b; }
  .info { color: #4dabf7; }
  .warn { color: #ffd435; }
</style>
</head>
<body>
  <div class="container">
    <h1>PortScan Web v2.0</h1>
    <div class="disclaimer">
      ⚠️ <strong>Uso Autorizado:</strong> Utilice esta herramienta únicamente en redes y sistemas propios o con autorización explícita por escrito.
    </div>

    <div class="ips">
      <span class="label">IP Local:</span> <span id="ip-local">{{ ip_local or 'Detectando...' }}</span><br>
      <span class="label">IP Pública:</span> <span id="ip-publica">{{ ip_publica or 'Detectando...' }}</span>
    </div>

    <form method="POST" action="/">
      <label>Host / IP (separados por coma para múltiples):</label>
      <input name="host" placeholder="ej. 192.168.1.1, google.com" value="{{ request.form.get('host', '') }}">

      <div class="row">
        <div class="col">
          <label>Puertos (rango, puerto único o lista):</label>
          <input name="ports" placeholder="ej. 1-1024 o 22,80,443" value="{{ request.form.get('ports', '') }}">
        </div>
        <div class="col">
          <label>O Seleccionar Preset:</label>
          <select name="preset">
            <option value="">-- Ninguno --</option>
            {% for p in presets %}
              <option value="{{ p }}" {% if request.form.get('preset') == p %}selected{% endif %}>{{ p }}</option>
            {% endfor %}
          </select>
        </div>
      </div>

      <div class="row">
        <div class="col">
          <label>Protocolo:</label>
          <select name="proto">
            <option value="tcp" {% if request.form.get('proto') == 'tcp' %}selected{% endif %}>TCP</option>
            <option value="udp" {% if request.form.get('proto') == 'udp' %}selected{% endif %}>UDP</option>
          </select>
        </div>
        <div class="col">
          <label>Timeout (seg):</label>
          <input name="timeout" type="number" step="0.1" value="{{ request.form.get('timeout', '1.0') }}">
        </div>
        <div class="col">
          <label>Hilos (Workers):</label>
          <input name="workers" type="number" value="{{ request.form.get('workers', '100') }}">
        </div>
      </div>

      <div class="row">
        <div class="col">
          <label>Formato de Salida:</label>
          <select name="output">
            <option value="text" {% if request.form.get('output') == 'text' %}selected{% endif %}>Resumen Texto</option>
            <option value="json" {% if request.form.get('output') == 'json' %}selected{% endif %}>JSON Completo</option>
            <option value="csv" {% if request.form.get('output') == 'csv' %}selected{% endif %}>CSV</option>
          </select>
        </div>
      </div>

      <button type="submit">Iniciar Escaneo</button>
    </form>

    {% if result %}
      <div id="result">{{ result | safe }}</div>
    {% endif %}
  </div>
</body>
</html>
"""

@app.route("/detectar", methods=["GET"])
def detectar():
    """Endpoint para detectar IPs local y pública."""
    import json
    return json.dumps({
        "ip_local": ip_local(),
        "ip_publica": ip_publica()
    }, ensure_ascii=False)


@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    # Detectar IPs al cargar la página
    ip_local_val = ip_local()
    ip_publica_val = ip_publica()

    if request.method == "POST":
        host_input = request.form.get("host", "").strip()
        ports_input = request.form.get("ports", "").strip()
        preset_input = request.form.get("preset", "").strip()
        proto = request.form.get("proto", "tcp").lower()

        try:
            timeout = float(request.form.get("timeout", "1.0"))
        except ValueError:
            timeout = 1.0

        try:
            workers = int(request.form.get("workers", "100"))
        except ValueError:
            workers = 100

        output_fmt = request.form.get("output", "text")

        try:
            # Determinación de puertos
            if preset_input and preset_input in PRESETS:
                puertos = PRESETS[preset_input]
            elif ports_input:
                puertos = parse_ports(ports_input)
            else:
                puertos = parse_ports("1-1024")

            hosts_raw = [h.strip() for h in host_input.split(",") if h.strip()]

            # Detectar si es un rango de red (ej: 192.168.100.0)
            hosts = []
            red_info = ""
            for h in hosts_raw:
                if h.endswith(".0") and h.count(".") == 3:
                    try:
                        red_ips = ips_en_red(h)
                        hosts.extend(red_ips)
                        red_info += f"\n<i class='info'>Red detectada: {h} → escaneando {len(red_ips)} IPs (.1-.254)</i>\n"
                    except ValueError:
                        hosts.append(h)
                else:
                    hosts.append(h)

            output_buffer = []
            if red_info:
                output_buffer.append(red_info)

            total_hosts = len(hosts)
            for idx, h in enumerate(hosts, 1):
                try:
                    ip, ip_version = resolve_host(h)
                except ValueError:
                    output_buffer.append(f"<span class='port-closed'>[!] No se pudo resolver: {h}</span>")
                    continue

                if total_hosts > 1:
                    output_buffer.append(f"<span class='info'>[{idx}/{total_hosts}] Escaneando: {h} ({ip})</span>")

                resultados, duracion = scan(
                    ip, puertos, timeout=timeout, workers=workers,
                    protocolo=proto, ip_version=ip_version, quiet=True
                )

                reporte = Reporte(
                    host=h, ip=ip, protocolo=proto,
                    inicio=datetime.now().isoformat(timespec="seconds"),
                    duracion=duracion, puertos_escaneados=len(puertos),
                    puertos_abiertos=sum(1 for r in resultados if r.abierto),
                    resultados=resultados,
                )

                if output_fmt == "json":
                    import json
                    output_buffer.append(json.dumps(reporte.__dict__, indent=2, ensure_ascii=False, default=str))
                elif output_fmt == "csv":
                    import csv
                    import io as string_io
                    buf = string_io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(["host", "ip", "protocolo", "puerto", "estado", "servicio"])
                    for r in reporte.resultados:
                        w.writerow([reporte.host, reporte.ip, r.protocolo,
                                    r.puerto, "abierto" if r.abierto else "cerrado",
                                    r.servicio])
                    output_buffer.append(buf.getvalue())
                else:
                    # Formato texto con resaltado HTML
                    abiertos = [r for r in resultados if r.abierto]
                    res_text = f"=== Escaneo: {h} ({ip}) [IPv{ip_version}] ===\n"
                    res_text += f"Protocolo: {proto.upper()} | Escaneados: {len(puertos)} | Abiertos: {len(abiertos)} | Duración: {duracion:.2f}s\n\n"
                    if abiertos:
                        res_text += "Puertos Abiertos:\n"
                        for r in abiertos:
                            res_text += f"  <span class='port-open'>[+] Puerto {r.puerto:<5} ({r.servicio})</span>\n"
                    else:
                        res_text += "  No se encontraron puertos abiertos.\n"
                    output_buffer.append(res_text)

            result = "\n".join(output_buffer)

        except Exception as e:
            result = f"<span class='port-closed'>Error al ejecutar escaneo: {e}</span>"

    return render_template_string(HTML_TEMPLATE, result=result, presets=list(PRESETS.keys()),
                                  ip_local=ip_local_val, ip_publica=ip_publica_val)

if __name__ == "__main__":
    print("Iniciando PortScan Web Server en http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)