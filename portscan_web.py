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
import os
import tempfile
from datetime import datetime
from typing import List
from pathlib import Path

from flask import Flask, render_template_string, request, Response

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
  .quick-actions { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
  .quick-actions button { background: rgba(255, 68, 68, 0.15); color: #ff6b6b; padding: 6px 12px; border: 1px solid rgba(255, 68, 68, 0.3); border-radius: 4px; cursor: pointer; font-size: 0.8em; transition: all 0.2s; }
  .quick-actions button:hover { background: rgba(255, 68, 68, 0.25); border-color: #ff4444; }
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

    <form method="POST" action="/" id="scanForm">
      <label>Host / IP / Red:</label>
      <input name="host" id="hostInput" placeholder="ej. 192.168.1.1, 192.168.100.0/24, google.com" value="{{ request.form.get('host', '') }}">
      <div class="quick-actions">
        <button type="button" onclick="setNetwork('192.168.100.0/24')">🌐 Red Local /24 (254 IPs)</button>
        <button type="button" onclick="setNetwork('192.168.1.0/24')">🏠 Red 192.168.1.0/24</button>
        <button type="button" onclick="setNetwork('10.0.0.0/24')">🏢 Red 10.0.0.0/24</button>
        <button type="button" onclick="setNetwork('172.16.0.0/24')">🔒 Red 172.16.0.0/24</button>
      </div>

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
            <option value="html" {% if request.form.get('output') == 'html' %}selected{% endif %}>Informe HTML</option>
          </select>
        </div>
      </div>

      <button type="submit">Iniciar Escaneo</button>
    </form>

    {% if result %}
      <div id="result">{{ result | safe }}</div>
    {% endif %}
  </div>
  
  <script>
    function setNetwork(cidr) {
      document.getElementById('hostInput').value = cidr;
      // Auto-ajustar configuración para escaneo de red
      if (!document.querySelector('input[name="ports"]').value) {
        document.querySelector('input[name="ports"]').value = '22,80,443,8080';
      }
      if (!document.querySelector('input[name="timeout"]').value || parseFloat(document.querySelector('input[name="timeout"]').value) > 0.5) {
        document.querySelector('input[name="timeout"]').value = '0.3';
      }
      if (!document.querySelector('input[name="workers"]').value || parseInt(document.querySelector('input[name="workers"]').value) < 50) {
        document.querySelector('input[name="workers"]').value = '100';
      }
    }

    // Streaming en tiempo real con Server-Sent Events
    async function scanStream() {
      const form = document.getElementById('scanForm');
      const formData = new FormData(form);
      const params = new URLSearchParams();
      for (const [key, value] of formData.entries()) {
        params.append(key, value);
      }
      
      const resultDiv = document.getElementById('result');
      resultDiv.innerHTML = '<span class="info">Iniciando escaneo en tiempo real...</span>';
      
      const eventSource = new EventSource('/scan-stream?' + params.toString());
      
      eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        if (data.type === 'progress') {
          resultDiv.innerHTML += data.html + '\n';
          resultDiv.scrollTop = resultDiv.scrollHeight;
        } else if (data.type === 'complete') {
          resultDiv.innerHTML = data.html;
          eventSource.close();
        } else if (data.type === 'error') {
          resultDiv.innerHTML += '<span class="port-closed">Error: ' + data.message + '</span>';
          eventSource.close();
        }
      };
      
      eventSource.onerror = function(err) {
        resultDiv.innerHTML += '<span class="port-closed">Conexión interrumpida</span>';
        eventSource.close();
      };
    }

    // Interceptar el form submit para usar streaming
    document.getElementById('scanForm').addEventListener('submit', function(e) {
      const outputFmt = document.querySelector('select[name="output"]').value;
      // Para HTML/CSV/JSON como descarga, usar el método POST normal
      if (outputFmt !== 'text') {
        // Dejar que el formulario funcione normal (POST)
        return true;
      }
      // Para texto, usar streaming en tiempo real
      e.preventDefault();
      scanStream();
    });
  </script>
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


@app.route("/scan-stream")
def scan_stream():
    """Endpoint SSE (Server-Sent Events) para escaneo en tiempo real."""
    from flask import Response as FlaskResponse
    import json
    import urllib.parse

    # Obtener parámetros
    query = request.args
    host_input = urllib.parse.unquote(query.get("host", ""))
    ports_input = query.get("ports", "").strip()
    preset_input = query.get("preset", "").strip()
    proto = query.get("proto", "tcp").lower()

    try:
        timeout = float(query.get("timeout", "1.0"))
    except ValueError:
        timeout = 1.0

    try:
        workers = int(query.get("workers", "100"))
    except ValueError:
        workers = 100

    output_fmt = query.get("output", "text")

    def generate():
        try:
            # Determinar puertos
            if preset_input and preset_input in PRESETS:
                puertos = PRESETS[preset_input]
            elif ports_input:
                puertos = parse_ports(ports_input)
            else:
                puertos = parse_ports("1-1024")

            hosts_raw = [h.strip() for h in host_input.split(",") if h.strip()]

            # Detectar red CIDR
            network_cidr = None
            hosts = []
            red_info = ""
            import ipaddress

            for h in hosts_raw:
                if "/" in h:
                    try:
                        net = ipaddress.ip_network(h, strict=False)
                        network_cidr = net
                        hosts.extend([str(ip) for ip in net.hosts()])
                        red_info += f"<i class='info'>Red CIDR detectada: {h} → {len(list(net.hosts()))} hosts</i>"
                        break
                    except ValueError:
                        pass

            # Detectar red clásica (.0 al final)
            if not network_cidr:
                for h in hosts_raw:
                    if h.endswith(".0") and h.count(".") == 3:
                        try:
                            red_ips = ips_en_red(h)
                            hosts.extend(red_ips)
                            red_info += f"<i class='info'>Red detectada: {h} → escaneando {len(red_ips)} IPs (.1-.254)</i>"
                        except ValueError:
                            hosts.append(h)
                        break

            # Agregar hosts individuales
            for h in hosts_raw:
                if "/" not in h and not (h.endswith(".0") and h.count(".") == 3):
                    if h not in hosts and h:
                        hosts.append(h)

            if not hosts:
                yield f"data: {json.dumps({'type': 'error', 'message': 'No se especificaron hosts válidos'})}\n\n"
                return

            total_hosts = len(hosts)
            all_reportes = []
            abiertos_totales = []

            # Enviar info de la red
            if red_info:
                yield f"data: {json.dumps({'type': 'progress', 'html': red_info})}\n\n"

            # Escanear cada host
            for idx, h in enumerate(hosts, 1):
                try:
                    ip, ip_version = resolve_host(h)
                except ValueError:
                    msg = f"<span class='port-closed'>[!] No se pudo resolver: {h}</span>"
                    yield "data: " + json.dumps({'type': 'progress', 'html': msg}) + "\n\n"
                    continue

                if total_hosts > 1:
                    msg = f"<span class='info'>[{idx}/{total_hosts}] Escaneando: {h} ({ip})</span>"
                    yield "data: " + json.dumps({'type': 'progress', 'html': msg}) + "\n\n"

                resultados, duracion = scan(
                    ip, puertos, timeout=timeout, workers=workers,
                    protocolo=proto, ip_version=ip_version, quiet=True
                )

                abiertos = [r for r in resultados if r.abierto]
                for r in abiertos:
                    abiertos_totales.append(r)
                    html_msg = f"<span class='port-open'>[+] {h}:{r.puerto} ({r.servicio})</span>"
                    yield "data: " + json.dumps({'type': 'progress', 'html': html_msg}) + "\n\n"

                resumen = f"=== {h} ({ip}) [IPv{ip_version}] === "
                resumen += f"Abiertos: {len(abiertos)} | Duración: {duracion:.2f}s"
                yield "data: " + json.dumps({'type': 'progress', 'html': f"<span class='info'>{resumen}</span>"}) + "\n\n"

                reporte = Reporte(
                    host=h, ip=ip, protocolo=proto,
                    inicio=datetime.now().isoformat(timespec="seconds"),
                    duracion=duracion, puertos_escaneados=len(puertos),
                    puertos_abiertos=len(abiertos),
                    resultados=resultados,
                )
                all_reportes.append(reporte)

            # Enviar resumen final
            resumen_final = f"<div class='ips'>Escaneo completado: {total_hosts} hosts, {sum(len(r.resultados) for r in all_reportes)} puertos escaneados, {len(abiertos_totales)} puertos abiertos</div>"
            
            if output_fmt == "html" and total_hosts == 1 and all_reportes:
                # Exportar HTML completo
                from portscan import _exportar_html
                import tempfile
                import os
                with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode='w', encoding='utf-8') as tmp:
                    tmp_path = tmp.name
                try:
                    _exportar_html(all_reportes[0], Path(tmp_path))
                    with open(tmp_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    yield f"data: {json.dumps({'type': 'complete', 'html': html_content})}\n\n"
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
            elif output_fmt == "html" and total_hosts > 1:
                # Combinar HTML de todos los reportes
                from portscan import _exportar_html
                import tempfile
                import os
                combined = ""
                for rep in all_reportes:
                    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode='w', encoding='utf-8') as tmp:
                        tmp_path = tmp.name
                    try:
                        _exportar_html(rep, Path(tmp_path))
                        with open(tmp_path, 'r', encoding='utf-8') as f:
                            combined += f.read() + "\n<hr/>\n"
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                yield f"data: {json.dumps({'type': 'complete', 'html': combined})}\n\n"
            else:
                # Formato texto con todos los resultados
                output_html = resumen_final
                for rep in all_reportes:
                    abiertos = [r for r in rep.resultados if r.abierto]
                    output_html += f"\n<div class='port-open'>Puerto(es) abiertos en {rep.host} ({rep.ip}):</div>\n<ul>"
                    for r in abiertos:
                        output_html += f"<li class='port-open'>Puerto {r.puerto} ({r.servicio})</li>"
                    output_html += "</ul>"
                    if not abiertos:
                        output_html += f"<div>No se encontraron puertos abiertos en {rep.host}</div>"
                yield f"data: {json.dumps({'type': 'complete', 'html': output_html})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return FlaskResponse(generate(), mimetype='text/event-stream')


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

            # Detectar si es red con notación CIDR (ej: 192.168.100.0/24)
            network_cidr = None
            hosts = []
            red_info = ""
            for h in hosts_raw:
                if "/" in h:
                    try:
                        import ipaddress
                        net = ipaddress.ip_network(h, strict=False)
                        network_cidr = net
                        hosts.extend([str(ip) for ip in net.hosts()])
                        red_info += f"<i class='info'>Red CIDR detectada: {h} → {len(list(net.hosts()))} hosts</i>\n"
                        break
                    except ValueError:
                        pass

            # Si no es CIDR, verificar si es red clásica (.0 al final)
            if not network_cidr:
                for h in hosts_raw:
                    if h.endswith(".0") and h.count(".") == 3:
                        try:
                            red_ips = ips_en_red(h)
                            hosts.extend(red_ips)
                            red_info += f"<i class='info'>Red detectada: {h} → escaneando {len(red_ips)} IPs (.1-.254)</i>\n"
                        except ValueError:
                            hosts.append(h)
                        break

            # Agregar hosts que no son redes
            for h in hosts_raw:
                if "/" not in h and not (h.endswith(".0") and h.count(".") == 3):
                    if h not in hosts and h:
                        hosts.append(h)

            output_buffer = []
            if red_info:
                output_buffer.append(red_info)

            total_hosts = len(hosts)

            # Si es HTML y un solo host, devolver como descarga directa
            if output_fmt == "html" and total_hosts == 1:
                h = hosts[0]
                try:
                    ip, ip_version = resolve_host(h)
                except ValueError:
                    return f"<span class='port-closed'>Error: No se pudo resolver: {h}</span>", 400

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

                from flask import Response
                from portscan import _exportar_html
                import tempfile
                import os

                with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode='w', encoding='utf-8') as tmp:
                    tmp_path = tmp.name
                try:
                    _exportar_html(reporte, Path(tmp_path))
                    with open(tmp_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    return Response(
                        html_content,
                        mimetype='text/html',
                        headers={'Content-Disposition': f'attachment; filename="portscan_{h.replace(".", "_")}_{proto}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html"'}
                    )
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)

            # Para otros formatos o múltiples hosts
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
                elif output_fmt == "html":
                    # Para múltiples hosts, generar HTML y añadir al buffer
                    from portscan import _exportar_html
                    import tempfile
                    import os

                    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode='w', encoding='utf-8') as tmp:
                        tmp_path = tmp.name
                    try:
                        _exportar_html(reporte, Path(tmp_path))
                        with open(tmp_path, 'r', encoding='utf-8') as f:
                            html_content = f.read()
                        output_buffer.append(f"<!-- INFORME HTML PARA {h} -->\n{html_content}")
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
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