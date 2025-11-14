#!/usr/bin/env python3
import subprocess
import json
import threading
import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Хранилище результатов сканирований
scan_results = {}

def run_nmap(target):
    """Запуск Nmap сканирования"""
    try:
        print(f"[+] Запуск Nmap для {target}")
        # Быстрое сканирование портов и определение версий
        result = subprocess.run([
            'nmap', '-sS', '-sV', '--open', '-T4', 
            '-oX', '-',  # вывод в XML формате в stdout
            target
        ], capture_output=True, text=True, timeout=300)
        
        return {
            'success': True,
            'output': result.stdout,
            'error': result.stderr
        }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Nmap timeout'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def run_nikto(target, port=80):
    """Запуск Nikto для веб-сканирования"""
    try:
        print(f"[+] Запуск Nikto для {target}:{port}")
        url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
        
        result = subprocess.run([
            'nikto', '-h', url,
            '-o', '-',  # вывод в stdout
            '-Format', 'txt'
        ], capture_output=True, text=True, timeout=600)
        
        return {
            'success': True,
            'output': result.stdout,
            'error': result.stderr
        }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Nikto timeout'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def run_gobuster(target, port=80, wordlist='/usr/share/wordlists/dirb/common.txt'):
    """Запуск Gobuster для поиска директорий"""
    try:
        print(f"[+] Запуск Gobuster для {target}:{port}")
        url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
        
        # Используем упрощенную версию если стандартная wordlist не доступна
        result = subprocess.run([
            'gobuster', 'dir', '-u', url, '-w', wordlist,
            '-o', '-',  # вывод в stdout
            '-q'  # тихий режим
        ], capture_output=True, text=True, timeout=300)
        
        # Если wordlist не найдена, используем минимальный набор
        if "no such file" in result.stderr.lower():
            # Создаем минимальную wordlist на лету
            minimal_words = ["admin", "login", "uploads", "images", "css", "js", "api"]
            temp_wordlist = "/tmp/minimal_wordlist.txt"
            with open(temp_wordlist, 'w') as f:
                for word in minimal_words:
                    f.write(word + '\n')
            
            result = subprocess.run([
                'gobuster', 'dir', '-u', url, '-w', temp_wordlist,
                '-o', '-', '-q'
            ], capture_output=True, text=True, timeout=300)
            
            # Удаляем временный файл
            os.unlink(temp_wordlist)
        
        return {
            'success': True,
            'output': result.stdout,
            'error': result.stderr
        }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Gobuster timeout'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def parse_nmap_xml(xml_output):
    """Парсим XML вывод Nmap для извлечения информации о портах"""
    try:
        import xml.etree.ElementTree as ET
        
        root = ET.fromstring(xml_output)
        ports_info = []
        
        for host in root.findall('host'):
            for ports in host.findall('ports'):
                for port in ports.findall('port'):
                    port_id = port.get('portid')
                    state = port.find('state').get('state') if port.find('state') is not None else 'unknown'
                    
                    service_info = {
                        'port': port_id,
                        'state': state,
                        'service': 'unknown',
                        'version': 'unknown'
                    }
                    
                    service = port.find('service')
                    if service is not None:
                        service_info['service'] = service.get('name', 'unknown')
                        service_info['version'] = service.get('product', 'unknown')
                        if service.get('version'):
                            service_info['version'] += ' ' + service.get('version')
                    
                    ports_info.append(service_info)
        
        return ports_info
    except Exception as e:
        print(f"Ошибка парсинга Nmap XML: {e}")
        return []

def scan_target(target):
    """Основная функция сканирования"""
    scan_id = f"{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    scan_data = {
        'id': scan_id,
        'target': target,
        'status': 'running',
        'start_time': datetime.now().isoformat(),
        'results': {}
    }
    
    # Сохраняем в глобальное хранилище
    scan_results[scan_id] = scan_data
    
    try:
        # Шаг 1: Nmap сканирование
        nmap_result = run_nmap(target)
        if nmap_result['success']:
            scan_data['results']['nmap'] = {
                'raw_output': nmap_result['output'],
                'parsed_ports': parse_nmap_xml(nmap_result['output'])
            }
            
            # Шаг 2: Проверяем веб-порты и запускаем дополнительные инструменты
            web_ports = []
            for port_info in scan_data['results']['nmap']['parsed_ports']:
                if port_info['state'] == 'open':
                    port_num = int(port_info['port'])
                    if port_num in [80, 443, 8080, 8443]:
                        web_ports.append(port_num)
            
            # Для первого найденного веб-порта запускаем Nikto и Gobuster
            if web_ports:
                first_web_port = web_ports[0]
                
                # Запускаем Nikto
                nikto_result = run_nikto(target, first_web_port)
                if nikto_result['success']:
                    scan_data['results']['nikto'] = {
                        'port': first_web_port,
                        'output': nikto_result['output']
                    }
                
                # Запускаем Gobuster
                gobuster_result = run_gobuster(target, first_web_port)
                if gobuster_result['success']:
                    scan_data['results']['gobuster'] = {
                        'port': first_web_port,
                        'output': gobuster_result['output']
                    }
        
        scan_data['status'] = 'completed'
        scan_data['end_time'] = datetime.now().isoformat()
        
    except Exception as e:
        scan_data['status'] = 'error'
        scan_data['error'] = str(e)
        scan_data['end_time'] = datetime.now().isoformat()

@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """API endpoint для запуска сканирования"""
    data = request.json
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Запускаем сканирование в отдельном потоке
    thread = threading.Thread(target=scan_target, args=(target,))
    thread.daemon = True
    thread.start()
    
    # Находим ID сканирования (последний добавленный для этого target)
    scan_id = None
    for sid, scan_data in scan_results.items():
        if scan_data['target'] == target and scan_data['status'] == 'running':
            scan_id = sid
            break
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'target': target
    })

@app.route('/api/scan/<scan_id>')
def get_scan_status(scan_id):
    """API endpoint для получения статуса сканирования"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/api/scans')
def list_scans():
    """API endpoint для списка всех сканирований"""
    return jsonify({
        'scans': list(scan_results.values())
    })

@app.route('/report/<scan_id>')
def view_report(scan_id):
    """Страница с отчетом по сканированию"""
    if scan_id not in scan_results:
        return "Report not found", 404
    
    return render_template('report.html', scan=scan_results[scan_id])

if __name__ == '__main__':
    # Создаем папку для шаблонов если её нет
    os.makedirs('templates', exist_ok=True)
    
    # Создаем базовые HTML шаблоны
    with open('templates/index.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Pentest Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .form-group { margin: 20px 0; }
        input[type="text"] { padding: 10px; width: 300px; }
        button { padding: 10px 20px; background: #007cba; color: white; border: none; cursor: pointer; }
        button:hover { background: #005a87; }
        .results { margin-top: 20px; padding: 20px; border: 1px solid #ddd; }
        .status { padding: 10px; margin: 10px 0; }
        .running { background: #fff3cd; }
        .completed { background: #d1ecf1; }
        .error { background: #f8d7da; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Pentest Scanner</h1>
        
        <div class="form-group">
            <input type="text" id="target" placeholder="Введите IP или домен (example.com)" />
            <button onclick="startScan()">Начать сканирование</button>
        </div>
        
        <div id="results"></div>
        
        <h2>История сканирований</h2>
        <div id="scanList"></div>
    </div>

    <script>
        function startScan() {
            const target = document.getElementById('target').value;
            if (!target) return alert('Введите target');
            
            fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target })
            })
            .then(r => r.json())
            .then(data => {
                if (data.scan_id) {
                    checkStatus(data.scan_id);
                }
            });
        }
        
        function checkStatus(scanId) {
            const resultsDiv = document.getElementById('results');
            
            function poll() {
                fetch('/api/scan/' + scanId)
                    .then(r => r.json())
                    .then(scan => {
                        let html = `<div class="status ${scan.status}">
                            <h3>Сканирование: ${scan.target}</h3>
                            <p>Статус: ${scan.status}</p>
                            <p>Время начала: ${scan.start_time}</p>`;
                        
                        if (scan.status === 'completed') {
                            html += `<p>Время завершения: ${scan.end_time}</p>`;
                            html += `<p><a href="/report/${scanId}" target="_blank">Посмотреть полный отчет</a></p>`;
                            
                            // Быстрый предпросмотр
                            if (scan.results.nmap) {
                                html += `<h4>Nmap результаты:</h4>`;
                                html += `<pre>${JSON.stringify(scan.results.nmap.parsed_ports, null, 2)}</pre>`;
                            }
                            if (scan.results.nikto) {
                                html += `<h4>Nikto результаты (порт ${scan.results.nikto.port}):</h4>`;
                                html += `<pre>${scan.results.nikto.output.substring(0, 500)}...</pre>`;
                            }
                        } else if (scan.status === 'running') {
                            html += `<p>Сканирование выполняется... (обновление через 3 секунды)</p>`;
                            setTimeout(poll, 3000);
                        }
                        
                        html += `</div>`;
                        resultsDiv.innerHTML = html;
                    });
            }
            
            poll();
        }
        
        // Загружаем список сканирований
        fetch('/api/scans')
            .then(r => r.json())
            .then(data => {
                const listDiv = document.getElementById('scanList');
                if (data.scans.length === 0) {
                    listDiv.innerHTML = '<p>Нет завершенных сканирований</p>';
                } else {
                    let html = '<ul>';
                    data.scans.forEach(scan => {
                        html += `<li><a href="/report/${scan.id}">${scan.target} - ${scan.status} (${scan.start_time})</a></li>`;
                    });
                    html += '</ul>';
                    listDiv.innerHTML = html;
                }
            });
    </script>
</body>
</html>''')

    with open('templates/report.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Отчет сканирования - {{ scan.target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; }
        pre { background: #f5f5f5; padding: 15px; overflow: auto; }
        .port { margin: 10px 0; padding: 10px; background: #f9f9f9; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Отчет сканирования: {{ scan.target }}</h1>
        <p><strong>Статус:</strong> {{ scan.status }}</p>
        <p><strong>Время начала:</strong> {{ scan.start_time }}</p>
        {% if scan.end_time %}
        <p><strong>Время завершения:</strong> {{ scan.end_time }}</p>
        {% endif %}
        
        {% if scan.results.nmap %}
        <div class="section">
            <h2>Nmap Результаты</h2>
            <h3>Открытые порты:</h3>
            {% for port in scan.results.nmap.parsed_ports %}
            <div class="port">
                <strong>Порт {{ port.port }} ({{ port.service }})</strong> - {{ port.state }}<br>
                Версия: {{ port.version }}
            </div>
            {% endfor %}
            
            <h3>Полный вывод Nmap:</h3>
            <pre>{{ scan.results.nmap.raw_output }}</pre>
        </div>
        {% endif %}
        
        {% if scan.results.nikto %}
        <div class="section">
            <h2>Nikto Результаты (порт {{ scan.results.nikto.port }})</h2>
            <pre>{{ scan.results.nikto.output }}</pre>
        </div>
        {% endif %}
        
        {% if scan.results.gobuster %}
        <div class="section">
            <h2>Gobuster Результаты (порт {{ scan.results.gobuster.port }})</h2>
            <pre>{{ scan.results.gobuster.output }}</pre>
        </div>
        {% endif %}
        
        <a href="/">Вернуться к сканеру</a>
    </div>
</body>
</html>''')

    print("Запуск Flask сервера на http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)