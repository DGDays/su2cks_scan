#!/usr/bin/env python3
import subprocess
import json
import threading
import os
import re
import pdfkit
import tempfile
import platform
from datetime import datetime
from flask import Flask, render_template, request, jsonify, make_response
import xml.etree.ElementTree as ET

app = Flask(__name__)

# Хранилище результатов сканирований
scan_results = {}

def find_wkhtmltopdf():
    """Автоматически находит путь к wkhtmltopdf"""
    # Список возможных путей для разных ОС
    possible_paths = []
    
    system = platform.system().lower()
    
    if system == 'windows':
        possible_paths = [
            r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\wkhtmltopdf\bin\wkhtmltopdf.exe',
            'wkhtmltopdf.exe'  # Если добавлен в PATH
        ]
    elif system == 'linux' or system == 'darwin':  # Linux или Mac
        possible_paths = [
            '/usr/bin/wkhtmltopdf',
            '/usr/local/bin/wkhtmltopdf',
            '/bin/wkhtmltopdf',
            '/opt/bin/wkhtmltopdf',
            'wkhtmltopdf'  # Если в PATH
        ]
    
    # Проверяем каждый путь
    for path in possible_paths:
        if os.path.exists(path):
            print(f"[+] Найден wkhtmltopdf: {path}")
            return path
    
    # Пробуем найти через which/where
    try:
        if system == 'windows':
            result = subprocess.run(['where', 'wkhtmltopdf'], 
                                  capture_output=True, text=True)
        else:
            result = subprocess.run(['which', 'wkhtmltopdf'], 
                                  capture_output=True, text=True)
        
        if result.returncode == 0:
            path = result.stdout.strip().split('\n')[0]
            print(f"[+] Найден wkhtmltopdf через which/where: {path}")
            return path
    except:
        pass
    
    # Если ничего не нашли
    print("[-] Wkhtmltopdf не найден. Установите его:")
    if system == 'windows':
        print("Скачайте с: https://wkhtmltopdf.org/downloads.html")
    else:
        print("sudo apt-get install wkhtmltopdf  # Ubuntu/Debian")
        print("brew install wkhtmltopdf          # MacOS")
    
    return None

# Конфигурация pdfkit с автопоиском
try:
    wkhtmltopdf_path = find_wkhtmltopdf()
    if wkhtmltopdf_path:
        PDF_CONFIG = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
        print("[+] PDF_CONFIG успешно инициализирован")
    else:
        PDF_CONFIG = None
        print("[-] Не удалось найти wkhtmltopdf, PDF экспорт недоступен")
except Exception as e:
    print(f"[-] Ошибка инициализации PDF_CONFIG: {e}")
    PDF_CONFIG = None


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
        
        # УБИРАЕМ -o - и используем только capture_output
        result = subprocess.run([
            'gobuster', 'dir', '-u', url, '-w', wordlist, '-q'
        ], capture_output=True, text=True, timeout=300)
        
        if "no such file" in result.stderr.lower():
            minimal_words = ["admin", "login", "uploads", "images", "css", "js", "api"]
            temp_wordlist = "/tmp/minimal_wordlist.txt"
            with open(temp_wordlist, 'w') as f:
                for word in minimal_words:
                    f.write(word + '\n')
            
            result = subprocess.run([
                'gobuster', 'dir', '-u', url, '-w', temp_wordlist, '-q'
            ], capture_output=True, text=True, timeout=300)
            
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
    
def run_arp_scan(network):
    try:
        # Запускаем nmap ARP ping scan
        result = subprocess.run([
            'nmap', '-sn', '-PR', network, '-oX', '-'
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0:
            return []
        
        # Парсим XML и извлекаем IP адреса
        ip_addresses = []
        root = ET.fromstring(result.stdout)
        
        for host in root.findall('host'):
            address_elem = host.find('address[@addrtype="ipv4"]')
            if address_elem is not None:
                ip = address_elem.get('addr')
                if ip:
                    ip_addresses.append(ip)
    except:
        ip_addresses = []

    return ip_addresses

def scan_target(target, scan_data):
    """Основная функция сканирования для одиночной цели"""
    try:
        # Nmap сканирование
        nmap_result = run_nmap(target)
        if nmap_result['success']:
            scan_data['results']['nmap'] = {
                'raw_output': nmap_result['output'],
                'parsed_ports': parse_nmap_xml(nmap_result['output'])
            }
            
            # Проверяем веб-порты и запускаем Nikto/Gobuster
            web_ports = []
            for port_info in scan_data['results']['nmap']['parsed_ports']:
                if port_info['state'] == 'open':
                    port_num = int(port_info['port'])
                    if port_num in [80, 443, 8080, 8443]:
                        web_ports.append(port_num)
            
            if web_ports:
                first_web_port = web_ports[0]
                scan_data['results']['nikto'] = {
                    'port': first_web_port,
                    'output': run_nikto(target, first_web_port)['output']
                }
                scan_data['results']['gobuster'] = {
                    'port': first_web_port,
                    'output': run_gobuster(target, first_web_port)['output']
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
    
    ip_mask_strict_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$'
    
    if bool(re.match(ip_mask_strict_pattern, target)):
        # ARP сканирование сети
        ips = run_arp_scan(target)
        
        # Сохраняем ARP сканирование в историю
        arp_scan_id = f"arp_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        arp_scan_data = {
            'id': arp_scan_id,
            'target': target,
            'type': 'arp_scan',
            'status': 'completed',
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat(),
            'results': {
                'hosts_found': len(ips),
                'hosts': ips,
                'network': target
            }
        }
        scan_results[arp_scan_id] = arp_scan_data
        
        return jsonify({
            'status': 'arp_completed',
            'arp': True,
            'scan_id': arp_scan_id,
            'network': target,
            'hosts_found': len(ips),
            'hosts': ips,
            'message': f'Найдено {len(ips)} хостов в сети {target}'
        })
    else:
        # Одиночное сканирование
        scan_id = f"{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        scan_data = {
            'id': scan_id,
            'target': target,
            'type': 'single_scan',
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'results': {}
        }
        
        scan_results[scan_id] = scan_data
        
        # Запускаем сканирование в отдельном потоке
        thread = threading.Thread(target=scan_target, args=(target, scan_data))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'arp': False,
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

@app.route('/arp_report/<scan_id>')
def view_arp_report(scan_id):
    """Страница с отчетом по ARP сканированию"""
    if scan_id not in scan_results:
        return "ARP report not found", 404
    
    scan_data = scan_results[scan_id]
    if scan_data.get('type') != 'arp_scan':
        return "This is not an ARP scan report", 400
    
    return render_template('arp_report.html', scan=scan_data)

@app.route('/save_as_pdf/<scan_id>')
def save_scan_as_pdf(scan_id):
    """Сохранение отчета сканирования в PDF"""
    if scan_id not in scan_results:
        return "Scan not found", 404
    
    scan_data = scan_results[scan_id]
    
    # Рендерим HTML для PDF
    if scan_data.get('type') == 'arp_scan':
        html_content = render_template('arp_report_pdf.html', scan=scan_data)
        filename = f"arp_scan_{scan_data['target']}.pdf"
    else:
        html_content = render_template('report_pdf.html', scan=scan_data)
        filename = f"scan_{scan_data['target']}.pdf"
    
    # Конвертируем в PDF
    try:
        pdf = pdfkit.from_string(html_content, False, configuration=PDF_CONFIG)
        
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return response
    except Exception as e:
        return f"Error generating PDF: {str(e)}", 500

@app.route('/save_dashboard_pdf')
def save_dashboard_pdf():
    """Сохранение главной страницы с историей в PDF"""
    # Получаем все сканирования для отображения в PDF
    all_scans = list(scan_results.values())
    
    # Загружаем ARP историю из localStorage (эмулируем)
    arp_history = []
    # В реальности нужно передавать через параметры или сессию
    
    html_content = render_template('dashboard_pdf.html', 
                                 scans=all_scans,
                                 arp_history=arp_history)
    
    try:
        pdf = pdfkit.from_string(html_content, False, configuration=PDF_CONFIG)
        
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=pentest_dashboard.pdf'
        return response
    except Exception as e:
        return f"Error generating PDF: {str(e)}", 500

# Новый endpoint для сохранения с передачей ARP истории
@app.route('/save_dashboard_with_arp', methods=['POST'])
def save_dashboard_with_arp():
    """Сохранение дашборда с переданной ARP историей"""
    data = request.json
    arp_history = data.get('arp_history', [])
    
    all_scans = list(scan_results.values())
    
    html_content = render_template('dashboard_pdf.html',
                                 scans=all_scans,
                                 arp_history=arp_history)
    
    try:
        pdf = pdfkit.from_string(html_content, False, configuration=PDF_CONFIG)
        
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=pentest_dashboard.pdf'
        return response
    except Exception as e:
        return f"Error generating PDF: {str(e)}", 500

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
        .arp-results { background: #e8f5e8; border: 2px solid #28a745; }
        .host-list { margin: 15px 0; }
        .host-item { 
            padding: 8px; 
            margin: 5px 0; 
            background: white; 
            border: 1px solid #ddd;
            border-radius: 4px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .scan-host-btn { 
            padding: 5px 10px; 
            background: #28a745; 
            color: white; 
            border: none; 
            border-radius: 3px;
            cursor: pointer;
            margin-left: 10px;
        }
        .scan-host-btn:hover { background: #218838; }
        .save-arp-btn { 
            padding: 8px 15px; 
            background: #6c757d; 
            color: white; 
            border: none; 
            border-radius: 3px;
            cursor: pointer;
            margin: 10px 0;
        }
        .save-arp-btn:hover { background: #545b62; }
        .arp-permanent { 
            background: #d4edda; 
            border-left: 4px solid #28a745;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Pentest Scanner</h1>
        
        <div class="form-group">
            <input type="text" id="target" placeholder="Введите IP, домен или сеть (192.168.1.0/24)" />
            <button onclick="startScan()">Начать сканирование</button>
        </div>
        
        <p><small>Примеры: example.com, 192.168.1.1, 192.168.1.0/24</small></p>
        
        <div id="results"></div>
        
        <h2>История сканирований</h2>
        <div id="scanList"></div>
        
        <!-- Постоянный блок для ARP результатов -->
        <div id="arpHistory" style="margin-top: 30px;"></div>
                    <button onclick="saveDashboardPdf()" style="padding: 10px 15px; background: #28a745; color: white; border: none; cursor: pointer; margin: 10px 0;">
    📊 Сохранить дашборд в PDF
</button>

<script>
function saveDashboardPdf() {
    // Передаем ARP историю на сервер
    fetch('/save_dashboard_with_arp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ arp_history: arpScans })
    })
    .then(response => response.blob())
    .then(blob => {
        // Скачиваем PDF
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'pentest_dashboard.pdf';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    })
    .catch(error => {
        console.error('Error saving dashboard:', error);
        alert('Ошибка при сохранении PDF');
    });
}
</script>
    </div>
            

    <script>
        // Глобальная переменная для хранения ARP результатов
        let arpScans = [];
        
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
                if (data.status === 'arp_completed') {
                    showArpResults(data);
                    // Сохраняем в историю ARP сканирований
                    saveArpToHistory(data);
                } else if (data.scan_id) {
                    checkStatus(data.scan_id);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                document.getElementById('results').innerHTML = 
                    '<div class="status error">Ошибка при запуске сканирования</div>';
            });
        }
        
        function showArpResults(data) {
            const resultsDiv = document.getElementById('results');
            let html = `<div class="status arp-results">
                <h3>🔍 ARP Сканирование завершено: ${data.network}</h3>
                <p>${data.message}</p>
                <button class="save-arp-btn" onclick="saveArpToHistory(${JSON.stringify(data).replace(/"/g, '&quot;')})">
                    💾 Сохранить это ARP сканирование
                </button>`;
            
            if (data.hosts && data.hosts.length > 0) {
                html += `<div class="host-list">
                    <h4>Найденные хосты:</h4>`;
                
                data.hosts.forEach(ip => {
                    html += `<div class="host-item">
                        <span>📡 ${ip}</span>
                        <div>
                            <button class="scan-host-btn" onclick="scanSingleHost('${ip}')">Сканировать</button>
                        </div>
                    </div>`;
                });
                
                html += `</div>`;
            } else {
                html += `<p>Хосты не найдены</p>`;
            }
            
            html += `</div>`;
            resultsDiv.innerHTML = html;
        }
        
        function saveArpToHistory(arpData) {
            // Добавляем timestamp для уникальности
            arpData.timestamp = new Date().toISOString();
            arpData.saved = true;
            
            // Добавляем в массив ARP сканирований
            arpScans.unshift(arpData);
            
            // Сохраняем в localStorage
            localStorage.setItem('arpScansHistory', JSON.stringify(arpScans));
            
            // Обновляем отображение истории ARP
            renderArpHistory();
            
            // Показываем сообщение
            showNotification('ARP сканирование сохранено в истории!');
        }
        
        function renderArpHistory() {
            const arpHistoryDiv = document.getElementById('arpHistory');
            
            if (arpScans.length === 0) {
                arpHistoryDiv.innerHTML = '';
                return;
            }
            
            let html = `<h2>💾 Сохраненные ARP сканирования</h2>`;
            
            arpScans.forEach((scan, index) => {
                html += `<div class="status arp-permanent">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h4>🔍 ${scan.network} (${scan.hosts_found} хостов)</h4>
                        <div>
                            <button class="scan-host-btn" onclick="loadArpScan(${index})">Показать</button>
                            <button class="scan-host-btn" style="background: #dc3545;" onclick="removeArpScan(${index})">Удалить</button>
                        </div>
                    </div>
                    <p>Сохранено: ${new Date(scan.timestamp).toLocaleString()}</p>
                </div>`;
            });
            
            arpHistoryDiv.innerHTML = html;
        }
        
        function loadArpScan(index) {
            const scan = arpScans[index];
            const resultsDiv = document.getElementById('results');
            
            let html = `<div class="status arp-results">
                <h3>🔍 Сохраненное ARP сканирование: ${scan.network}</h3>
                <p>${scan.message} (сохранено: ${new Date(scan.timestamp).toLocaleString()})</p>
                <p><a href="/arp_report/${scan.scan_id}" target="_blank">📄 Открыть полный отчет</a></p>`;
            
            if (scan.hosts && scan.hosts.length > 0) {
                html += `<div class="host-list">
                    <h4>Найденные хосты:</h4>`;
                
                scan.hosts.forEach(ip => {
                    html += `<div class="host-item">
                        <span>📡 ${ip}</span>
                        <button class="scan-host-btn" onclick="scanSingleHost('${ip}')">Сканировать</button>
                    </div>`;
                });
                
                html += `</div>`;
            }
            
            html += `</div>`;
            resultsDiv.innerHTML = html;
            
            // Прокручиваем к результатам
            resultsDiv.scrollIntoView({ behavior: 'smooth' });
        }
        
        function removeArpScan(index) {
            if (confirm('Удалить это ARP сканирование из истории?')) {
                arpScans.splice(index, 1);
                localStorage.setItem('arpScansHistory', JSON.stringify(arpScans));
                renderArpHistory();
                showNotification('ARP сканирование удалено из истории');
            }
        }
        
        function scanSingleHost(ip) {
            document.getElementById('target').value = ip;
            startScan();
        }
        
        function showNotification(message) {
            // Простое уведомление
            alert(message);
        }
        
        // Загружаем историю ARP из localStorage при загрузке страницы
        function loadArpHistoryFromStorage() {
            const saved = localStorage.getItem('arpScansHistory');
            if (saved) {
                arpScans = JSON.parse(saved);
                renderArpHistory();
            }
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
                            
                            if (scan.results.nmap) {
                                html += `<h4>Nmap результаты:</h4>`;
                                html += `<pre>${JSON.stringify(scan.results.nmap.parsed_ports, null, 2)}</pre>`;
                            }
                            if (scan.results.nikto) {
                                html += `<h4>Nikto результаты:</h4>`;
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
        function loadScanHistory() {
            fetch('/api/scans')
                .then(r => r.json())
                .then(data => {
                    const listDiv = document.getElementById('scanList');
                    if (data.scans.length === 0) {
                        listDiv.innerHTML = '<p>Нет завершенных сканирований</p>';
                    } else {
                        let html = '<ul>';
                        data.scans.forEach(scan => {
                            const type = scan.type === 'arp_scan' ? '🔍 ARP' : '🎯 Single';
                            html += `<li><a href="${scan.type === 'arp_scan' ? '/arp_report/' : '/report/'}${scan.id}">${type}: ${scan.target} - ${scan.status} (${scan.start_time})</a></li>`;
                        });
                        html += '</ul>';
                        listDiv.innerHTML = html;
                    }
                });
        }
        
        // Инициализация при загрузке страницы
        document.addEventListener('DOMContentLoaded', function() {
            loadScanHistory();
            loadArpHistoryFromStorage();
        });
    </script>
</body>
</html>''')
        
    with open('templates/arp_report.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <title>ARP Report - {{ scan.target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; }
        .host-list { margin: 15px 0; }
        .host-item { 
            padding: 10px; 
            margin: 5px 0; 
            background: #f9f9f9; 
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .scan-btn { 
            padding: 5px 10px; 
            background: #28a745; 
            color: white; 
            border: none; 
            border-radius: 3px;
            cursor: pointer;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 ARP Scan Report: {{ scan.target }}</h1>
        <p><strong>Статус:</strong> {{ scan.status }}</p>
        <p><strong>Время начала:</strong> {{ scan.start_time }}</p>
        <p><strong>Время завершения:</strong> {{ scan.end_time }}</p>
        <p><strong>Найдено хостов:</strong> {{ scan.results.hosts_found }}</p>
        
        <div class="section">
            <h2>Найденные хосты</h2>
            <div class="host-list">
                {% for host in scan.results.hosts %}
                <div class="host-item">
                    📡 {{ host }}
                    <button class="scan-btn" onclick="scanHost('{{ host }}')">Сканировать этот хост</button>
                </div>
                {% endfor %}
            </div>
        </div>
                <button onclick="saveAsPdf()" style="padding: 10px 15px; background: #dc3545; color: white; border: none; cursor: pointer;">
        💾 Сохранить как PDF
    </button>
        
        <a href="/">← Вернуться к сканеру</a>

<script>
function saveAsPdf() {
    // Получаем scan_id из URL
    const path = window.location.pathname;
    const scanId = path.split('/').pop();
    
    // Определяем тип отчета
    const isArpReport = path.includes('arp_report');
    const endpoint = isArpReport ? `/save_as_pdf/${scanId}` : `/save_as_pdf/${scanId}`;
    
    window.open(endpoint, '_blank');
}
</script>
    </div>
                

    <script>
        function scanHost(ip) {
            // Открываем новую вкладку с формой сканирования
            window.open('/', '_blank');
            // Можно также передать IP через URL параметры
            setTimeout(() => {
                localStorage.setItem('autoScanIP', ip);
            }, 1000);
        }
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
                    <div style="margin: 20px 0;">
    <button onclick="saveAsPdf()" style="padding: 10px 15px; background: #dc3545; color: white; border: none; cursor: pointer;">
        💾 Сохранить как PDF
    </button>
</div>

<script>
function saveAsPdf() {
    // Получаем scan_id из URL
    const path = window.location.pathname;
    const scanId = path.split('/').pop();
    
    // Определяем тип отчета
    const isArpReport = path.includes('arp_report');
    const endpoint = isArpReport ? `/save_as_pdf/${scanId}` : `/save_as_pdf/${scanId}`;
    
    window.open(endpoint, '_blank');
}
</script>
    </div>

</body>
</html>''')
        
    with open('templates/report_pdf.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .port { margin: 8px 0; padding: 8px; background: #f9f9f9; }
        pre { background: #f5f5f5; padding: 10px; font-size: 10px; overflow: auto; }
        .timestamp { color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Pentest Report: {{ scan.target }}</h1>
        <p class="timestamp">Generated: {{ scan.end_time or scan.start_time }}</p>
    </div>
    
    <div class="section">
        <h2>Scan Information</h2>
        <p><strong>Target:</strong> {{ scan.target }}</p>
        <p><strong>Status:</strong> {{ scan.status }}</p>
        <p><strong>Start Time:</strong> {{ scan.start_time }}</p>
        {% if scan.end_time %}
        <p><strong>End Time:</strong> {{ scan.end_time }}</p>
        {% endif %}
    </div>
    
    {% if scan.results.nmap %}
    <div class="section">
        <h2>Nmap Results</h2>
        {% for port in scan.results.nmap.parsed_ports %}
        <div class="port">
            <strong>Port {{ port.port }}</strong> ({{ port.service }}) - {{ port.state }}<br>
            Version: {{ port.version }}
        </div>
        {% endfor %}
    </div>
    {% endif %}
    
    {% if scan.results.nikto %}
    <div class="section">
        <h2>Nikto Results</h2>
        <pre>{{ scan.results.nikto.output }}</pre>
    </div>
    {% endif %}
    
    {% if scan.results.gobuster %}
    <div class="section">
        <h2>Gobuster Results</h2>
        <pre>{{ scan.results.gobuster.output }}</pre>
    </div>
    {% endif %}
</body>
</html>
''')
    
    with open('templates/arp_report_pdf.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .host-item { margin: 5px 0; padding: 8px; background: #f0f8f0; }
        .timestamp { color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ARP Scan Report: {{ scan.target }}</h1>
        <p class="timestamp">Generated: {{ scan.end_time }}</p>
    </div>
    
    <div class="section">
        <h2>Scan Summary</h2>
        <p><strong>Network:</strong> {{ scan.target }}</p>
        <p><strong>Hosts Found:</strong> {{ scan.results.hosts_found }}</p>
        <p><strong>Scan Date:</strong> {{ scan.start_time }}</p>
    </div>
    
    <div class="section">
        <h2>Discovered Hosts</h2>
        {% for host in scan.results.hosts %}
        <div class="host-item">
            📡 {{ host }}
        </div>
        {% endfor %}
    </div>
</body>
</html>
''')
        
    with open('templates/dashboard_pdf.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .scan-item { margin: 10px 0; padding: 10px; background: #f9f9f9; }
        .arp-scan { background: #f0f8f0; }
        .timestamp { color: #666; font-size: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Pentest Scanner Dashboard</h1>
        <p class="timestamp">Generated: {{ now }}</p>
    </div>
    
    <div class="section">
        <h2>Scan History</h2>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Date</th>
                    <th>Results</th>
                </tr>
            </thead>
            <tbody>
                {% for scan in scans %}
                <tr>
                    <td>{% if scan.type == 'arp_scan' %}ARP Scan{% else %}Single Scan{% endif %}</td>
                    <td>{{ scan.target }}</td>
                    <td>{{ scan.status }}</td>
                    <td>{{ scan.start_time[:16] }}</td>
                    <td>
                        {% if scan.type == 'arp_scan' %}
                            {{ scan.results.hosts_found }} hosts
                        {% else %}
                            {{ scan.results.nmap.parsed_ports|length }} ports
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    
    {% if arp_history %}
    <div class="section">
        <h2>Saved ARP Scans</h2>
        {% for arp_scan in arp_history %}
        <div class="scan-item arp-scan">
            <h3>Network: {{ arp_scan.network }}</h3>
            <p><strong>Hosts Found:</strong> {{ arp_scan.hosts_found }}</p>
            <p><strong>Saved:</strong> {{ arp_scan.timestamp }}</p>
            <div>
                <strong>Hosts:</strong>
                {% for host in arp_scan.hosts %}
                <div>📡 {{ host }}</div>
                {% endfor %}
            </div>
        </div>
        {% endfor %}
    </div>
    {% endif %}
</body>
</html>
''')

    print("Запуск Flask сервера на http://localhost:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)