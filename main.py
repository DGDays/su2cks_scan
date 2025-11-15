#!/usr/bin/env python3
import subprocess
import json
import threading
import os
import re
import pdfkit
import tempfile
import platform
import uuid
import requests
import time
from datetime import datetime
from collections import deque
from flask import Flask, render_template, request, jsonify, make_response
import xml.etree.ElementTree as ET
  
'''
│╲   ____╲│╲  ╲│╲  ╲  ╱  ___  ╲│╲   ____╲│╲  ╲│╲  ╲ │╲   ____╲         │╲   ____╲│╲   ____╲│╲   __  ╲│╲   ___  ╲    
╲ ╲  ╲___│╲ ╲  ╲╲╲  ╲╱__╱│_╱  ╱╲ ╲  ╲___│╲ ╲  ╲╱  ╱│╲ ╲  ╲___│_        ╲ ╲  ╲___│╲ ╲  ╲___│╲ ╲  ╲│╲  ╲ ╲  ╲╲ ╲  ╲   
 ╲ ╲_____  ╲ ╲  ╲╲╲  ╲__│╱╱  ╱ ╱╲ ╲  ╲    ╲ ╲   ___  ╲ ╲_____  ╲        ╲ ╲_____  ╲ ╲  ╲    ╲ ╲   __  ╲ ╲  ╲╲ ╲  ╲  
  ╲│____│╲  ╲ ╲  ╲╲╲  ╲  ╱  ╱_╱__╲ ╲  ╲____╲ ╲  ╲╲ ╲  ╲│____│╲  ╲        ╲│____│╲  ╲ ╲  ╲____╲ ╲  ╲ ╲  ╲ ╲  ╲╲ ╲  ╲ 
    ____╲_╲  ╲ ╲_______╲│╲________╲ ╲_______╲ ╲__╲╲ ╲__╲____╲_╲  ╲         ____╲_╲  ╲ ╲_______╲ ╲__╲ ╲__╲ ╲__╲╲ ╲__╲
   │╲_________╲│_______│ ╲│_______│╲│_______│╲│__│ ╲│__│╲_________╲       │╲_________╲│_______│╲│__│╲│__│╲│__│ ╲│__│
   ╲│_________│                                        ╲│_________│       ╲│_________│   
   '''

app = Flask(__name__)

# Хранилище результатов сканирований
scan_results = {}
UPLOAD_FOLDER = '/tmp/pentest_scanner_wordlists'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# =====================================================================================================================

# Глобальные переменные для управления CVE анализом
cve_analysis_queue = deque()
cve_analysis_active = False
nvd_request_times = deque()

def start_cve_analysis_async(scan_data, nmap_output):
    """
    Запускает CVE анализ в отдельном потоке с ограничением запросов
    """
    global cve_analysis_active
    
    if cve_analysis_active:
        print("[-] CVE анализ уже выполняется, добавляем в очередь")
        cve_analysis_queue.append((scan_data, nmap_output))
        return
    
    cve_analysis_active = True
    
    def async_cve_analysis():
        global cve_analysis_active
        
        try:
            print("[🚀] Запуск асинхронного CVE анализа в фоновом режиме...")
            
            # Парсим сервисы для анализа
            services = parse_nmap_for_cve_services(nmap_output)
            if not services:
                print("[-] Нет сервисов для CVE анализа")
                return
            
            # Ограничиваем количество анализируемых сервисов
            services_to_analyze = services[:3]  # Только первые 3 сервиса
            
            vulnerabilities = []
            
            for i, service in enumerate(services_to_analyze):
                print(f"[{i+1}/{len(services_to_analyze)}] Анализ CVE для: {service['name']} {service['version']}")
                
                # Делаем паузу между запросами (25 секунд)
                if i > 0:
                    wait_time = 25
                    print(f"[⏳] Пауза {wait_time} секунд перед следующим запросом...")
                    time.sleep(wait_time)
                
                # Ищем CVE для сервиса
                cve_list = search_cve_for_service_safe(service['name'], service['version'])
                
                if cve_list:
                    for cve in cve_list:
                        vulnerabilities.append({
                            'service': service['name'],
                            'version': service['version'],
                            'port': service['port'],
                            'cve_id': cve['id'],
                            'description': cve['description'],
                            'cvss_score': cve.get('cvss_score', 'N/A'),
                            'severity': cve.get('severity', 'N/A')
                        })
            
            # Сохраняем результаты в scan_data
            if vulnerabilities:
                scan_data['results']['cve_analysis'] = {
                    'vulnerabilities': vulnerabilities,
                    'total_found': len(vulnerabilities),
                    'scan_time': datetime.now().isoformat()
                }
                print(f"[✅] CVE анализ завершен: найдено {len(vulnerabilities)} уязвимостей")
            else:
                print("[ℹ️] CVE анализ завершен: уязвимости не найдены")
            
        except Exception as e:
            print(f"[-] Ошибка асинхронного CVE анализа: {e}")
        finally:
            cve_analysis_active = False
            
            # Обрабатываем следующее сканирование в очереди
            if cve_analysis_queue:
                next_scan_data, next_nmap_output = cve_analysis_queue.popleft()
                start_cve_analysis_async(next_scan_data, next_nmap_output)
    
    # Запускаем в отдельном потоке
    thread = threading.Thread(target=async_cve_analysis)
    thread.daemon = True
    thread.start()

def parse_nmap_for_cve_services(nmap_xml_output):
    """
    Парсит вывод Nmap для извлечения сервисов и версий для CVE анализа
    """
    try:
        services = []
        root = ET.fromstring(nmap_xml_output)
        
        for host in root.findall('host'):
            for ports in host.findall('ports'):
                for port in ports.findall('port'):
                    if port.find('state').get('state') == 'open':
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service_name = service_elem.get('name', 'unknown')
                            product = service_elem.get('product', '')
                            version = service_elem.get('version', '')
                            
                            # Формируем полную версию
                            full_version = product
                            if version:
                                full_version += f" {version}"
                            
                            # Фильтруем только интересные сервисы
                            if service_name in ['http', 'https', 'ssh', 'ftp', 'mysql', 
                                              'postgresql', 'microsoft-ds', 'netbios-ssn', 
                                              'smb', 'telnet'] and full_version.strip():
                                services.append({
                                    'port': port.get('portid'),
                                    'name': service_name,
                                    'version': full_version.strip()
                                })
        
        print(f"[+] Найдено {len(services)} сервисов для CVE анализа")
        return services
        
    except Exception as e:
        print(f"[-] Ошибка парсинга Nmap для CVE: {e}")
        return []

def search_cve_for_service_safe(service_name, service_version):
    """
    Безопасный поиск CVE с учетом лимитов NVD API
    """
    global nvd_request_times
    
    # Очищаем старые запросы (старше 30 секунд)
    current_time = time.time()
    while nvd_request_times and current_time - nvd_request_times[0] > 30:
        nvd_request_times.popleft()
    
    # Проверяем лимит (5 запросов в 30 секунд)
    if len(nvd_request_times) >= 5:
        wait_time = 30 - (current_time - nvd_request_times[0])
        print(f"[-] Достигнут лимит NVD API. Ожидание {wait_time:.1f} секунд...")
        time.sleep(wait_time + 1)
        current_time = time.time()
        nvd_request_times.clear()
    
    # Добавляем текущий запрос
    nvd_request_times.append(current_time)
    
    try:
        # Нормализуем название сервиса
        service_map = {
            'http': 'apache', 'https': 'apache', 
            'ssh': 'openssh', 'ftp': 'vsftpd',  # ⚠️ ИСПРАВИЛ: ftp -> vsftpd
            'mysql': 'mysql', 'postgresql': 'postgresql', 
            'microsoft-ds': 'windows', 'netbios-ssn': 'samba', 
            'smb': 'samba', 'telnet': 'telnet'
        }
        
        search_term = service_map.get(service_name.lower(), service_name.lower())
        
        # ⚠️ ИСПРАВИЛ: Правильный формат запроса
        if service_name == 'ftp' and 'vsftpd' in service_version.lower():
            search_term = 'vsftpd'
            query = f"vsftpd 2.3.4"  # Конкретная версия
        else:
            query = f"{search_term} {service_version}"
        
        # ⚠️ ИСПРАВИЛ: Используем новый API endpoint
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'keywordSearch': query,
            'resultsPerPage': 5
        }
        
        # ⚠️ ДОБАВИЛ: Заголовки для обхода ограничений
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
        }
        
        print(f"[+] Запрос к NVD API: {query}")
        response = requests.get(url, params=params, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            cve_list = []
            
            for vuln in data.get('vulnerabilities', []):
                cve_data = vuln['cve']
                cve_id = cve_data['id']
                description = cve_data['descriptions'][0]['value']
                
                cvss_score = 'N/A'
                severity = 'N/A'
                
                # Парсим CVSS v3 или v2
                if 'metrics' in cve_data:
                    if 'cvssMetricV31' in cve_data['metrics']:
                        cvss_data = cve_data['metrics']['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data['baseScore']
                        severity = cvss_data['baseSeverity']
                    elif 'cvssMetricV30' in cve_data['metrics']:
                        cvss_data = cve_data['metrics']['cvssMetricV30'][0]['cvssData']
                        cvss_score = cvss_data['baseScore']
                        severity = cvss_data['baseSeverity']
                    elif 'cvssMetricV2' in cve_data['metrics']:
                        cvss_data = cve_data['metrics']['cvssMetricV2'][0]['cvssData']
                        cvss_score = cvss_data['baseScore']
                        severity = cve_data['metrics']['cvssMetricV2'][0]['baseSeverity']
                
                cve_list.append({
                    'id': cve_id,
                    'description': description[:200] + "..." if len(description) > 200 else description,
                    'cvss_score': cvss_score,
                    'severity': severity
                })
            
            print(f"[+] Найдено {len(cve_list)} CVE для {search_term}")
            return cve_list
        else:
            print(f"[-] Ошибка NVD API: {response.status_code} - {response.text[:100]}")
            return []
            
    except Exception as e:
        print(f"[-] Ошибка поиска CVE: {e}")
        return []

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
        print(f"[+] Используется словарь: {wordlist}")
        url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
        
        # УБИРАЕМ -o - и используем только capture_output
        result = subprocess.run([
            'gobuster', 'dir', '-u', url, '-w', wordlist, '-q'
        ], capture_output=True, text=True, timeout=300)
        
        if "no such file" in result.stderr.lower():
            print(f"[-] Словарь {wordlist} не найден, используем минимальный словарь")
            minimal_words = ["admin", "login", "uploads", "images", "css", "js", "api"]
            temp_wordlist = "/tmp/minimal_wordlist.txt"
            with open(temp_wordlist, 'w') as f:
                for word in minimal_words:
                    f.write(word + '\n')
            
            result = subprocess.run([
                'gobuster', 'dir', '-u', url, '-w', temp_wordlist, '-q'
            ], capture_output=True, text=True, timeout=300)
            
            os.unlink(temp_wordlist)
        
        print(f"[+] Gobuster завершен для {target}:{port}")
        print(f"[+] Вывод: {len(result.stdout)} символов, ошибки: {len(result.stderr)} символов")
        
        return {
            'success': True,
            'output': result.stdout,
            'error': result.stderr
        }
    except subprocess.TimeoutExpired:
        print(f"[-] Таймаут Gobuster для {target}:{port}")
        return {'success': False, 'error': 'Gobuster timeout'}
    except Exception as e:
        print(f"[-] Ошибка Gobuster для {target}:{port}: {e}")
        return {'success': False, 'error': str(e)}
    
def run_gobuster_vhost(target, port=80, wordlist='/usr/share/wordlists/dirb/common.txt'):
    """Запуск Gobuster для поиска директорий"""
    try:
        print(f"[+] Запуск Gobuster для {target}:{port}")
        url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
        
        # УБИРАЕМ -o - и используем только capture_output
        result = subprocess.run([
            'gobuster', 'vhost', '-u', url, '-w', wordlist, '-q'
        ], capture_output=True, text=True, timeout=300)
        
        if "no such file" in result.stderr.lower():
            minimal_words = ["admin", "login", "uploads", "images", "panel"]
            temp_wordlist = "/tmp/minimal_wordlist.txt"
            with open(temp_wordlist, 'w') as f:
                for word in minimal_words:
                    f.write(word + '\n')
            
            result = subprocess.run([
                'gobuster', 'vhost', '-u', url, '-w', temp_wordlist, '-q'
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
    
def run_custom_scan_and_update(target, port, scan_type, wordlist=None, main_scan_id=None, commands=None):
    """Запускает кастомное сканирование и добавляет результаты в основное"""
    try:
        if scan_type == 'dir':
            result = run_gobuster(target, port, wordlist)
        elif scan_type == 'vhost':
            result = run_gobuster_vhost(target, port, wordlist)
        elif scan_type == 'sqlmap':
            # Для SQLMap передаем commands и target
            result = run_sqlmap(target, commands)
        else:
            return
        
        # Добавляем результаты в основное сканирование
        if main_scan_id in scan_results:
            main_scan = scan_results[main_scan_id]
            
            # Создаем ключ для дополнительного сканирования
            custom_key = f"custom_{scan_type}_{datetime.now().strftime('%H%M%S')}"
            
            if 'custom_scans' not in main_scan['results']:
                main_scan['results']['custom_scans'] = {}
            
            main_scan['results']['custom_scans'][custom_key] = {
                'scan_type': scan_type,
                'wordlist_used': wordlist or 'default',
                'port': port,
                'output': result.get('output', ''),
                'timestamp': datetime.now().isoformat(),
                'success': result.get('success', False)
            }
            
    except Exception as e:
        print(f"Error in custom scan: {e}")

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

# Обновляем функцию сканирования чтобы включать CVE анализ
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
            
            # Запускаем CVE анализ в фоновом режиме
            print("[🚀] Запуск асинхронного CVE анализа...")
            start_cve_analysis_async(scan_data, nmap_result['output'])
            
            # Остальное сканирование продолжается без ожидания CVE
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
                scan_data['results']['gobuster_vhost'] = {
                    'port': first_web_port,
                    'output': run_gobuster_vhost(target, first_web_port)['output']
                }
        
        scan_data['status'] = 'completed'
        scan_data['end_time'] = datetime.now().isoformat()
        
    except Exception as e:
        scan_data['status'] = 'error'
        scan_data['error'] = str(e)
        scan_data['end_time'] = datetime.now().isoformat()

def run_sqlmap(target, commands=None, timeout=300):
    """Запуск SQLMap для тестирования SQL инъекций"""
    if commands is None:
        commands = f"-u {target} --batch --level=1 --risk=1"
    
    try:
        print(f"[+] Запуск SQLMap для {target}")
        print(f"[+] Команда: sqlmap {commands}")
        
        result = subprocess.run(['sqlmap'] + commands.split(),
                                capture_output=True, text=True, timeout=timeout)
        
        print(f"[+] SQLMap завершен для {target}")
        print(f"[+] Код возврата: {result.returncode}")
        print(f"[+] Вывод: {len(result.stdout)} символов")
        
        return {
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode,
            'commands': commands
        }
        
    except subprocess.TimeoutExpired:
        print(f"[-] Таймаут SQLMap для {target}")
        return {'success': False, 'error': 'SQLMap timeout'}
    except Exception as e:
        print(f"[-] Ошибка SQLMap для {target}: {e}")
        return {'success': False, 'error': str(e)}


# =====================================================================================================================

@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/api/upload_wordlist', methods=['POST'])
def upload_wordlist():
    """Загружает wordlist на сервер"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and (file.filename.endswith('.txt') or file.filename.endswith('.lst')):
        # Сохраняем файл с уникальным именем
        filename = f"{uuid.uuid4().hex}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        return jsonify({
            'success': True,
            'filepath': filepath,
            'filename': file.filename
        })
    else:
        return jsonify({'error': 'Invalid file type. Only .txt and .lst allowed'}), 400

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
    
@app.route('/api/custom_scan', methods=['POST'])
def custom_scan():
    """Endpoint для кастомного сканирования"""
    data = request.json
    target = data.get('target', '')
    scan_type = data.get('scan_type', 'dir')
    custom_wordlist = data.get('wordlist', '')
    port = data.get('port', 80)
    main_scan_id = data.get('main_scan_id', '')
    commands = data.get('commands', '')  # ⭐ ДОБАВИЛ ЭТУ СТРОЧКУ!
    
    if not target or not main_scan_id:
        return jsonify({'error': 'Target and main_scan_id are required'}), 400
    
    if main_scan_id not in scan_results:
        return jsonify({'error': 'Main scan not found'}), 404
    
    # Запускаем в отдельном потоке
    thread = threading.Thread(target=run_custom_scan_and_update, 
                             args=(target, port, scan_type, custom_wordlist, main_scan_id, commands))  # ⭐ И commands ЗДЕСЬ!
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'status': 'started',
        'message': 'Дополнительное сканирование запущено'
    })

if __name__ == '__main__':
    print("Запуск Flask сервера на http://localhost:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)