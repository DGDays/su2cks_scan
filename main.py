#!/usr/bin/env python3
import subprocess
import json
import threading
import os, sys
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
from gigachat import GigaChat

sys.path.append(os.path.join(os.path.dirname(__file__), 'fstec_vul_db'))
from core import VulnerabilityDB
  
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
scan_results = {}
UPLOAD_FOLDER = '/tmp/pentest_scanner_wordlists'
GIGACHAD_TOKEN = "token"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

cve_analysis_queue = deque()
cve_analysis_active = False
nvd_request_times = deque()

def init_fstec_db():
    """Инициализация базы данных уязвимостей ФСТЭК"""
    try:
        db = VulnerabilityDB()
        print("[✅] БД ФСТЭК инициализирована")
        return db
    except Exception as e:
        print(f"[-] Ошибка инициализации БД ФСТЭК: {e}")
        return None

def search_fstec_vulnerabilities(service_name=None, service_version=None, cve_id=None):
    """Поиск уязвимостей в базе данных ФСТЭК для указанного сервиса или CVE"""
    try:
        db = init_fstec_db()
        if not db:
            return []
        
        service_map = {
            'ftp': 'vsftpd',
            'http': 'Apache HTTP Server',
            'https': 'Apache HTTP Server', 
            'ssh': 'OpenSSH',
            'mysql': 'MySQL',
            'postgresql': 'PostgreSQL',
            'smb': 'Samba',
            'microsoft-ds': 'Windows',
            'netbios-ssn': 'Samba'
        }
        
        if cve_id is None:
            search_name = service_map.get(service_name.lower(), service_name)
            print(f"[+] Поиск в БД ФСТЭК: {search_name} {service_version}")
            vulnerabilities = db.find_vulnerabilities(software_name=search_name, software_version=service_version)
        else:
            print(f"[+] Поиск в БД ФСТЭК: {cve_id}")
            vulnerabilities = db.find_vulnerabilities(cve_id=cve_id)
        
        return vulnerabilities
        
    except Exception as e:
        print(f"[-] Ошибка поиска в БД ФСТЭК: {e}")
        return []

def start_cve_analysis_async(scan_data, nmap_output):
    """Запуск асинхронного анализа CVE уязвимостей в фоновом режиме"""
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
            
            services = parse_nmap_for_cve_services(nmap_output)
            if not services:
                print("[-] Нет сервисов для CVE анализа")
                return
            
            services_to_analyze = services
            
            nvd_vulnerabilities = []
            fstec_vulnerabilities = []
            
            for i, service in enumerate(services_to_analyze):
                print(f"[{i+1}/{len(services_to_analyze)}] Анализ CVE для: {service['name']} {service['version']}")
                
                if i > 0:
                    wait_time = 25
                    print(f"[⏳] Пауза {wait_time} секунд перед следующим запросом...")
                    time.sleep(wait_time)
                
                cve_list = search_cve_for_service_safe(service['name'], service['version'])
                
                if cve_list:
                    for cve in cve_list:
                        nvd_vulnerabilities.append({
                            'service': service['name'],
                            'version': service['version'],
                            'port': service['port'],
                            'cve_id': cve['id'],
                            'description': cve['description'],
                            'cvss_score': cve.get('cvss_score', 'N/A'),
                            'severity': cve.get('severity', 'N/A')
                        })
                
                print(f"[{i+1}/{len(services_to_analyze)}] Поиск в БД ФСТЭК для: {service['name']} {service['version']}")
                fstec_vulns = search_fstec_vulnerabilities(service_name=service['name'], service_version=service['version'])
                
                if fstec_vulns:
                    for fstec_vuln in fstec_vulns:
                        fstec_vulnerabilities.append({
                            'service': service['name'],
                            'version': service['version'],
                            'port': service['port'],
                            'vuln_id': fstec_vuln.get('identifier', 'N/A'),
                            'name': fstec_vuln.get('name', 'N/A'),
                            'description': fstec_vuln.get('description', 'N/A'),
                            'severity': fstec_vuln.get('severity', 'N/A'),
                            'publication_date': fstec_vuln.get('publication_date', 'N/A'),
                            'solution': fstec_vuln.get('solution', 'N/A')
                        })

            print("+++++++++++ Ищем ФСТЭК ПО CVE")
            for cve in nvd_vulnerabilities:
                fstec_vulns = search_fstec_vulnerabilities(cve_id=cve["cve_id"])

                if fstec_vulns:
                    for fstec_vuln in fstec_vulns:
                        fstec_vulnerabilities.append({
                            'service': fstec_vuln.get("software_list", "N/A")[0]["name"],
                            'version': fstec_vuln.get("software_list", "N/A")[0]["version"],
                            'port': fstec_vuln.get("port", "N/A"),
                            'vuln_id': fstec_vuln.get('identifier', 'N/A'),
                            'name': fstec_vuln.get('name', 'N/A'),
                            'description': fstec_vuln.get('description', 'N/A'),
                            'severity': fstec_vuln.get('severity', 'N/A'),
                            'publication_date': fstec_vuln.get('publication_date', 'N/A'),
                            'solution': fstec_vuln.get('solution', 'N/A')
                        })

            if GIGACHAD_TOKEN != 'token':
                gigachat_responses = dict()
                for i in nvd_vulnerabilities+fstec_vulnerabilities:
                    giga = GigaChat(
                        ca_bundle_file="./fstec_vul_db/cert/russian_trusted_combined_ca_pem.crt",
                        credentials=GIGACHAD_TOKEN,
                        scope="GIGACHAT_API_PERS",
                        model="GigaChat"
                    )
                    response = giga.chat("Привет. Проанализируй, пожалуйста, данную уязвимость. Что можешь сказать о ней? Ответ нужен краткий, но ёмкий. Буквально на 5-6 предложений. Уязвимость: "+str(i)).choices[0].message.content
                    try:
                        gigachat_responses[i["cve_id"]] = response
                    except:
                        gigachat_responses[i["vuln_id"]] = response
                scan_data['results']['ai_analysis'] = gigachat_responses
            
            scan_data['results']['vulnerability_analysis'] = {
                'nvd_vulnerabilities': nvd_vulnerabilities,
                'fstec_vulnerabilities': fstec_vulnerabilities,
                'nvd_total': len(nvd_vulnerabilities),
                'fstec_total': len(fstec_vulnerabilities),
                'total_found': len(nvd_vulnerabilities) + len(fstec_vulnerabilities),
                'scan_time': datetime.now().isoformat()
            }
            
            print(f"[✅] Анализ уязвимостей завершен: "
                  f"NVD: {len(nvd_vulnerabilities)}, ФСТЭК: {len(fstec_vulnerabilities)}")
            
        except Exception as e:
            print(f"[-] Ошибка асинхронного анализа уязвимостей: {e}")
        finally:
            cve_analysis_active = False
            
            if cve_analysis_queue:
                next_scan_data, next_nmap_output = cve_analysis_queue.popleft()
                start_cve_analysis_async(next_scan_data, next_nmap_output)
    
    thread = threading.Thread(target=async_cve_analysis)
    thread.daemon = True
    thread.start()

def parse_nmap_for_cve_services(nmap_xml_output):
    """Парсит вывод Nmap для извлечения информации о сервисах и версиях для последующего CVE анализа"""
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
                            
                            full_version = product
                            if version:
                                full_version += f" {version}"
                            
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
    """Безопасный поиск CVE с учетом ограничений API NVD и управлением частотой запросов"""
    global nvd_request_times
    
    current_time = time.time()
    while nvd_request_times and current_time - nvd_request_times[0] > 30:
        nvd_request_times.popleft()
    
    if len(nvd_request_times) >= 5:
        wait_time = 30 - (current_time - nvd_request_times[0])
        print(f"[-] Достигнут лимит NVD API. Ожидание {wait_time:.1f} секунд...")
        time.sleep(wait_time + 1)
        current_time = time.time()
        nvd_request_times.clear()
    
    nvd_request_times.append(current_time)
    
    try:
        service_map = {
            'http': 'apache', 'https': 'apache', 
            'ssh': 'openssh', 'ftp': 'vsftpd',
            'mysql': 'mysql', 'postgresql': 'postgresql', 
            'microsoft-ds': 'windows', 'netbios-ssn': 'samba', 
            'smb': 'samba', 'telnet': 'telnet'
        }
        
        search_term = service_map.get(service_name.lower(), service_name.lower())
        
        if service_name == 'ftp' and 'vsftpd' in service_version.lower():
            search_term = 'vsftpd'
            query = f"vsftpd 2.3.4"
        else:
            query = f"{search_term} {service_version}"
        
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'keywordSearch': query,
            'resultsPerPage': 5
        }
        
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
    
def nmap_exploit_scan(target, ports=None, options="-sV", searchsploit_options=""):
    """Выполняет сканирование Nmap с последующим поиском эксплойтов через searchsploit"""
    results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'nmap_command': '',
        'open_ports': [],
        'vulnerable_services': [],
        'searchsploit_output': '',
        'error': None
    }
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp_file:
            xml_filename = tmp_file.name
        
        nmap_cmd = f"nmap {options}"
        if ports:
            nmap_cmd += f" -p {ports}"
        nmap_cmd += f" -oX {xml_filename} {target}"
        
        results['nmap_command'] = nmap_cmd
        
        print(f"🔍 Выполняю сканирование Nmap: {nmap_cmd}")
        
        nmap_process = subprocess.run(
            nmap_cmd.split(),
            capture_output=True,
            text=True,
            timeout=3600
        )
        
        if nmap_process.returncode != 0:
            results['error'] = f"Nmap ошибка: {nmap_process.stderr}"
            return results
        
        tree = ET.parse(xml_filename)
        root = tree.getroot()
        
        for host in root.findall('host'):
            for ports_elem in host.findall('ports'):
                for port_elem in ports_elem.findall('port'):
                    if port_elem.find('state').get('state') == 'open':
                        port_info = {
                            'port': port_elem.get('portid'),
                            'protocol': port_elem.get('protocol'),
                            'service': 'unknown',
                            'version': 'unknown'
                        }
                        
                        service_elem = port_elem.find('service')
                        if service_elem is not None:
                            port_info['service'] = service_elem.get('name', 'unknown')
                            port_info['version'] = service_elem.get('version', 'unknown')
                            port_info['product'] = service_elem.get('product', 'unknown')
                        
                        results['open_ports'].append(port_info)
        
        print("🎯 Ищу эксплойты через searchsploit...")
        
        searchsploit_cmd = f"searchsploit --nmap {xml_filename} {searchsploit_options}"
        exploit_process = subprocess.run(
            searchsploit_cmd.split(),
            capture_output=True,
            text=True
        )
        
        results['searchsploit_output'] = exploit_process.stdout
        
        if exploit_process.returncode == 0:
            for line in exploit_process.stdout.split('\n'):
                if '|' in line and not line.startswith('--'):
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 4:
                        service_info = {
                            'service': parts[0],
                            'version': parts[1],
                            'cve': parts[2],
                            'exploit_info': parts[3] if len(parts) > 3 else ''
                        }
                        results['vulnerable_services'].append(service_info)
        
        print("✅ Сканирование эксплойтов завершено!")
        
    except subprocess.TimeoutExpired:
        results['error'] = "Nmap сканирование превысило таймаут"
    except Exception as e:
        results['error'] = f"Ошибка: {str(e)}"
    finally:
        if 'xml_filename' in locals() and os.path.exists(xml_filename):
            os.unlink(xml_filename)
    
    return results

def search_exploits(target=None, nmap_xml=None, query=None, options=None):
    """Выполняет поиск эксплойтов через searchsploit на основе результатов Nmap или прямого запроса"""
    try:
        base_options = options or " -j "
        
        if nmap_xml:
            print(f"[+] Поиск эксплойтов для результатов Nmap")
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp_file:
                tmp_file.write(nmap_xml)
                xml_filename = tmp_file.name
            
            cmd = f"searchsploit --nmap {xml_filename} {base_options}"
            
        elif query:
            print(f"[+] Поиск эксплойтов для запроса: {query}")
            cmd = f"searchsploit {query} {base_options}"
            
        elif target:
            print(f"[+] Поиск эксплойтов для цели: {target}")
            cmd = f"searchsploit {target} {base_options}"
            
        else:
            return {
                'success': False,
                'error': 'Не указана цель, XML Nmap или запрос для поиска'
            }
        
        print(f"[+] Выполняю: {cmd}")
        
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=300
        )
        
        response = {
            'success': result.returncode == 0,
            'command': cmd,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }
        out = []
        for i in response.get("output").split("\n\n\n")[1::2]:
            try:
                res_exp = json.loads(i)["RESULTS_EXPLOIT"]
                for j in res_exp:
                    out.append("Title: "+j["Title"]+"\nEDB-ID: "+j["EDB-ID"]+"\nCodes in VulDBs: "+j["Codes"]+"\n")
            except:
                pass
        out = '\n'.join(out)
        response['output'] = out
        
        if 'xml_filename' in locals() and os.path.exists(xml_filename):
            os.unlink(xml_filename)
        
        return response
        
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Searchsploit timeout'
        }
    except Exception as e:
        if 'xml_filename' in locals() and os.path.exists(xml_filename):
            os.unlink(xml_filename)
            print(f'Unexpected error: {str(e)}')
        return {
            'success': False,
            'error': f'Unexpected error: {str(e)}'
        }

def find_wkhtmltopdf():
    """Автоматически находит путь к wkhtmltopdf для генерации PDF отчетов"""
    possible_paths = []
    
    system = platform.system().lower()
    
    if system == 'windows':
        possible_paths = [
            r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\wkhtmltopdf\bin\wkhtmltopdf.exe',
            'wkhtmltopdf.exe'
        ]
    elif system == 'linux' or system == 'darwin':
        possible_paths = [
            '/usr/bin/wkhtmltopdf',
            '/usr/local/bin/wkhtmltopdf',
            '/bin/wkhtmltopdf',
            '/opt/bin/wkhtmltopdf',
            'wkhtmltopdf'
        ]
    
    for path in possible_paths:
        if os.path.exists(path):
            print(f"[+] Найден wkhtmltopdf: {path}")
            return path
    
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
    
    print("[-] Wkhtmltopdf не найден. Установите его:")
    if system == 'windows':
        print("Скачайте с: https://wkhtmltopdf.org/downloads.html")
    else:
        print("sudo apt-get install wkhtmltopdf  # Ubuntu/Debian")
        print("brew install wkhtmltopdf          # MacOS")
    
    return None

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
    """Выполняет базовое сканирование Nmap для определения открытых портов и версий сервисов"""
    try:
        print(f"[+] Запуск Nmap для {target}")
        result = subprocess.run([
            'nmap', '-sS', '-sV', '--open', '-T4', 
            '-oX', '-',
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
    """Выполняет веб-сканирование с помощью Nikto для обнаружения распространенных уязвимостей"""
    try:
        print(f"[+] Запуск Nikto для {target}:{port}")
        url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
        
        result = subprocess.run([
            'nikto', '-h', url,
            '-o', '-',
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
    """Выполняет поиск директорий и файлов на веб-сервере с помощью Gobuster"""
    try:
        print(f"[+] Запуск Gobuster для {target}:{port}")
        print(f"[+] Используется словарь: {wordlist}")
        url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
        
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
    """Выполняет поиск виртуальных хостов с помощью Gobuster"""
    try:
        print(f"[+] Запуск Gobuster для {target}:{port}")
        url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
        
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
    """Запускает дополнительное сканирование и обновляет основные результаты"""
    try:
        if scan_type == 'dir':
            result = run_gobuster(target, port, wordlist)
        elif scan_type == 'vhost':
            result = run_gobuster_vhost(target, port, wordlist)
        elif scan_type == 'sqlmap':
            result = run_sqlmap(target, commands)
        else:
            return
        
        if main_scan_id in scan_results:
            main_scan = scan_results[main_scan_id]
            
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
    """Парсит XML вывод Nmap для извлечения информации об открытых портах и сервисах"""
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
    """Выполняет ARP сканирование сети для обнаружения активных хостов"""
    try:
        result = subprocess.run([
            'nmap', '-sn', '-PR', network, '-oX', '-'
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0:
            return []
        
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
    """Основная функция сканирования цели, координирующая различные инструменты проверки"""
    try:
        nmap_result = run_nmap(target)
        if nmap_result['success']:
            scan_data['results']['nmap'] = {
                'raw_output': nmap_result['output'],
                'parsed_ports': parse_nmap_xml(nmap_result['output'])
            }
            
            print("[🚀] Запуск асинхронного CVE анализа...")
            start_cve_analysis_async(scan_data, nmap_result['output'])

            print("[🔍] Запуск поиска эксплойтов...")
            exploit_result = search_exploits(nmap_xml=nmap_result['output'])
            if exploit_result['success']:
                scan_data['results']['exploits'] = {
                    'searchsploit_output': exploit_result['output'],
                    'command': exploit_result['command'],
                    'timestamp': datetime.now().isoformat()
                }
            
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
    """Выполняет тестирование на SQL инъекции с помощью SQLMap"""
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

@app.route('/')
def index():
    """Главная страница веб-интерфейса сканера"""
    return render_template('index.html')

@app.route('/api/upload_wordlist', methods=['POST'])
def upload_wordlist():
    """API endpoint для загрузки пользовательских wordlist файлов"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and (file.filename.endswith('.txt') or file.filename.endswith('.lst')):
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
    """API endpoint для запуска сканирования цели или сети"""
    data = request.json
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    ip_mask_strict_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$'
    
    if bool(re.match(ip_mask_strict_pattern, target)):
        ips = run_arp_scan(target)
        
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
    """API endpoint для получения статуса и результатов сканирования"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/api/scans')
def list_scans():
    """API endpoint для получения списка всех выполненных сканирований"""
    return jsonify({
        'scans': list(scan_results.values())
    })

@app.route('/report/<scan_id>')
def view_report(scan_id):
    """Страница с детальным отчетом по сканированию"""
    if scan_id not in scan_results:
        return "Report not found", 404
    
    return render_template('report.html', scan=scan_results[scan_id])

@app.route('/arp_report/<scan_id>')
def view_arp_report(scan_id):
    """Страница с отчетом по ARP сканированию сети"""
    if scan_id not in scan_results:
        return "ARP report not found", 404
    
    scan_data = scan_results[scan_id]
    if scan_data.get('type') != 'arp_scan':
        return "This is not an ARP scan report", 400
    
    return render_template('arp_report.html', scan=scan_data)

@app.route('/save_as_pdf/<scan_id>')
def save_scan_as_pdf(scan_id):
    """Генерирует и возвращает PDF отчет по сканированию"""
    if scan_id not in scan_results:
        return "Scan not found", 404
    
    scan_data = scan_results[scan_id]
    
    if scan_data.get('type') == 'arp_scan':
        html_content = render_template('arp_report_pdf.html', scan=scan_data)
        filename = f"arp_scan_{scan_data['target']}.pdf"
    else:
        html_content = render_template('report_pdf.html', scan=scan_data)
        filename = f"scan_{scan_data['target']}.pdf"
    
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
    """Генерирует PDF отчет главной страницы с историей сканирований"""
    all_scans = list(scan_results.values())
    
    arp_history = []
    
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

@app.route('/save_dashboard_with_arp', methods=['POST'])
def save_dashboard_with_arp():
    """Генерирует PDF отчет дашборда с переданной историей ARP сканирований"""
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
    """API endpoint для запуска дополнительных кастомных сканирований"""
    data = request.json
    target = data.get('target', '')
    scan_type = data.get('scan_type', 'dir')
    custom_wordlist = data.get('wordlist', '')
    port = data.get('port', 80)
    main_scan_id = data.get('main_scan_id', '')
    commands = data.get('commands', '')
    
    if not target or not main_scan_id:
        return jsonify({'error': 'Target and main_scan_id are required'}), 400
    
    if main_scan_id not in scan_results:
        return jsonify({'error': 'Main scan not found'}), 404
    
    thread = threading.Thread(target=run_custom_scan_and_update, 
                             args=(target, port, scan_type, custom_wordlist, main_scan_id, commands))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'status': 'started',
        'message': 'Дополнительное сканирование запущено'
    })

@app.route('/api/search_exploits', methods=['POST'])
def api_search_exploits():
    """API endpoint для поиска эксплойтов через searchsploit"""
    data = request.json
    target = data.get('target', '')
    query = data.get('query', '')
    options = data.get('options', '')
    
    if not target and not query:
        return jsonify({'error': 'Target or query is required'}), 400
    
    try:
        if query:
            result = search_exploits(query=query, options=options)
        else:
            result = search_exploits(target=target, options=options)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    print("Запуск Flask сервера на http://localhost:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)