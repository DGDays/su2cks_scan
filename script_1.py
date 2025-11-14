###pervoe 4to predlogil ds
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os
from datetime import datetime

def nmap_exploit_scan(target, ports=None, options="-sV", searchsploit_options=""):
    """
    Выполняет сканирование Nmap и поиск эксплойтов через searchsploit
    
    Args:
        target (str): IP-адрес или домен для сканирования
        ports (str, optional): Порт или диапазон портов. Defaults to None.
        options (str, optional): Дополнительные опции Nmap. Defaults to "-sV".
        searchsploit_options (str, optional): Дополнительные опции searchsploit. Defaults to "".
    
    Returns:
        dict: Результаты сканирования и найденные эксплойты
    """
    
    results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'nmap_command': '',
        'xml_file': '',
        'open_ports': [],
        'vulnerable_services': [],
        'searchsploit_output': '',
        'error': None
    }
    
    try:
        # Создаем временный XML-файл
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp_file:
            xml_filename = tmp_file.name
            results['xml_file'] = xml_filename
        
        # Формируем команду Nmap
        nmap_cmd = f"nmap {options}"
        if ports:
            nmap_cmd += f" -p {ports}"
        nmap_cmd += f" -oX {xml_filename} {target}"
        
        results['nmap_command'] = nmap_cmd
        
        print(f"🔍 Выполняю сканирование Nmap: {nmap_cmd}")
        
        # Выполняем Nmap сканирование
        nmap_process = subprocess.run(
            nmap_cmd.split(),
            capture_output=True,
            text=True,
            timeout=3600  # 1 час таймаут
        )
        
        if nmap_process.returncode != 0:
            results['error'] = f"Nmap ошибка: {nmap_process.stderr}"
            return results
        
        # Парсим XML результат
        tree = ET.parse(xml_filename)
        root = tree.getroot()
        
        # Извлекаем информацию об открытых портах
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
        
        # Запускаем searchsploit с XML-файлом
        print("🎯 Ищу эксплойты через searchsploit...")
        
        searchsploit_cmd = f"searchsploit --nmap {xml_filename} {searchsploit_options}"
        exploit_process = subprocess.run(
            searchsploit_cmd.split(),
            capture_output=True,
            text=True
        )
        
        results['searchsploit_output'] = exploit_process.stdout
        
        if exploit_process.returncode == 0:
            # Парсим вывод searchsploit для поиска уязвимых сервисов
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
        
        print("✅ Сканирование завершено!")
        
    except subprocess.TimeoutExpired:
        results['error'] = "Nmap сканирование превысило таймаут"
    except Exception as e:
        results['error'] = f"Ошибка: {str(e)}"
    finally:
        # Удаляем временный файл
        if os.path.exists(xml_filename):
            os.unlink(xml_filename)
    
    return results

def print_scan_results(results):
    """Красиво выводит результаты сканирования"""
    
    print(f"\n{'='*60}")
    print(f"📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
    print(f"{'='*60}")
    print(f"Цель: {results['target']}")
    print(f"Время: {results['timestamp']}")
    
    if results['error']:
        print(f"❌ Ошибка: {results['error']}")
        return
    
    print(f"\n🔓 ОТКРЫТЫЕ ПОРТЫ:")
    print("-" * 40)
    for port in results['open_ports']:
        print(f"Порт {port['port']}/{port['protocol']}: {port['service']} {port.get('version', '')}")
    
    if results['vulnerable_services']:
        print(f"\n⚠️  НАЙДЕНЫ ЭКСПЛОЙТЫ:")
        print("-" * 40)
        for vuln in results['vulnerable_services']:
            print(f"Сервис: {vuln['service']}")
            print(f"Версия: {vuln['version']}")
            print(f"CVE: {vuln['cve']}")
            print(f"Инфо: {vuln['exploit_info']}")
            print("-" * 20)
    else:
        print(f"\n✅ Эксплойты не найдены")
    
    if results['searchsploit_output']:
        print(f"\n📋 ПОЛНЫЙ ВЫВОД SEARCHSPLOIT:")
        print("-" * 40)
        print(results['searchsploit_output'])

# Примеры использования
if __name__ == "__main__":
    # Пример 1: Простое сканирование
    print("Пример 1: Сканирование одного хоста")
    results1 = nmap_exploit_scan("192.168.1.1")
    print_scan_results(results1)
    
    # Пример 2: Сканирование конкретных портов
    print("\n\nПример 2: Сканирование конкретных портов")
    results2 = nmap_exploit_scan("example.com", ports="53,80,443,22")
    print_scan_results(results2)
    
    # Пример 3: Расширенное сканирование
    print("\n\nПример 3: Расширенное сканирование")
    results3 = nmap_exploit_scan(
        "target.local", 
        options="-sV -A --script vuln",
        searchsploit_options="--exclude='/dos/'"
    )
    print_scan_results(results3)

########################################################
###################   4ut lu4IIIe   ####################
########################################################


import subprocess
import tempfile
import os

def search_exploits(target=None, nmap_xml=None, query=None, options=None):
    """
    Функция для поиска эксплойтов через searchsploit
    
    Args:
        target (str): Цель для поиска (IP, домен или название сервиса)
        nmap_xml (str): XML вывод Nmap для анализа
        query (str): Прямой запрос для searchsploit
        options (str): Дополнительные опции searchsploit
    
    Returns:
        dict: Результаты поиска эксплойтов
    """
    
    try:
        # Базовые опции
        base_options = options or ""
        
        # Если передан XML Nmap
        if nmap_xml:
            print(f"[+] Поиск эксплойтов для результатов Nmap")
            
            # Создаем временный файл для XML
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp_file:
                tmp_file.write(nmap_xml)
                xml_filename = tmp_file.name
            
            # Команда для searchsploit с XML
            cmd = f"searchsploit --nmap {xml_filename} {base_options}"
            
        # Если передан прямой запрос
        elif query:
            print(f"[+] Поиск эксплойтов для запроса: {query}")
            cmd = f"searchsploit {query} {base_options}"
            
        # Если указана цель
        elif target:
            print(f"[+] Поиск эксплойтов для цели: {target}")
            cmd = f"searchsploit {target} {base_options}"
            
        else:
            return {
                'success': False,
                'error': 'Не указана цель, XML Nmap или запрос для поиска'
            }
        
        print(f"[+] Выполняю: {cmd}")
        
        # Выполняем поиск
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=300  # 5 минут таймаут
        )
        
        response = {
            'success': result.returncode == 0,
            'command': cmd,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }
        
        # Очистка временного файла
        if 'xml_filename' in locals() and os.path.exists(xml_filename):
            os.unlink(xml_filename)
        
        return response
        
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Searchsploit timeout (превышено время выполнения)'
        }
    except Exception as e:
        # Очистка в случае ошибки
        if 'xml_filename' in locals() and os.path.exists(xml_filename):
            os.unlink(xml_filename)
            
        return {
            'success': False,
            'error': f'Unexpected error: {str(e)}'
        }
