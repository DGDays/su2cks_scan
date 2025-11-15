def search_exploits(target=None, nmap_xml=None, query=None, options=None):
    """
    Функция для поиска эксплойтов через searchsploit
    """
    try:
        # Базовые опции
        base_options = options or " -j "
        
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
        print("\n\n")
        for i in response.get("output").split("\n\n\n"):
            res_exp = json.loads(i)["RESULTS_EXPLOIT"]
            for j in res_exp:
                print(j["Title"],"\n",j["EDB-ID"],"\n",j["Codes"])
                out.append(j["Title"]+"\n"+j["EDB-ID"]+"\n"+j["Codes"])
        out = '\n'.join(out)
        response['output'] = out
        print("\n\n")
        print(os.system(f"cat {xml_filename}"))
        # Очистка временного файла
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
        return {
            'success': False,
            'error': f'Unexpected error: {str(e)}'
        }