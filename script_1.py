from flask import Flask, render_template_string
import json

app = Flask(__name__)

# Ваши JSON данные
exploit_data = {
    "SEARCH": "microsoft windows rpc",
    "DB_PATH_EXPLOIT": "/usr/share/exploitdb",
    "RESULTS_EXPLOIT": [
        {"Title":"Microsoft Windows - 'Lsasrv.dll' RPC Remote Buffer Overflow (MS04-011)","EDB-ID":"293","Date_Published":"2004-04-24","Date_Added":"2004-04-23","Date_Updated":"","Author":"sbaa","Type":"remote","Platform":"windows","Port":"445","Verified":"1","Codes":"OSVDB-5248;CVE-2003-0533;MS04-011","Tags":"","Aliases":"","Screenshot":"","Application":"","Source":"","Path":"/usr/share/exploitdb/exploits/windows/remote/293.c"},
        {"Title":"Microsoft Windows - 'RPC DCOM' Long Filename Overflow (MS03-026)","EDB-ID":"100","Date_Published":"2003-09-16","Date_Added":"2003-09-15","Date_Updated":"","Author":"ey4s","Type":"remote","Platform":"windows","Port":"135","Verified":"1","Codes":"OSVDB-2100;CVE-2003-0352;MS03-026","Tags":"","Aliases":"","Screenshot":"","Application":"","Source":"","Path":"/usr/share/exploitdb/exploits/windows/remote/100.c"},
        {"Title":"Microsoft Windows - 'RPC DCOM' Remote (1)","EDB-ID":"69","Date_Published":"2003-07-29","Date_Added":"2003-07-28","Date_Updated":"2016-09-29","Author":"pHrail","Type":"remote","Platform":"windows","Port":"135","Verified":"1","Codes":"OSVDB-11460;CVE-2003-0605","Tags":"","Aliases":"","Screenshot":"","Application":"","Source":"","Path":"/usr/share/exploitdb/exploits/windows/remote/69.c"},
        
    ],
    "DB_PATH_SHELLCODE": "/usr/share/exploitdb",
    "RESULTS_SHELLCODE": []
}

# HTML шаблон с CSS стилями
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Exploit Codes - {{ search_query }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            color: white;
        }
        
        .header h1 {
            font-size: 2.2em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .search-info {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            color: white;
            text-align: center;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #1e3c72;
            display: block;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9em;
        }
        
        .codes-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .code-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border-left: 4px solid #1e3c72;
        }
        
        .code-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        
        .exploit-title {
            font-size: 1em;
            color: #2c3e50;
            margin-bottom: 15px;
            line-height: 1.4;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        
        .codes-container {
            margin-top: 10px;
        }
        
        .code-item {
            display: inline-block;
            background: linear-gradient(45deg, #1e3c72, #2a5298);
            color: white;
            padding: 6px 12px;
            margin: 4px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }
        
        .code-badge {
            display: inline-flex;
            align-items: center;
            margin: 2px;
        }
        
        .metadata {
            margin-top: 15px;
            padding-top: 10px;
            border-top: 1px dashed #eee;
            font-size: 0.8em;
            color: #666;
        }
        
        .meta-item {
            margin: 3px 0;
        }
        
        .no-codes {
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 20px;
        }
        
        .filter-buttons {
            text-align: center;
            margin-bottom: 20px;
        }
        
        .filter-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 8px 16px;
            margin: 0 5px;
            border-radius: 20px;
            cursor: pointer;
            transition: background 0.3s ease;
        }
        
        .filter-btn:hover, .filter-btn.active {
            background: rgba(255,255,255,0.3);
        }
        
        .unique-codes-section {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-top: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .unique-codes-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Exploit Code Analysis</h1>
            <p>Анализ уязвимостей и их идентификаторов</p>
        </div>
        
        <div class="search-info">
            <h3>Поисковый запрос: "{{ search_query }}"</h3>
            <p>Найдено эксплойтов: {{ total_exploits }} | Уникальных кодов: {{ unique_codes_count }}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <span class="stat-number">{{ total_exploits }}</span>
                <span class="stat-label">Всего эксплойтов</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">{{ exploits_with_codes }}</span>
                <span class="stat-label">С кодами уязвимостей</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">{{ unique_codes_count }}</span>
                <span class="stat-label">Уникальных кодов</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">{{ cve_count }}</span>
                <span class="stat-label">CVE идентификаторов</span>
            </div>
        </div>
        
        <div class="filter-buttons">
            <button class="filter-btn active" onclick="filterCodes('all')">Все</button>
            <button class="filter-btn" onclick="filterCodes('CVE')">Только CVE</button>
            <button class="filter-btn" onclick="filterCodes('MS')">Только MS</button>
            <button class="filter-btn" onclick="filterCodes('OSVDB')">Только OSVDB</button>
        </div>
        
        <div class="codes-grid">
            {% for exploit in exploits %}
            <div class="code-card" data-codes="{{ exploit.codes_string }}">
                <div class="exploit-title">
                    <strong>{{ exploit.edb_id }}</strong> - {{ exploit.title[:80] }}{% if exploit.title|length > 80 %}...{% endif %}
                </div>
                
                <div class="codes-container">
                    {% if exploit.codes_list %}
                        {% for code in exploit.codes_list %}
                        <span class="code-item {{ code.lower().split('-')[0] }}">{{ code }}</span>
                        {% endfor %}
                    {% else %}
                        <div class="no-codes">Нет кодов уязвимостей</div>
                    {% endif %}
                </div>
                
                <div class="metadata">
                    <div class="meta-item"><strong>Тип:</strong> {{ exploit.type }}</div>
                    <div class="meta-item"><strong>Платформа:</strong> {{ exploit.platform }}</div>
                    <div class="meta-item"><strong>Автор:</strong> {{ exploit.author }}</div>
                    <div class="meta-item"><strong>Дата:</strong> {{ exploit.date }}</div>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <div class="unique-codes-section">
            <h3>📊 Все уникальные коды уязвимостей</h3>
            <div class="unique-codes-grid">
                {% for code in all_unique_codes %}
                <span class="code-item {{ code.lower().split('-')[0] }}">{{ code }}</span>
                {% endfor %}
            </div>
        </div>
    </div>

    <script>
        function filterCodes(type) {
            const cards = document.querySelectorAll('.code-card');
            const buttons = document.querySelectorAll('.filter-btn');
            
            // Убираем активный класс со всех кнопок
            buttons.forEach(btn => btn.classList.remove('active'));
            // Добавляем активный класс нажатой кнопке
            event.target.classList.add('active');
            
            cards.forEach(card => {
                const codesString = card.getAttribute('data-codes').toLowerCase();
                
                switch(type) {
                    case 'all':
                        card.style.display = 'block';
                        break;
                    case 'CVE':
                        card.style.display = codesString.includes('cve') ? 'block' : 'none';
                        break;
                    case 'MS':
                        card.style.display = codesString.includes('ms') ? 'block' : 'none';
                        break;
                    case 'OSVDB':
                        card.style.display = codesString.includes('osvdb') ? 'block' : 'none';
                        break;
                }
            });
        }
    </script>
</body>
</html>
"""

def extract_codes_info(data):
    """Извлекает и анализирует информацию о кодах уязвимостей"""
    exploits = []
    all_codes = set()
    cve_codes = set()
    
    for exploit in data["RESULTS_EXPLOIT"]:
        codes_string = [exploit.get("Title",""),exploit.get("Codes", "")]
        codes_list = [code.strip() for code in codes_string.split(";") if code.strip()] if codes_string else []
        
        # Собираем все коды
        for code in codes_list:
            all_codes.add(code)
            if code.startswith("CVE-"):
                cve_codes.add(code)
        
        exploits.append({
            "title": exploit.get("Title", ""),
            "edb_id": f"EDB-{exploit.get('EDB-ID', 'N/A')}",
            "codes_string": codes_string,
            "codes_list": codes_list,
            "type": exploit.get("Type", "N/A"),
            "platform": exploit.get("Platform", "N/A"),
            "author": exploit.get("Author", "N/A"),
            "date": exploit.get("Date_Published", "N/A")
        })
    
    return {
        "exploits": exploits,
        "all_unique_codes": sorted(list(all_codes)),
        "unique_codes_count": len(all_codes),
        "cve_count": len(cve_codes),
        "total_exploits": len(data["RESULTS_EXPLOIT"]),
        "exploits_with_codes": len([e for e in exploits if e["codes_list"]]),
        "search_query": data["SEARCH"]
    }

@app.route('/')
def index():
    # Анализируем данные
    analysis = extract_codes_info(exploit_data)
    
    # Рендерим шаблон
    return render_template_string(HTML_TEMPLATE, **analysis)

@app.route('/api/codes')
def api_codes():
    """API endpoint для получения всех кодов в JSON формате"""
    analysis = extract_codes_info(exploit_data)
    return {
        "search_query": analysis["search_query"],
        "total_exploits": analysis["total_exploits"],
        "unique_codes": analysis["all_unique_codes"],
        "cve_codes": [code for code in analysis["all_unique_codes"] if code.startswith("CVE-")],
        "ms_codes": [code for code in analysis["all_unique_codes"] if code.startswith("MS")],
        "osvdb_codes": [code for code in analysis["all_unique_codes"] if code.startswith("OSVDB-")]
    }

@app.route('/api/exploits')
def api_exploits():
    """API endpoint для получения всех эксплойтов с кодами"""
    analysis = extract_codes_info(exploit_data)
    return {
        "exploits": analysis["exploits"],
        "summary": {
            "total": analysis["total_exploits"],
            "with_codes": analysis["exploits_with_codes"],
            "unique_codes_count": analysis["unique_codes_count"]
        }
    }


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)