Pentest Scanner
Обязательные утилиты для установки:
nmap
nikto
gobuster
python3
python3-pip
arp-scan

Установка на Kali/Debian/Ubuntu:
sudo apt update
sudo apt install -y nmap nikto gobuster python3 python3-pip arp-scan

Установка wkhtmltopdf для PDF отчетов:
Скачать бинарник:
wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox-0.12.6-1.linux-amd64.tar.xz

Распаковать:
tar -xvf wkhtmltox-0.12.6-1.linux-amd64.tar.xz

Установить:
sudo cp wkhtmltox/bin/wkhtmltopdf /usr/local/bin/
sudo chmod +x /usr/local/bin/wkhtmltopdf

Проверить:
wkhtmltopdf --version

Python зависимости:
Flask==2.3.3
pdfkit==1.0.0

Установка:
pip install Flask==2.3.3 pdfkit==1.0.0

Запуск:
python app.py

Приложение будет доступно по адресу: http://localhost:5000

Форматы целей для сканирования:
Одиночный IP: 192.168.1.1

Домен: example.com

Сеть: 192.168.1.0/24

