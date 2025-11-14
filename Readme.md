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

# Установим зависимости
sudo apt update
sudo apt install -y xfonts-75dpi xfonts-base libjpeg-turbo8 libssl3 ca-certificates

# Скачаем правильную версию для Debian Bullseye/Bookworm
wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/wkhtmltox_0.12.6.1-3.bookworm_amd64.deb

# Установим
sudo dpkg -i wkhtmltox_*.deb
sudo apt install -f  # Исправим зависимости

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

