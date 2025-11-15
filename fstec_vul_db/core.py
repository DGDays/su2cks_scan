import redis
import json
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET
import requests
from io import BytesIO
from zipfile import ZipFile
from typing import List, Dict, Optional

# Сертификат МинЦифры
CORE_DIR = Path(__file__).parent
CERT_PATH = CORE_DIR / "cert" / "russian_trusted_combined_ca_pem.crt"


class VulnerabilityDB:
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        decode_responses: bool = True,
        source_url: str = None,
    ):
        """
        Инициализация СУБД Redis.

        Аргументы:
            host: ip/host redis
            port: порт redis
            db: номер БД redis (0-15)
            decode_responses: Если истина, выводит питоновскую строку, иначе, байты
        """
        self.source_url = (
            source_url or "https://bdu.fstec.ru/files/documents/vulxml.zip"
        )

        try:
            self.r = redis.Redis(
                host=host,
                port=port,
                db=db,
                decode_responses=True,
                encoding="utf-8",
            )
            # Проверяем соединение
            self.r.ping()
        except redis.ConnectionError as e:
            raise ValueError(f"Could not connect to Redis: {e}")

        # Проверяем существование БД. Если нет, инициализируем
        if not self.r.exists("lastUpdated"):
            self._initialize_db()

    def _initialize_db(self) -> None:
        # Инициализация БД из xml с сайта ФСТЭК
        """
        Структура REDIS:
        vuln:
            vul_id:
                name
                description
                identifier
                last_upd_date
                publication_date
                severity
                solution

                softs:
                    [
                        {
                        name
                        vendor
                        version
                        platform
                        },
                        ...
                    ]
            ...
        """
        """
        Структура REDIS:
        vuln:
            vul_id:
                name
                description
                identifier
                last_upd_date
                publication_date
                severity
                solution

                softs:
                    [
                        {
                        name
                        vendor
                        version
                        platform
                        },
                        ...
                    ]
            ...
        """

        try:
            response = requests.get(self.source_url, timeout=30, verify=CERT_PATH)
            response.raise_for_status()

            with ZipFile(BytesIO(response.content)) as zip_file:
                xml_path = "export/vulxml.xml"

                # Открываем файл xml в архиве
                if xml_path in zip_file.namelist():
                    with zip_file.open(xml_path) as xml_file:
                        tree = ET.parse(xml_file)
                        vulns = tree.getroot()

                        # Устанавливаем дату и время последнего обновления
                        current_datetime = datetime.now().isoformat()
                        self.r.set("lastUpdated", current_datetime)

                        # Записываем уязвимости
                        if vulns is not None:  # Added safety check
                            for vul in vulns.findall("vul"):
                                self._store_vulnerability(vul)
                        else:
                            print("Warning: No 'vulnerabilities' element found in XML")

        except requests.exceptions.RequestException as e:
            raise ValueError(f"Не удалось скачать БД ФСТЭК: {e}")
        except Exception as e:
            raise ValueError(f"Не удалось инициализировать БД REDIS: {e}")

    def _store_vulnerability(self, vul_element: ET.Element) -> None:
        # Запись конкретной уязвимости в Redis
        vul_id = vul_element.findtext("identifier")
        if not vul_id:
            return

        # Базовое описание уязвимости
        vul_data = {
            "name": vul_element.findtext("name"),
            "description": vul_element.findtext("description"),
            "identifier": vul_id,
            "last_upd_date": vul_element.findtext("last_upd_date"),
            "publication_date": vul_element.findtext("publication_date"),
            "severity": vul_element.findtext("severity"),
            "solution": vul_element.findtext("solution"),
        }

        # Записываем питоновский словарь в Redis через mapping
        mapping = {k: v or "" for k, v in vul_data.items()}
        self.r.hset(f"vuln:{vul_id}", mapping=mapping)

        # В xml "vulnerable_software" перечисляет уязвимые версии программ
        vuln_soft = vul_element.find("vulnerable_software")
        if vuln_soft is not None:
            for soft_element in vuln_soft.findall("soft"):
                soft_data = {
                    "name": soft_element.findtext("name"),
                    "vendor": soft_element.findtext("vendor"),
                    "version": soft_element.findtext("version"),
                    "platform": soft_element.findtext("platform"),
                }

                # Записываем данные о уязвимой версии в json, чтобы упростить структуру БД
                json_data = json.dumps(soft_data)
                self.r.rpush(f"vuln:{vul_id}:softs", json_data)

                # Задаём группу уязвимостей, с одинаковыми названиями программ и версиями для быстрого поиска
                # по названию программы и её версии
                if soft_data["name"] and soft_data["version"]:
                    index_key = f"idx:{soft_data['name'].lower()}:{soft_data['version'].lower()}"
                    self.r.sadd(index_key, vul_id)

    def get_last_updated(self) -> Optional[str]:
        # Получаем данные о дате создания БД
        return self.r.get("lastUpdated")

    def get_vuln_by_id(self, vuln_id: str) -> Optional[Dict]:
        # Получаем данные об уязвимости по её идентификатору (BDU:0000-00000)
        vuln_data = self.r.hgetall(f"vuln:{vuln_id}")
        if not vuln_data:
            return None

        # Получаем массив "softs" - список уязвимых версий
        soft_list_key = f"vuln:{vuln_id}:softs"
        soft_jsons = self.r.lrange(soft_list_key, 0, -1)

        # Переводим полученные строки json в питоновский словарь
        software_list = []
        for soft_json in soft_jsons:
            soft_data = json.loads(soft_json)
            software_list.append(soft_data)

        vuln_data["software_list"] = software_list
        return vuln_data

    def find_vulnerabilities(
        self, software_name: str, software_version: str
    ) -> List[Dict]:
        # Получаем идентификаторы уязвимостей по ранее созданным группам уязвимостей (сгруппированы по одному названию софта и версии)
        index_key = f"idx:{software_name.lower()}:{software_version.lower()}"
        vuln_ids = self.r.smembers(index_key)

        if not vuln_ids:
            return []

        # Получаем более подробные данные для каждой найденной уязвимости
        results = []
        for vuln_id in vuln_ids:
            vuln_data = self.get_vuln_by_id(vuln_id)
            if vuln_data:
                results.append(vuln_data)

        return results

    def clear_database(self) -> None:
        keys = self.r.keys("vuln:*")
        keys_date = self.r.keys("lastUpdated")
        if keys:
            self.r.delete(*keys)

        if keys_date:
            self.r.delete(*keys_date)
