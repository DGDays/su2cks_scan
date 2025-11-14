import sys
import os

# Add the current directory to Python path so we can import the module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core import VulnerabilityDB


def main():
    print("Инициализируем БД...")
    try:
        db = VulnerabilityDB()
        print("Инициализация прошла успешно!")
    except Exception as e:
        print(f"Ошибка при инициализации: {e}")
        return

    print("\n" + "=" * 50)
    print("Проверяем поиск по идентификатору...")

    vuln_identifier = "BDU:2014-00001"

    print(f"Поиск по идентификатору: {vuln_identifier}")
    vulnerability = db.get_vuln_by_id(vuln_identifier)

    if vulnerability:
        print("Уязвимость найдена:")
        print(f"  Имя: {vulnerability.get('name', 'N/A')}")
        print(f"  Описание: {vulnerability.get('description', 'N/A')[:100]}...")
        print(f"  Опасность: {vulnerability.get('severity', 'N/A')}")
        print(
            f"  Количество затронутых версий: {len(vulnerability.get('software_list', []))}"
        )
    else:
        print(f"Не найдены уязвимости по идентификатору: {vuln_identifier}")

    print("\n" + "=" * 50)
    print("Проверяем поиск по программе и версии...")

    software_name = "Java Development Kit"
    software_version = "1.7.0 update 51"

    print(f"Поиск уязвимостей по программе: {software_name} {software_version}")
    vulnerabilities = db.find_vulnerabilities(software_name, software_version)

    print(f"Нашлось {len(vulnerabilities)} уязвимостей:")
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"  {i}. {vuln.get('identifier', 'N/A')} - {vuln.get('name', 'N/A')}")

    print("\n" + "=" * 50)
    print("Тест завершен!")


if __name__ == "__main__":
    main()
