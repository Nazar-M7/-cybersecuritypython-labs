# Lab 02 - Variant 11 (Аудитор ARP-таблиць та виявлення ARP-Spoofing)

## Встановлення залежностей
Усі команди виконуються з кореня репозиторію в активованому середовищі з ЛР №1:
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Структура вхідних даних
З архіву `lab2_data.zip` використано каталог `data_v11`, його вміст розміщено в `labs/lab02/data/`:
```
labs/lab02/data/
└── arp_table.csv    # знімок ARP-кешу (вхідний файл)
```
Після запуску `analyze` у цьому ж каталозі з'являються `arp_security_alerts.json` (звіт) та `audit.log` (журнал).

## Запуск демонстрації ООП
```bash
python -m labs.lab02.main demo
```

## Запуск утиліти аналізу
```bash
python -m labs.lab02.main analyze --arp-file labs/lab02/data/arp_table.csv --detect-spoofing --output-json labs/lab02/data/arp_security_alerts.json --log-file labs/lab02/data/audit.log
```

### Опис аргументів:
- `--arp-file`: Шлях до вхідного CSV-файлу із знімком ARP-таблиці для аналізу.
- `--detect-spoofing`: Прапорець, який вмикає перевірку на наявність ARP-Spoofing (пошук декількох IP-адрес, прив'язаних до однієї MAC-адреси).
- `--output-json`: Шлях до JSON-файлу, у який будуть збережені знайдені критичні конфлікти (результати виявлення атак).
- `--log-file`: Шлях до файлу для запису логів аудиту виконання програми.

## Вхідні дані
Програма приймає на вхід файл у форматі CSV із наступними колонками:
- `IP Address`
- `MAC Address`
- `Interface`
- `Type`

## Поведінка при помилках
- Не вказано обов'язковий `--arp-file` — `argparse` виводить підказку та завершує роботу.
- Файл не знайдено (`FileNotFoundError`) або немає прав на читання (`PermissionError`) — повідомлення в лог, аналіз не виконується.
- Пошкоджений CSV (`csv.Error`) — повідомлення про помилку розбору.
- Рядки з некоректною IP- або MAC-адресою не зупиняють роботу, а враховуються в лічильнику `Invalid Syntax`.
- Помилка запису JSON-звіту (`PermissionError`, `OSError`) — повідомлення в лог, результати аналізу вже виведені в консоль.
