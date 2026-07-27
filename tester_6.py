#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import base64
import time
import shutil
import tempfile
import atexit
import argparse
from pathlib import Path
from datetime import datetime

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class SecureDataExchangeTester:
    """
    Тестер API безопасного обмена данными.

    Сохранено:
    - загрузка конфигурации из JSON через аргумент командной строки;
    - отображение актуально подключенного сервера;
    - интерактивное изменение настроек подключения;
    - работа с ключами и генерация подписи.

    Добавлено:
    - аргумент запуска --keys-dir для указания каталога с .pem ключами;
    - по умолчанию каталог ключей: ./keys относительно каталога запуска;
    - подробный вывод параметров текущего запуска понятным языком;
    - более надежная работа с путями в Windows.
    """

    def __init__(self, config_path=None, keys_dir=None):
        self.default_server_ip = "192.168.0.19"
        self.default_server_port = 8000
        self.default_scheme = "http"
        self.default_token = "1234"
        self.default_timeout = 30

        self.server_ip = self.default_server_ip
        self.server_port = self.default_server_port
        self.server_scheme = self.default_scheme
        self.TOKEN = self.default_token
        self.request_timeout = self.default_timeout
        self.output_mode = 0
        self.config_path = self.normalize_optional_path(config_path)
        self.keys_dir_argument = keys_dir

        self.is_windows = (os.name == 'nt')
        self.script_dir = self.get_script_dir()
        self.base_dir = self.get_base_dir()
        self.launch_dir = self.get_launch_dir()

        self.source_keys_dir = self.resolve_keys_dir(keys_dir)
        self.keys_dir = self.source_keys_dir
        self.files_dir = self.normalize_path(Path(self.base_dir) / 'files')
        self.temp_keys_dir = None

        self.ensure_directory(self.source_keys_dir)
        self.ensure_directory(self.files_dir)

        self.load_settings_from_json(self.config_path)
        self.rebuild_server_url()
        self.setup_keys()
        atexit.register(self.cleanup_temp_keys)

    def normalize_path(self, path_value):
        return str(Path(path_value).expanduser().resolve(strict=False))

    def normalize_optional_path(self, path_value):
        if not path_value:
            return None
        return self.normalize_path(path_value)

    def ensure_directory(self, path_value):
        Path(path_value).mkdir(parents=True, exist_ok=True)

    def get_script_dir(self):
        if getattr(sys, 'frozen', False):
            return self.normalize_path(Path(sys.executable).resolve().parent)
        return self.normalize_path(Path(__file__).resolve().parent)

    def get_base_dir(self):
        if getattr(sys, 'frozen', False):
            return self.normalize_path(Path(sys.executable).resolve().parent)
        return self.script_dir

    def get_launch_dir(self):
        return self.normalize_path(Path.cwd())

    def resolve_keys_dir(self, keys_dir):
        if keys_dir:
            candidate = Path(keys_dir).expanduser()
            if not candidate.is_absolute():
                candidate = Path(self.launch_dir) / candidate
            return self.normalize_path(candidate)
        return self.normalize_path(Path(self.launch_dir) / 'keys')

    def setup_keys(self):
        self.cleanup_old_temp_keys()
        self.temp_keys_dir = self.normalize_path(Path(tempfile.mkdtemp(prefix="api_tester_keys_")))
        self.ensure_public_key()
        self.copy_keys_to_temp()
        self.keys_dir = self.temp_keys_dir

    def cleanup_old_temp_keys(self):
        temp_dir = Path(tempfile.gettempdir())
        for item in temp_dir.iterdir():
            if item.is_dir() and item.name.startswith("api_tester_keys_"):
                try:
                    shutil.rmtree(str(item))
                except Exception:
                    pass

    def copy_keys_to_temp(self):
        source_dir = Path(self.source_keys_dir)
        target_dir = Path(self.temp_keys_dir)

        if not source_dir.exists():
            return False

        copied = 0
        for pem_file in source_dir.glob('*.pem'):
            try:
                shutil.copy2(str(pem_file), str(target_dir / pem_file.name))
                copied += 1
            except Exception:
                pass
        return copied > 0

    def ensure_public_key(self):
        public_key_path = Path(self.source_keys_dir) / 'public_server.pem'
        if public_key_path.exists():
            return

        public_key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

    def cleanup_temp_keys(self):
        if self.temp_keys_dir and Path(self.temp_keys_dir).exists():
            try:
                shutil.rmtree(self.temp_keys_dir)
            except Exception:
                pass

    def rebuild_server_url(self):
        self.SERVER_URL = f"{self.server_scheme}://{self.server_ip}:{self.server_port}"

    def load_settings_from_json(self, config_path):
        """
        Загрузка настроек из JSON-файла, переданного через аргумент командной строки.
        """
        if not config_path:
            return

        config_file = Path(config_path)
        if not config_file.exists():
            print(f"Предупреждение: файл конфигурации не найден: {config_path}")
            return

        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.server_ip = str(data.get('server_ip') or data.get('ip') or data.get('host') or self.server_ip)
            self.server_port = int(data.get('server_port') or data.get('port') or self.server_port)
            self.server_scheme = str(data.get('scheme') or data.get('protocol') or self.server_scheme)
            self.TOKEN = str(data.get('token') or self.TOKEN)
            self.request_timeout = int(data.get('request_timeout') or data.get('timeout') or self.request_timeout)

            print(f"Загружена конфигурация из файла: {self.normalize_path(config_file)}")
        except Exception as e:
            print(f"Предупреждение: не удалось загрузить настройки из JSON: {e}")

    def clear_screen(self):
        os.system('cls' if self.is_windows else 'clear')

    def wait_for_key(self, message="Нажмите Enter для продолжения..."):
        input(f"\n{message}")

    def get_current_date(self):
        return datetime.now().strftime("%d.%m.%Y")

    def input_with_default(self, prompt, default_value):
        value = input(f"{prompt} [по умолчанию: {default_value}]: ").strip()
        return value if value else default_value

    def input_int_with_default(self, prompt, default_value):
        while True:
            value = self.input_with_default(prompt, str(default_value))
            try:
                return int(value)
            except ValueError:
                print("Ошибка: требуется целое число.")

    def input_bool01(self, prompt, default_value=0):
        while True:
            value = self.input_with_default(prompt, str(default_value))
            if value in ('0', '1'):
                return int(value)
            print("Ошибка: допустимы только 0 или 1.")

    def get_script_name(self):
        return os.path.basename(sys.argv[0]) or os.path.basename(__file__)

    def describe_launch_parameters(self):
        script_name = self.get_script_name()
        config_display = self.config_path if self.config_path else 'не задан, используются встроенные настройки по умолчанию'
        keys_arg_display = self.keys_dir_argument if self.keys_dir_argument else 'не задан, поэтому используется ./keys относительно каталога запуска'
        frozen_display = 'да' if getattr(sys, 'frozen', False) else 'нет'
        os_display = 'Windows' if self.is_windows else 'Linux/macOS'

        print("\n" + "=" * 80)
        print("ПАРАМЕТРЫ ТЕКУЩЕГО ЗАПУСКА ТЕСТЕРА")
        print("=" * 80)
        print("1. Общая информация о запуске")
        print(f"   - Имя файла запуска: {script_name}")
        print(f"   - Полная командная строка: {' '.join(sys.argv)}")
        print(f"   - Операционная система: {os_display}")
        print(f"   - Запуск из собранного EXE: {frozen_display}")
        print()
        print("2. Файл конфигурации сервера")
        print(f"   - Аргумент config: {config_display}")
        print("   - Если файл конфигурации не задан, тестер использует встроенные значения")
        print("     для IP, порта, схемы, токена и таймаута.")
        print()
        print("3. Откуда тестер считает текущий каталог запуска")
        print(f"   - Текущий каталог запуска: {self.launch_dir}")
        print("   - Если параметр --keys-dir не указан, то каталог ключей берется как ./keys")
        print("     именно относительно этого каталога запуска.")
        print()
        print("4. Где находится сам тестер")
        print(f"   - Каталог файла скрипта: {self.script_dir}")
        print(f"   - Базовый каталог программы: {self.base_dir}")
        print("   - Базовый каталог используется, например, для папки files.")
        print()
        print("5. Как определяется каталог ключей .pem")
        print(f"   - Аргумент --keys-dir: {keys_arg_display}")
        print(f"   - Исходный каталог ключей: {self.source_keys_dir}")
        print("   - Это основной каталог, откуда тестер читает ваши .pem-файлы.")
        print("   - Ожидаемый файл для подписи запросов: public_server.pem")
        print()
        print("6. Как тестер реально работает с ключами во время запуска")
        print(f"   - Временный рабочий каталог ключей: {self.keys_dir}")
        print("   - При старте тестер копирует .pem-файлы из исходного каталога во временный каталог,")
        print("     и дальше работает уже с этой временной копией.")
        print()
        print("7. Где тестер ищет файлы для загрузки")
        print(f"   - Каталог files: {self.files_dir}")
        print()
        print("8. Сетевые настройки, с которыми тестер запущен сейчас")
        print(f"   - Схема: {self.server_scheme}")
        print(f"   - IP адрес: {self.server_ip}")
        print(f"   - Порт: {self.server_port}")
        print(f"   - Базовый URL: {self.SERVER_URL}")
        print(f"   - Токен: {self.TOKEN}")
        print(f"   - Таймаут: {self.request_timeout} сек.")
        print("=" * 80)

    def print_startup_help(self):
        script_name = self.get_script_name()
        print("=" * 80)
        print("ТЕСТЕР API БЕЗОПАСНОГО ОБМЕНА ДАННЫМИ")
        print("=" * 80)
        print("Краткая инструкция запуска:")
        print(f"  python {script_name}")
        print(f"  python {script_name} config.json")
        print(f"  python {script_name} --keys-dir ./keys")
        print(f"  python {script_name} config.json --keys-dir D:/pem")
        print("\nПараметры запуска:")
        print("  config.json         - необязательный путь к JSON-файлу конфигурации")
        print("  --keys-dir PATH     - необязательный путь к каталогу с .pem ключами")
        print("\nДополнительно:")
        print(f"  - каталог ключей по умолчанию: {self.normalize_path(Path(self.launch_dir) / 'keys')}")
        print(f"  - исходный каталог ключей: {self.source_keys_dir}")
        print(f"  - рабочий каталог ключей: {self.keys_dir}")
        print(f"  - каталог файлов: {self.files_dir}")
        if self.config_path:
            print(f"  - загружена конфигурация: {self.config_path}")
        print("=" * 80)

    def print_current_settings(self):
        print("\nТекущие настройки:")
        print("-" * 60)
        print(f"Схема: {self.server_scheme}")
        print(f"IP адрес: {self.server_ip}")
        print(f"Порт: {self.server_port}")
        print(f"Базовый URL: {self.SERVER_URL}")
        print(f"Токен: {self.TOKEN}")
        print(f"Таймаут: {self.request_timeout} сек.")
        print(f"Режим вывода: {'краткий' if self.output_mode == 0 else 'полный'}")
        print(f"Каталог исходных ключей: {self.source_keys_dir}")
        print(f"Рабочий каталог ключей: {self.keys_dir}")
        print("-" * 60)

    def configure_connection_interactive(self):
        self.clear_screen()
        print("=" * 80)
        print("ИЗМЕНЕНИЕ НАСТРОЕК ПОДКЛЮЧЕНИЯ")
        print("=" * 80)
        self.print_current_settings()

        self.server_scheme = self.input_with_default("Введите схему подключения (http/https)", self.server_scheme)
        self.server_ip = self.input_with_default("Введите IP адрес сервера", self.server_ip)
        self.server_port = self.input_int_with_default("Введите порт сервера", self.server_port)
        self.TOKEN = self.input_with_default("Введите токен", self.TOKEN)
        self.request_timeout = self.input_int_with_default("Введите таймаут запроса в секундах", self.request_timeout)

        self.rebuild_server_url()

        print("\nНастройки успешно обновлены.")
        print(f"Актуально подключенный сервер: {self.SERVER_URL}")
        self.wait_for_key()

    def generate_signature(self):
        try:
            public_key_path = Path(self.keys_dir) / 'public_server.pem'
            if not public_key_path.exists():
                print(f"Ошибка: файл публичного ключа не найден: {self.normalize_path(public_key_path)}")
                return None

            with open(public_key_path, 'rb') as f:
                server_public_key = serialization.load_pem_public_key(f.read())

            expiry_time = int(time.time()) + 300
            signature_data = f'{self.TOKEN}.{expiry_time}'
            encrypted = server_public_key.encrypt(signature_data.encode('utf-8'), padding.PKCS1v15())
            return base64.b64encode(encrypted).decode('utf-8')

        except Exception as e:
            print(f"Ошибка генерации подписи: {e}")
            return None

    def print_request_info(self, url, headers, data):
        if self.output_mode == 0:
            return

        print("\n" + "=" * 80)
        print("ЗАПРОС")
        print("=" * 80)
        print(f"URL: {url}")

        print("\nЗаголовки:")
        for key, value in headers.items():
            if key == 'Signature' and len(value) > 100:
                print(f"  {key}: {value[:50]}...{value[-50:]}")
            else:
                print(f"  {key}: {value}")

        print("\nТело запроса:")
        print("-" * 40)
        print(json.dumps(data, ensure_ascii=False, indent=2) if data else "{}")
        print("=" * 80)

    def print_response_info(self, response):
        print("\n" + "=" * 80)
        print("ОТВЕТ СЕРВЕРА")
        print("=" * 80)
        print(f"Статус код: {response.status_code}")

        if self.output_mode == 1:
            print("Заголовки ответа:")
            for key, value in response.headers.items():
                print(f"  {key}: {value}")

        print("\nТело ответа:")
        print("-" * 40)
        try:
            print(json.dumps(response.json(), ensure_ascii=False, indent=2))
        except Exception:
            print(response.text[:1500])
        print("=" * 80)

    def send_request(self, endpoint, data, use_signature=True, method='POST'):
        headers = {
            "Content-Type": "application/json",
            "Token": f"Bearer {self.TOKEN}"
        }

        if use_signature:
            signature = self.generate_signature()
            if not signature:
                return None
            headers["Signature"] = signature

        url = f"{self.SERVER_URL}{endpoint}"
        self.print_request_info(url, headers, data)

        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=self.request_timeout)
            else:
                response = requests.post(url, headers=headers, json=data, timeout=self.request_timeout)

            self.print_response_info(response)

            try:
                return response.json()
            except Exception:
                return {"status_code": response.status_code, "text": response.text}

        except requests.exceptions.RequestException as e:
            print("\nОШИБКА ЗАПРОСА:", e)
            return None

    def ask_output_mode(self):
        print("\nВыберите режим вывода информации:")
        print("0. Краткий")
        print("1. Полный")

        while True:
            value = input("Выберите режим (0 или 1) [по умолчанию: 0]: ").strip() or '0'
            if value in ('0', '1'):
                return int(value)
            print("Ошибка: допустимы только 0 или 1.")

    def print_test_title(self, title):
        self.clear_screen()
        print("=" * 80)
        print(title)
        print("=" * 80)
        self.print_current_settings()

    def build_login_payload(self):
        phone = self.input_with_default("Введите номер телефона", "9991234567")
        password = self.input_with_default("Введите пароль", "123456")
        return {"phone": phone, "password": password}

    def test_user_by_phone(self):
        self.print_test_title("ТЕСТ ПОИСКА ПОЛЬЗОВАТЕЛЯ /user/by-phone")
        phone = self.input_with_default("Введите номер телефона", "9991234567")
        self.send_request("/user/by-phone", {"phone": phone})
        self.wait_for_key()

    def test_user_update(self):
        self.print_test_title("ТЕСТ ОБНОВЛЕНИЯ ДАННЫХ /user/update")
        user_id = self.input_with_default("Введите ID пользователя", "1")
        email = self.input_with_default("Введите email", "user@example.com")
        password = self.input_with_default("Введите пароль", "123456")
        payload = {
            "user_id": user_id,
            "email": email,
            "password": password
        }
        self.send_request("/user/update", payload)
        self.wait_for_key()

    def test_user_mailing(self):
        self.print_test_title("ТЕСТ EMAIL РАССЫЛКИ /user/mailing")
        user_id = self.input_with_default("Введите ID пользователя", "1")
        consent = self.input_bool01("Согласие на рассылку (0 - нет, 1 - да)", 1)
        payload = {
            "user_id": user_id,
            "consent_to_mailing": bool(consent)
        }
        self.send_request("/user/mailing", payload)
        self.wait_for_key()

    def test_ticket_list(self):
        self.print_test_title("ТЕСТ ЗАЛОГОВЫХ БИЛЕТОВ /ticket/list")
        user_id = self.input_with_default("Введите ID пользователя", "1")
        payload = {"user_id": user_id}

        if self.input_bool01("Передавать статус билета? (0 - нет, 1 - да)", 0) == 1:
            payload["status"] = self.input_with_default("Введите статус", "")

        self.send_request("/ticket/list", payload)
        self.wait_for_key()

    def test_payment_set(self):
        self.print_test_title("ТЕСТ ОПЛАТЫ /payment/set")
        amount = self.input_with_default("Введите сумму платежа", "1000")
        user_id = self.input_with_default("Введите ID пользователя", "1")
        payload = {
            "user_id": user_id,
            "amount": amount,
            "date": self.get_current_date()
        }
        self.send_request("/payment/set", payload)
        self.wait_for_key()

    def test_payment_calculate_distribution(self):
        self.print_test_title("ТЕСТ РАСЧЕТА РАСПРЕДЕЛЕНИЯ ПЛАТЕЖА /payment/calculate-distribution")
        amount = self.input_with_default("Введите сумму платежа", "1000")
        ticket_id = self.input_with_default("Введите ID билета", "1")
        request_data = {
            "amount": amount,
            "ticket_id": ticket_id
        }
        self.send_request("/payment/calculate-distribution", request_data)
        self.wait_for_key()

    def test_login(self):
        self.print_test_title("ТЕСТ ВХОДА В СИСТЕМУ /user/login")
        self.send_request("/user/login", self.build_login_payload(), use_signature=True)
        self.wait_for_key()

    def test_document_load(self):
        self.print_test_title("ТЕСТ ЗАГРУЗКИ ДОКУМЕНТА /document/load")

        if not Path(self.files_dir).is_dir():
            print(f"Ошибка: каталог с файлами не найден: {self.files_dir}")
            self.wait_for_key()
            return

        available_files = sorted(
            [
                str(Path(root) / file_name)
                for root, _, files in os.walk(self.files_dir)
                for file_name in files
            ]
        )

        if not available_files:
            print(f"Ошибка: в каталоге {self.files_dir} нет файлов для загрузки")
            self.wait_for_key()
            return

        print("\nДоступные файлы:\n")
        for index, path in enumerate(available_files, start=1):
            relative_path = os.path.relpath(path, self.files_dir)
            print(f" {index}. {relative_path}")

        choice = self.input_with_default("Выберите номер файла", "1")
        try:
            file_index = int(choice)
        except ValueError:
            print("Ошибка: требуется ввести номер файла.")
            self.wait_for_key()
            return

        if not 1 <= file_index <= len(available_files):
            print("Ошибка: выбран неизвестный номер файла.")
            self.wait_for_key()
            return

        file_path = available_files[file_index - 1]
        selected_name = os.path.basename(file_path)
        default_type = os.path.splitext(selected_name)[1].lstrip('.').lower() or 'bin'

        user_id = self.input_with_default("Введите ID пользователя", "1")
        description = self.input_with_default("Введите описание документа", f"Файл {selected_name}")
        doc_type = self.input_with_default("Введите тип документа", default_type)

        with open(file_path, 'rb') as f:
            encoded_data = base64.b64encode(f.read()).decode('utf-8')

        payload = {
            "user_id": user_id,
            "description": description,
            "type": doc_type,
            "name": selected_name,
            "data": encoded_data
        }

        self.send_request("/document/load", payload)
        self.wait_for_key()

    def test_document_signed(self):
        self.print_test_title("ТЕСТ ПОДПИСИ ДОКУМЕНТА /document/signed")
        document_id = self.input_with_default("Введите ID документа", "1")
        is_signed = self.input_bool01("Документ подписан? (0 - нет, 1 - да)", 1)

        payload = {
            "document_id": document_id,
            "is_signed": bool(is_signed)
        }

        self.send_request("/document/signed", payload)
        self.wait_for_key()

    def test_document_list(self):
        self.print_test_title("ТЕСТ СПИСКА ДОКУМЕНТОВ /document/list")
        user_id = self.input_with_default("Введите ID пользователя", "1")
        self.send_request("/document/list", {"user_id": user_id})
        self.wait_for_key()

    def show_menu(self):
        menu_items = [
            ("[+] Поиск пользователя (/user/by-phone)", self.test_user_by_phone),
            ("[+] Обновление данных (/user/update)", self.test_user_update),
            ("[+] Email рассылка (/user/mailing)", self.test_user_mailing),
            ("[+] Залоговые билеты (/ticket/list)", self.test_ticket_list),
            ("[+] Оплата (/payment/set)", self.test_payment_set),
            ("[+] Расчет распределения платежа (/payment/calculate-distribution)", self.test_payment_calculate_distribution),
            ("[+] Вход в систему (/user/login)", self.test_login),
            ("[+] Загрузка документа (/document/load)", self.test_document_load),
            ("[+] Подпись документа (/document/signed)", self.test_document_signed),
            ("[+] Список документов (/document/list)", self.test_document_list),
        ]

        while True:
            self.clear_screen()
            print("=" * 40)
            print("    ТЕСТЕР API - ГЛАВНОЕ МЕНЮ")
            print("=" * 40)
            print(f"\nАктуально подключенный сервер: {self.SERVER_URL}")
            print(f"Режим вывода: {'краткий' if self.output_mode == 0 else 'полный'}")
            if self.config_path:
                print(f"Файл конфигурации: {self.config_path}")
            print(f"Каталог ключей: {self.source_keys_dir}")
            print("\nДоступные тесты:\n")

            for index, (title, _) in enumerate(menu_items, start=1):
                print(f" {index}. {title}")

            print(f"\n {len(menu_items) + 1}. Изменить настройки подключения")
            print(" 0. Выход\n")
            print(f"Статус: {len(menu_items)}/{len(menu_items)} тестов доступно")
            print("=" * 40)

            choice = self.input_with_default("Выберите пункт меню", "0")
            if choice == '0':
                break

            try:
                numeric_choice = int(choice)
            except ValueError:
                print("Ошибка: требуется ввести номер пункта меню.")
                self.wait_for_key()
                continue

            if 1 <= numeric_choice <= len(menu_items):
                menu_items[numeric_choice - 1][1]()
            elif numeric_choice == len(menu_items) + 1:
                self.configure_connection_interactive()
            else:
                print("Ошибка: выбран неизвестный пункт меню.")
                self.wait_for_key()


def parse_arguments():
    parser = argparse.ArgumentParser(description="Тестер API безопасного обмена данными")
    parser.add_argument(
        'config',
        nargs='?',
        default=None,
        help='Необязательный путь к JSON-файлу конфигурации сервера'
    )
    parser.add_argument(
        '--keys-dir',
        dest='keys_dir',
        default=None,
        help='Необязательный путь к каталогу с .pem ключами; по умолчанию используется ./keys'
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    tester = SecureDataExchangeTester(config_path=args.config, keys_dir=args.keys_dir)
    tester.print_startup_help()
    tester.describe_launch_parameters()
    tester.output_mode = tester.ask_output_mode()
    tester.show_menu()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nРабота тестера прервана пользователем.")
