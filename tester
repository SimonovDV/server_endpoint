#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import base64
import time
import getpass
import shutil
import tempfile
import atexit
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import requests

class SecureDataExchangeTester:
    """
    Основной класс тестировщика API для безопасного обмена данными.
    
    Класс предоставляет функционал для тестирования различных эндпоинтов API,
    управления ключами шифрования, отправки запросов и обработки ответов.
    Поддерживает два режима вывода информации: стандартный и расширенный.
    """
    
    def __init__(self):
        """Инициализация тестировщика API"""
        # Базовые настройки подключения
        self.SERVER_URL = "http://192.168.0.19:8000"
        self.TOKEN = "1234"
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Режим вывода информации (0 - стандартный, 1 - расширенный)
        self.output_mode = 0
        
        # Определение базовой директории в зависимости от способа запуска
        if getattr(sys, 'frozen', False):
            # Если программа запущена как исполняемый файл (.exe)
            self.base_dir = os.path.dirname(sys.executable)
            self.is_exe = True
        else:
            # Если программа запущена как Python-скрипт
            self.base_dir = self.script_dir
            self.is_exe = False
            
        # Пути к рабочим директориям
        self.keys_dir = os.path.join(self.base_dir, "keys")
        self.files_dir = os.path.join(self.base_dir, "files")
        self.temp_keys_dir = None
        
        # Создание необходимых директорий если они не существуют
        os.makedirs(self.keys_dir, exist_ok=True)
        os.makedirs(self.files_dir, exist_ok=True)
        
        # Настройка системы ключей
        self.setup_keys()
        
        # Регистрация функции очистки при завершении программы
        atexit.register(self.cleanup_temp_keys)
    
    def setup_keys(self):
        """
        Настройка системы ключей безопасности.
        
        Выполняет следующие действия:
        1. Очистка старых временных ключей
        2. Создание новой временной директории для ключей
        3. Проверка наличия публичного ключа сервера
        4. Копирование ключей во временную директорию
        
        Временное хранение ключей повышает безопасность работы программы.
        """
        print("Настройка ключей безопасности...")
        
        # Очистка старых временных ключей
        self.cleanup_old_temp_keys()
        
        # Создание новой временной директории для ключей
        self.temp_keys_dir = tempfile.mkdtemp(prefix="api_tester_keys_")
        print(f"Создана временная папка для ключей: {self.temp_keys_dir}")
        
        # Проверка и создание публичного ключа если необходимо
        self.ensure_public_key()
        
        # Копирование ключей во временную директорию
        self.copy_keys_to_temp()
        
        # Обновление пути к директории с ключами
        self.keys_dir = self.temp_keys_dir
        
        print("Ключи безопасности настроены успешно!")
    
    def cleanup_old_temp_keys(self):
        """
        Очистка старых временных директорий с ключами.
        
        Метод ищет в системной временной директории все папки,
        начинающиеся с "api_tester_keys_", и удаляет их.
        Это предотвращает накопление старых ключей в системе.
        """
        temp_dir = tempfile.gettempdir()
        
        # Поиск и удаление старых временных папок с ключами
        for item in os.listdir(temp_dir):
            item_path = os.path.join(temp_dir, item)
            if os.path.isdir(item_path) and item.startswith("api_tester_keys_"):
                try:
                    print(f"Удаление старой временной папки: {item}")
                    shutil.rmtree(item_path)
                except Exception as e:
                    print(f"Ошибка при удалении {item}: {e}")
    
    def copy_keys_to_temp(self):
        """
        Копирование ключей из основной директории во временную.
        
        Метод копирует все файлы с расширением .pem из основной
        директории ключей во временную директорию для работы.
        
        Returns:
            bool: True если копирование выполнено успешно, False в противном случае
        """
        source_keys_dir = os.path.join(self.base_dir, "keys")
        
        # Проверка существования исходной директории
        if not os.path.exists(source_keys_dir):
            print(f"Ошибка: Исходная папка ключей не найдена: {source_keys_dir}")
            return False
        
        # Копирование всех PEM файлов
        copied_files = []
        for file_name in os.listdir(source_keys_dir):
            if file_name.endswith('.pem'):
                source_path = os.path.join(source_keys_dir, file_name)
                dest_path = os.path.join(self.temp_keys_dir, file_name)
                
                try:
                    shutil.copy2(source_path, dest_path)
                    copied_files.append(file_name)
                    print(f"Скопирован ключ: {file_name}")
                except Exception as e:
                    print(f"Ошибка при копировании {file_name}: {e}")
        
        # Проверка наличия скопированных файлов
        if not copied_files:
            print("Предупреждение: Не найдено файлов ключей для копирования")
            return False
        
        print(f"Скопировано ключей: {len(copied_files)}")
        return True
    
    def ensure_public_key(self):
        """
        Создание тестового публичного ключа сервера если он отсутствует.
        
        Метод проверяет наличие файла public_server.pem в основной директории.
        Если файл отсутствует, создается тестовый RSA ключ для демонстрационных целей.
        """
        public_key_path = os.path.join(self.base_dir, "keys", "public_server.pem")
        
        # Создание тестового ключа если он отсутствует
        if not os.path.exists(public_key_path):
            print(f"Создание тестового публичного ключа...")
            print(f"Путь: {public_key_path}")
            
            # Создание директории если она не существует
            os.makedirs(os.path.dirname(public_key_path), exist_ok=True)
            
            # Генерация RSA ключевой пары
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            public_key = private_key.public_key()
            
            # Сохранение публичного ключа в файл
            with open(public_key_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            print("Тестовый публичный ключ создан!")
            print("ВАЖНО: Для работы с реальным сервером замените файл public_server.pem на настоящий публичный ключ сервера")
            print()
    
    def cleanup_temp_keys(self):
        """
        Очистка временных ключей при завершении работы программы.
        
        Метод удаляет временную директорию с ключами при завершении
        работы программы для обеспечения безопасности.
        """
        if self.temp_keys_dir and os.path.exists(self.temp_keys_dir):
            try:
                print(f"Очистка временных ключей...")
                shutil.rmtree(self.temp_keys_dir)
                print(f"Временная папка ключей удалена: {self.temp_keys_dir}")
            except Exception as e:
                print(f"Ошибка при удалении временной папки ключей: {e}")
    
    def clear_screen(self):
        """Очистка экрана консоли в зависимости от операционной системы"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def wait_for_key(self, message="Нажмите любую клавишу для продолжения..."):
        """
        Ожидание нажатия любой клавиши пользователем.
        
        Args:
            message (str): Сообщение для отображения пользователю
        """
        print(f"\n{message}")
        if os.name == 'nt':
            # Для Windows
            import msvcrt
            msvcrt.getch()
        else:
            # Для Linux/MacOS
            import termios
            import tty
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    def get_current_date(self):
        """
        Получение текущей даты в формате DD.MM.YYYY.
        
        Returns:
            str: Текущая дата в формате DD.MM.YYYY
        """
        return datetime.now().strftime("%d.%m.%Y")
    
    def input_with_default(self, prompt, default_value):
        """
        Ввод значения с подсказкой значения по умолчанию.
        
        Args:
            prompt (str): Текст подсказки для ввода
            default_value (str): Значение по умолчанию
            
        Returns:
            str: Введенное пользователем значение или значение по умолчанию
        """
        user_input = input(f"{prompt} [по умолчанию: {default_value}]: ").strip()
        return user_input if user_input else default_value
    
    def validate_date(self, date_str):
        """
        Проверка корректности даты в формате DD.MM.YYYY.
        
        Args:
            date_str (str): Дата для проверки
            
        Returns:
            bool: True если дата корректна, False в противном случае
        """
        try:
            day, month, year = map(int, date_str.split('.'))
            datetime(year, month, day)
            return True
        except:
            return False
    
    def input_date(self, prompt):
        """
        Ввод даты с текущей датой в качестве значения по умолчанию.
        
        Args:
            prompt (str): Текст подсказки для ввода
            
        Returns:
            str: Корректная дата в формате DD.MM.YYYY
        """
        current_date = self.get_current_date()
        while True:
            date_input = self.input_with_default(prompt, current_date)
            if self.validate_date(date_input):
                return date_input
            print("Неверный формат даты! Используйте формат DD.MM.YYYY")
    
    def generate_signature(self):
        """
        Генерация цифровой подписи для аутентификации запросов.
        
        Метод создает подпись с использованием публичного ключа сервера.
        Подпись включает токен и время истечения действия.
        
        Returns:
            str: Base64-кодированная подпись или None в случае ошибки
        """
        try:
            # Загрузка публичного ключа сервера
            public_key_path = os.path.join(self.keys_dir, "public_server.pem")
            if not os.path.exists(public_key_path):
                print("Ошибка: Файл публичного ключа не найден!")
                print(f"Путь: {public_key_path}")
                return None
            
            with open(public_key_path, 'rb') as f:
                server_public_key = serialization.load_pem_public_key(f.read())
            
            # Создание данных для подписи
            current_time = int(time.time())
            expiry_time = current_time + 300  # Подпись действует 5 минут
            signature_data = f'{self.TOKEN}.{expiry_time}'
            
            # Шифрование данных с использованием RSA
            encrypted = server_public_key.encrypt(
                signature_data.encode('utf-8'),
                padding.PKCS1v15()
            )
            
            # Кодирование в Base64
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print(f"Ошибка генерации подписи: {e}")
            return None
    
    def print_request_info(self, url, headers, data):
        """
        Вывод информации о запросе в зависимости от режима вывода.
        
        Args:
            url (str): URL запроса
            headers (dict): Заголовки запроса
            data (dict): Данные запроса
        """
        # Пропуск вывода в стандартном режиме
        if self.output_mode == 0:
            return
            
        print("\n" + "="*80)
        print("ЗАПРОС:")
        print("="*80)
        print(f"URL: {url}")
        print("\nЗаголовки:")
        for key, value in headers.items():
            if key == 'Signature' and len(value) > 100:
                print(f"  {key}: {value[:50]}...{value[-50:]}")
            else:
                print(f"  {key}: {value}")
        
        print("\nТело запроса (JSON):")
        print("-"*40)
        if data:
            try:
                # Форматирование JSON для читаемости
                json_str = json.dumps(data, ensure_ascii=False, indent=2)
                # Усечение больших данных Base64
                if 'data' in data and isinstance(data['data'], str) and len(data['data']) > 500:
                    truncated_data = data.copy()
                    truncated_data['data'] = f"[BASE64_DATA: {len(data['data'])} символов]"
                    json_str = json.dumps(truncated_data, ensure_ascii=False, indent=2)
                print(json_str)
            except:
                print(json.dumps(data, ensure_ascii=False))
        else:
            print("{}")
        print("="*80)
    
    def print_response_info(self, response):
        """
        Вывод информации об ответе сервера.
        
        Args:
            response: Объект ответа requests
        """
        # Стандартный режим: показываем только JSON ответа
        if self.output_mode == 0:
            print("\n" + "="*80)
            print("ОТВЕТ СЕРВЕРА:")
            print("="*80)
            print(f"Статус код: {response.status_code}")
            
            print("\nТело ответа:")
            print("-"*40)
            try:
                response_json = response.json()
                print(json.dumps(response_json, ensure_ascii=False, indent=2))
            except:
                print(response.text[:1000])
                if len(response.text) > 1000:
                    print(f"... [еще {len(response.text) - 1000} символов]")
            print("="*80)
            return
            
        # Расширенный режим: полная информация
        print("\n" + "="*80)
        print("ОТВЕТ СЕРВЕРА:")
        print("="*80)
        print(f"Статус код: {response.status_code}")
        print(f"Заголовки ответа:")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")
        
        print("\nТело ответа:")
        print("-"*40)
        try:
            response_json = response.json()
            print(json.dumps(response_json, ensure_ascii=False, indent=2))
        except:
            print(response.text[:1000])
            if len(response.text) > 1000:
                print(f"... [еще {len(response.text) - 1000} символов]")
        print("="*80)
    
    def send_request(self, endpoint, data):
        """
        Отправка HTTP запроса на сервер.
        
        Args:
            endpoint (str): Конечная точка API
            data (dict): Данные для отправки
            
        Returns:
            dict or None: Ответ сервера в формате JSON или None в случае ошибки
        """
        # Генерация подписи для аутентификации
        signature = self.generate_signature()
        if not signature:
            return None
        
        # Формирование заголовков запроса
        headers = {
            "Content-Type": "application/json",
            "Token": f"Bearer {self.TOKEN}",
            "Signature": signature
        }
        
        url = f"{self.SERVER_URL}{endpoint}"
        
        # Вывод информации о запросе
        self.print_request_info(url, headers, data)
        
        try:
            print(f"\nОтправка запроса...")
            # Отправка POST запроса с таймаутом 30 секунд
            response = requests.post(url, headers=headers, json=data, timeout=30)
            
            # Вывод информации об ответе
            self.print_response_info(response)
            
            # Проверка статуса ответа
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"\n" + "!"*80)
            print("ОШИБКА ПРИ ВЫПОЛНЕНИИ ЗАПРОСА:")
            print("!"*80)
            print(f"Тип ошибки: {type(e).__name__}")
            print(f"Описание: {e}")
            
            # Вывод деталей ошибки если они доступны
            if hasattr(e, 'response') and e.response is not None:
                print(f"\nДетали ответа с ошибкой:")
                print(f"Статус код: {e.response.status_code}")
                print(f"Текст ответа: {e.response.text[:500]}")
            
            print("!"*80)
            return None
    
    def ask_output_mode(self):
        """
        Запрос режима вывода информации у пользователя.
        
        Returns:
            int: 0 для стандартного режима, 1 для расширенного
        """
        print("\nВыберите режим вывода информации:")
        print("  0. Стандартный - показывать только JSON ответа")
        print("  1. Расширенный - показывать все детали запросов и ответов")
        
        while True:
            choice = input("\nВыберите режим (0 или 1): ").strip()
            if choice in ['0', '1']:
                return int(choice)
            print("Неверный выбор! Введите 0 или 1.")
    
    def test_user_by_phone(self):
        """
        Тестирование эндпоинта /user/by-phone.
        
        Метод позволяет найти пользователя по номеру телефона.
        Запрашивает у пользователя режим вывода информации.
        """
        self.clear_screen()
        print("=== Тестирование эндпоинта /user/by-phone ===")
        print("=" * 50)
        
        # Запрос режима вывода
        self.output_mode = self.ask_output_mode()
        
        # Ввод номера телефона
        phone = input("Введите номер телефона: ").strip()
        if not phone:
            print("Ошибка: Номер телефона не может быть пустым!")
            self.wait_for_key()
            return
        
        # Формирование и отправка запроса
        data = {"phone": phone}
        result = self.send_request("/user/by-phone", data)
        
        # Вывод результата выполнения
        if result:
            print("\nЗапрос успешно выполнен")
        else:
            print("\nЗапрос завершился с ошибкой")
        
        self.wait_for_key()
    
    def test_user_update(self):
        """
        Тестирование эндпоинта /user/update.
        
        Метод позволяет обновить данные пользователя (email и пароль).
        """
        self.clear_screen()
        print("=== Тестирование эндпоинта /user/update ===")
        print("=" * 50)
        
        # Запрос режима вывода
        self.output_mode = self.ask_output_mode()
        
        # Ввод данных пользователя
        user_id = input("Введите ID пользователя: ").strip()
        email = input("Введите email: ").strip()
        password = input("Введите пароль: ").strip()
        
        # Формирование данных запроса
        data = {
            "id": user_id,
            "email": email,
            "password": password
        }
        
        # Отправка запроса
        result = self.send_request("/user/update", data)
        
        # Вывод результата
        if result:
            print("\nЗапрос успешно выполнен")
        else:
            print("\nЗапрос завершился с ошибкой")
        
        self.wait_for_key()
    
    def test_user_mailing(self):
        """
        Тестирование эндпоинта /user/mailing.
        
        Метод позволяет управлять согласием пользователя на email рассылку.
        """
        self.clear_screen()
        print("=== Тестирование эндпоинта /user/mailing ===")
        print("=" * 50)
        
        # Запрос режима вывода
        self.output_mode = self.ask_output_mode()
        
        # Ввод ID пользователя
        user_id = input("Введите ID пользователя: ").strip()
        if not user_id:
            print("Ошибка: ID пользователя не может быть пустым!")
            self.wait_for_key()
            return
        
        # Выбор согласия на рассылку
        print("\nСогласие на email рассылку:")
        print("  1. Да (true) - пользователь СОГЛАСЕН получать рассылку")
        print("  0. Нет (false) - пользователь НЕ согласен получать рассылку")
        
        while True:
            choice = input("\nВыберите вариант (1 или 0): ").strip()
            if choice in ['0', '1']:
                consent = choice == '1'
                break
            print("Неверный выбор! Введите 1 или 0.")
        
        # Информация о выбранном варианте
        if consent:
            print("\nВыбран вариант: СОГЛАСИЕ на рассылку (true)")
            print("Пользователь будет получать email уведомления и рассылки")
        else:
            print("\nВыбран вариант: ОТКАЗ от рассылки (false)")
            print("Пользователь НЕ будет получать email уведомления и рассылки")
        
        # Формирование и отправка запроса
        data = {
            "user_id": user_id,
            "consent_to_mailing": consent
        }
        
        result = self.send_request("/user/mailing", data)
        
        # Вывод результата
        if result:
            print("\nЗапрос успешно выполнен")
        else:
            print("\nЗапрос завершился с ошибкой")
        
        self.wait_for_key()
    
    def test_ticket_list(self):
        """
        Тестирование эндпоинта /ticket/list.
        
        Метод позволяет получить список залоговых билетов пользователя.
        Поддерживает фильтрацию по статусу.
        """
        self.clear_screen()
        print("=== Тестирование эндпоинта /ticket/list ===")
        print("=" * 50)
        
        # Запрос режима вывода
        self.output_mode = self.ask_output_mode()
        
        # Ввод данных
        user_id = input("Введите ID пользователя: ").strip()
        status = input("Введите статус залоговых билетов (опционально, нажмите Enter чтобы пропустить): ").strip()
        
        if not user_id:
            print("Ошибка: ID пользователя не может быть пустым!")
            self.wait_for_key()
            return
        
        # Формирование данных запроса
        data = {"user_id": user_id}
        if status:
            data["status"] = status
        
        # Отправка запроса
        result = self.send_request("/ticket/list", data)
        
        # Вывод результата
        if result:
            print("\nЗапрос успешно выполнен")
        else:
            print("\nЗапрос завершился с ошибкой")
        
        self.wait_for_key()
    
    def test_payment_set(self):
        """
        Тестирование эндпоинта /payment/set.
        
        Метод позволяет отправить информацию о платежах.
        Поддерживает множественные платежи (до 10).
        """
        self.clear_screen()
        print("=== Тестирование эндпоинта /payment/set ===")
        print("=" * 50)
        
        # Запрос режима вывода
        self.output_mode = self.ask_output_mode()
        
        def validate_amount(amount_str):
            """Проверка корректности суммы платежа"""
            try:
                amount = float(amount_str)
                return amount > 0 and amount <= 1000000
            except:
                return False
        
        # Ввод базовой информации
        transaction_id = input("Введите ID транзакции: ").strip()
        user_id = input("Введите ID пользователя: ").strip()
        
        if not transaction_id or not user_id:
            print("Ошибка: ID транзакции и ID пользователя обязательны!")
            self.wait_for_key()
            return
        
        # Сбор информации о платежах
        payments = []
        
        print("\nДобавление платежей:")
        print("=" * 50)
        
        while True:
            print(f"\nПлатеж #{len(payments) + 1}")
            
            # Ввод ID залогового билета
            ticket_id = input("ID залогового билета (ticket_id): ").strip()
            if not ticket_id:
                print("Ошибка: ID залогового билета не может быть пустым!")
                continue
            
            # Ввод даты платежа
            date_input = self.input_date("Дата платежа")
            
            # Ввод суммы платежа
            while True:
                amount_input = input("Сумма платежа (пример: 100.00): ").strip()
                if validate_amount(amount_input):
                    amount = float(amount_input)
                    break
                print("Сумма должна быть положительным числом (макс. 2 знака после запятой)")
            
            # Добавление платежа в список
            payment = {
                "ticket_id": ticket_id,
                "date": date_input,
                "amount": amount
            }
            
            payments.append(payment)
            
            # Вывод информации о добавленном платеже
            print(f"\nПлатеж добавлен:")
            print(f"   ID билета: {ticket_id}")
            print(f"   Дата: {date_input}")
            print(f"   Сумма: {amount}")
            
            # Запрос на добавление следующего платежа
            if len(payments) < 10:
                print("\nДобавить еще один платеж?")
                print("  1. Да - добавить следующий платеж")
                print("  0. Нет - завершить ввод платежей")
                
                while True:
                    add_more = input("Выберите вариант (1 или 0): ").strip()
                    if add_more in ['0', '1']:
                        break
                    print("Неверный выбор! Введите 1 или 0.")
                
                if add_more == '0':
                    break
            else:
                print("Достигнуто максимальное количество платежей (10)")
                break
        
        # Расчет общей суммы платежей
        amount_due = sum(payment['amount'] for payment in payments)
        
        # Вывод итоговой информации
        print("\n" + "=" * 50)
        print("ИТОГОВАЯ ИНФОРМАЦИЯ:")
        print(f"Количество платежей: {len(payments)}")
        print(f"Общая сумма к оплате: {amount_due:.2f}")
        
        for payment in payments:
            print(f"  - Билет {payment['ticket_id']}: {payment['amount']} (дата: {payment['date']})")
        
        # Подтверждение отправки
        print("\nПодтверждение отправки:")
        print("  1. Да - отправить платежи на сервер")
        print("  0. Нет - отменить отправку")
        
        while True:
            confirm = input("Подтвердите отправку (1 или 0): ").strip()
            if confirm in ['0', '1']:
                break
            print("Неверный выбор! Введите 1 или 0.")
        
        if confirm == '0':
            print("Отправка отменена пользователем")
            self.wait_for_key()
            return
        
        # Формирование итоговых данных
        data = {
            "transaction_id": transaction_id,
            "user_id": user_id,
            "amount_due": amount_due,
            "payments": payments
        }
        
        print(f"\nПодготовка данных для отправки...")
        print(f"ID транзакции: {transaction_id}")
        print(f"ID пользователя: {user_id}")
        print(f"Количество платежей: {len(payments)}")
        print(f"Сумма к оплате: {amount_due:.2f}")
        
        # Отправка запроса
        result = self.send_request("/payment/set", data)
        
        # Вывод результата
        if result:
            print("\nЗапрос успешно выполнен")
        else:
            print("\nЗапрос завершился с ошибкой")
        
        self.wait_for_key()
    
    def test_login(self):
        """
        Тестирование эндпоинта /user/login.
        
        Метод позволяет выполнить аутентификацию пользователя
        по номеру телефона и паролю.
        """
        self.clear_screen()
        print("=== Тестирование эндпоинта /user/login ===")
        print("=" * 50)
        
        # Запрос режима вывода
        self.output_mode = self.ask_output_mode()
        
        # Ввод учетных данных
        phone = input("Введите номер телефона: ").strip()
        password = getpass.getpass("Введите пароль: ")
        
        if not phone or not password:
            print("Ошибка: Номер телефона и пароль обязательны!")
            self.wait_for_key()
            return
        
        # Формирование и отправка запроса
        data = {
            "phone": phone,
            "password": password
        }
        
        result = self.send_request("/user/login", data)
        
        # Вывод результата
        if result:
            print("\nЗапрос успешно выполнен")
        else:
            print("\nЗапрос завершился с ошибкой")
        
        self.wait_for_key()
    
    def test_document_load(self):
        """
        Тестирование эндпоинта /document/load.
        
        Метод позволяет загрузить документ на сервер.
        Документ конвертируется в Base64 формат.
        user_id - обязательное поле.
        description, type - опциональные параметры.
        """
        self.clear_screen()
        print("=== Тестирование эндпоинта /document/load ===")
        print("=" * 50)
        
        # Запрос режима вывода
        self.output_mode = self.ask_output_mode()
        
        # Проверка существования директории с файлами
        if not os.path.exists(self.files_dir):
            print("Ошибка: Папка 'files' не найдена!")
            print(f"Создайте папку 'files' в директории скрипта и добавьте файлы.")
            print(f"Путь к папке скрипта: {self.script_dir}")
            self.wait_for_key()
            return
        
        # Получение списка доступных файлов
        files = [f for f in os.listdir(self.files_dir) if os.path.isfile(os.path.join(self.files_dir, f))]
        
        if not files:
            print("Ошибка: Папка 'files' пуста!")
            print("Добавьте файлы в папку 'files'.")
            print(f"Путь к папке: {self.files_dir}")
            self.wait_for_key()
            return
        
        # Вывод списка доступных файлов
        print("\nДоступные файлы в папке 'files':")
        for i, file in enumerate(files, 1):
            file_path = os.path.join(self.files_dir, file)
            file_size = os.path.getsize(file_path) / 1024
            print(f"  {i}. {file} ({file_size:.2f} KB)")
        
        # Выбор файла пользователем
        while True:
            try:
                choice = input(f"\nВыберите файл по номеру (1-{len(files)}): ").strip()
                file_index = int(choice) - 1
                if 0 <= file_index < len(files):
                    break
                print(f"Неверный номер! Введите число от 1 до {len(files)}")
            except ValueError:
                print("Неверный формат! Введите число.")
        
        # Получение информации о выбранном файле
        selected_file = files[file_index]
        file_path = os.path.join(self.files_dir, selected_file)
        print(f"Выбран файл: {selected_file}")
        
        # Определение расширения файла
        extension = os.path.splitext(selected_file)[1].lstrip('.')
        if not extension:
            extension = "unknown"
        
        print(f"Автоматически определено расширение: {extension}")
        
        # Ввод обязательного параметра user_id
        while True:
            user_id = input("Введите ID пользователя (обязательное поле): ").strip()
            if user_id:
                break
            print("Ошибка: ID пользователя не может быть пустым! Попробуйте снова.")
        
        # Ввод опциональных параметров
        description = input("Введите описание документа (опционально, нажмите Enter чтобы пропустить): ").strip()
        doc_type = input("Введите тип документа (опционально, нажмите Enter чтобы пропустить): ").strip()
        
        # Конвертация файла в Base64
        print("\nКонвертация файла в Base64...")
        try:
            with open(file_path, 'rb') as f:
                file_bytes = f.read()
            base64_data = base64.b64encode(file_bytes).decode('utf-8')
            print(f"Файл успешно конвертирован в Base64 ({len(base64_data)} символов)")
        except Exception as e:
            print(f"Ошибка при чтении файла: {e}")
            self.wait_for_key()
            return
        
        # Формирование данных для отправки (user_id теперь обязательное поле)
        data = {
            "name": selected_file,
            "extension": extension,
            "data": base64_data,
            "user_id": user_id  # Обязательное поле
        }
        
        # Добавление опциональных параметров
        if description:
            data["description"] = description
        if doc_type:
            data["type"] = doc_type
        
        # Подготовка к отправке
        print(f"\nПодготовка данных для отправки...")
        print(f"Имя файла: {selected_file}")
        print(f"Размер файла: {os.path.getsize(file_path) / 1024:.2f} KB")
        print(f"ID пользователя: {user_id}")
        if description:
            print(f"Описание: {description}")
        if doc_type:
            print(f"Тип документа: {doc_type}")
        
        # Отправка запроса
        result = self.send_request("/document/load", data)
        
        # Вывод результата
        if result:
            print("\nЗапрос успешно выполнен")
        else:
            print("\nЗапрос завершился с ошибкой")
        
        self.wait_for_key()
        
    def test_document_signed(self):
        """
        Тестирование эндпоинта /document/signed.
        
        Метод позволяет обновить статус подписи документа.
        """
        self.clear_screen()
        print("=== Тестирование эндпоинта /document/signed ===")
        print("=" * 50)
        
        # Запрос режима вывода
        self.output_mode = self.ask_output_mode()
        
        # Ввод ID документа
        document_id = input("Введите ID документа: ").strip()
        if not document_id:
            print("Ошибка: ID документа не может быть пустым!")
            self.wait_for_key()
            return
        
        # Выбор статуса подписи
        print("\nСтатус подписи документа:")
        print("  1. Подписан (true) - документ ПОДПИСАН")
        print("  0. Не подписан (false) - документ НЕ подписан")
        
        while True:
            choice = input("\nВыберите статус (1 или 0): ").strip()
            if choice in ['0', '1']:
                is_signed = choice == '1'
                break
            print("Неверный выбор! Введите 1 или 0.")
        
        # Информация о выбранном статусе
        if is_signed:
            print("\nВыбран вариант: Документ ПОДПИСАН (true)")
            print("Документ считается юридически действительным")
        else:
            print("\nВыбран вариант: Документ НЕ подписан (false)")
            print("Документ требует подписи для юридической силы")
        
        # Формирование и отправка запроса
        data = {
            "document_id": document_id,
            "is_signed": is_signed
        }
        
        print(f"\nПодготовка данных для отправки...")
        print(f"ID документа: {document_id}")
        print(f"Статус подписи: {is_signed}")
        
        result = self.send_request("/document/signed", data)
        
        # Вывод результата
        if result:
            print("\nЗапрос успешно выполнен")
        else:
            print("\nЗапрос завершился с ошибкой")
        
        self.wait_for_key()
    
    def test_document_list(self):
        """
        Тестирование эндпоинта /document/list.
        
        Метод позволяет получить список документов пользователя.
        """
        self.clear_screen()
        print("=== Тестирование эндпоинта /document/list ===")
        print("=" * 50)
        
        # Запрос режима вывода
        self.output_mode = self.ask_output_mode()
        
        # Ввод ID пользователя
        user_id = input("Введите ID пользователя: ").strip()
        if not user_id:
            print("Ошибка: ID пользователя не может быть пустым!")
            self.wait_for_key()
            return
        
        # Отправка запроса
        data = {"user_id": user_id}
        result = self.send_request("/document/list", data)
        
        # Вывод результата
        if result:
            print("\nЗапрос успешно выполнен")
        else:
            print("\nЗапрос завершился с ошибкой")
        
        self.wait_for_key()


    def test_payment_calculate_distribution(self):
        """
        Тестирование эндпоинта /payment/calculate-distribution.
        
        Метод позволяет рассчитать распределение платежа по залоговым билетам.
        Процесс тестирования:
        1. Запрос номера билета (ticket_id)
        2. Запрос суммы платежа (amount)
        3. Запрос продолжения ввода (по умолчанию 0 - не продолжать)
        4. Формирование и вывод JSON запроса
        5. Отправка запроса на сервер и получение ответа
        6. Вывод ответа JSON на экран
        """
        self.clear_screen()
        print("=== Тестирование эндпоинта /payment/calculate-distribution ===")
        print("=" * 50)
        
        # Запрос режима вывода
        self.output_mode = self.ask_output_mode()
        
        print("РАСЧЕТ РАСПРЕДЕЛЕНИЯ ПЛАТЕЖА ПО ЗАЛОГОВЫМ БИЛЕТАМ")
        print("=" * 50)
        print("Введите информацию о платежах по залоговым билетам.")
        print("Процесс ввода можно завершить в любой момент.")
        print()
        
        # Сбор информации о платежах
        payments = []
        ticket_count = 0
        
        while True:
            ticket_count += 1
            print(f"\n[{ticket_count}] Добавление информации о платеже по залоговому билету")
            print("-" * 40)
            
            # 1. Запрос номера билета (ticket_id)
            while True:
                ticket_id = input("Номер залогового билета (ticket_id): ").strip()
                if not ticket_id:
                    if ticket_count == 1:
                        print("Ошибка: Необходимо ввести хотя бы один залоговый билет!")
                        continue
                    else:
                        print("Завершение ввода...")
                        break
                
                # Проверка на уникальность ticket_id
                ticket_exists = any(p['ticket_id'] == ticket_id for p in payments)
                if ticket_exists:
                    print("Ошибка: Этот номер билета уже был добавлен!")
                    continue
                
                break
            
            if not ticket_id:
                break
            
            # 2. Запрос суммы платежа (amount)
            while True:
                try:
                    amount_str = input("Сумма платежа (amount): ").strip()
                    if not amount_str:
                        print("Ошибка: Сумма платежа не может быть пустой!")
                        continue
                    
                    amount = float(amount_str)
                    if amount <= 0:
                        print("Ошибка: Сумма платежа должна быть положительным числом!")
                        continue
                    break
                except ValueError:
                    print("Ошибка: Введите корректное число (например: 1500.50)")
            
            # Добавление информации о платеже в список
            payment_data = {
                "ticket_id": ticket_id,
                "amount": amount
            }
            
            payments.append(payment_data)
            print(f"✓ Добавлен платеж: ticket_id={ticket_id}, amount={amount}")
            
            # 3. Запрос продолжения ввода (значение по умолчанию 0 - не продолжать)
            print("\nДобавить еще один платеж?")
            print("  1. Да - добавить еще один платеж")
            print("  0. Нет - завершить ввод и перейти к расчету (по умолчанию)")
            
            continue_choice = input("Выберите вариант (1 или 0, по умолчанию 0): ").strip()
            
            # Используем значение по умолчанию 0, если пользователь просто нажал Enter
            if continue_choice == '':
                continue_choice = '0'
                print("Использовано значение по умолчанию: 0 (не продолжать)")
            
            if continue_choice == '0':
                print(f"\nВвод завершен. Добавлено платежей: {len(payments)}")
                break
            elif continue_choice != '1':
                print(f"Неверный выбор '{continue_choice}'. Используем значение по умолчанию: 0")
                print(f"\nВвод завершен. Добавлено платежей: {len(payments)}")
                break
        
        # Проверка наличия данных
        if not payments:
            print("Ошибка: Не введено ни одного платежа!")
            self.wait_for_key()
            return
        
        # 4. Формирование JSON запроса
        print("\n" + "="*60)
        print("ФОРМИРОВАНИЕ JSON ЗАПРОСА")
        print("="*60)
        
        # Формирование массива платежей согласно требуемой структуре
        request_data = payments  # Просто массив платежей
        
        # Вывод JSON запроса
        print("Сформированный JSON запрос:")
        print("-"*40)
        json_request = json.dumps(request_data, ensure_ascii=False, indent=2)
        print(json_request)
        print("-"*40)
        
        # Подсчет итогов
        total_amount = sum(p['amount'] for p in payments)
        print(f"\nИТОГО:")
        print(f"Количество платежей: {len(payments)}")
        print(f"Общая сумма: {total_amount:.2f}")
        
        # Подтверждение отправки
        print("\nПодтверждение отправки запроса:")
        print("  1. Да - отправить запрос на сервер")
        print("  0. Нет - отменить отправку (по умолчанию)")
        
        confirm_choice = input("Подтвердите отправку (1 или 0, по умолчанию 0): ").strip()
        
        # Используем значение по умолчанию 0, если пользователь просто нажал Enter
        if confirm_choice == '':
            confirm_choice = '0'
            print("Использовано значение по умолчанию: 0 (отменить отправку)")
        
        if confirm_choice == '0':
            print("Отправка отменена пользователем")
            self.wait_for_key()
            return
        elif confirm_choice != '1':
            print(f"Неверный выбор '{confirm_choice}'. Используем значение по умолчанию: 0")
            print("Отправка отменена")
            self.wait_for_key()
            return
        
        # 5. Отправка запроса на сервер
        print("\n" + "="*60)
        print("ОТПРАВКА ЗАПРОСА НА СЕРВЕР")
        print("="*60)
        
        result = self.send_request("/payment/calculate-distribution", request_data)
        
        # 6. Вывод ответа JSON на экран
        if result:
            print("\n" + "="*60)
            print("ОТВЕТ ОТ СЕРВЕРА")
            print("="*60)
            
            # Вывод в красивом формате JSON
            if isinstance(result, dict) and "status" in result:
                if result["status"] == "success":
                    print("✓ Запрос выполнен успешно")
                    
                    # Вывод расчетов распределения платежа
                    if "tickets" in result and result["tickets"]:
                        print("\nРАСЧЕТ РАСПРЕДЕЛЕНИЯ ПЛАТЕЖА:")
                        print("-"*60)
                        
                        total_original = 0
                        total_distributed = 0
                        
                        for ticket_data in result["tickets"]:
                            if isinstance(ticket_data, dict):
                                ticket_info = ticket_data.get("ticket", {})
                                distribution_info = ticket_data.get("distribution", {})
                                
                                ticket_id = ticket_info.get("id", ticket_info.get("number", "N/A"))
                                original_payment = distribution_info.get("original_payment", 0)
                                distributed_amount = distribution_info.get("distributed_amount", 0)
                                remaining_debt = distribution_info.get("remaining_debt", 0)
                                
                                total_original += original_payment
                                total_distributed += distributed_amount
                                
                                print(f"\nЗалоговый билет: {ticket_id}")
                                print(f"  Исходный платеж: {original_payment:.2f}")
                                print(f"  Распределенная сумма: {distributed_amount:.2f}")
                                print(f"  Остаток долга: {remaining_debt:.2f}")
                        
                        print("\n" + "-"*60)
                        print(f"ИТОГО:")
                        print(f"  Общая сумма платежей: {total_original:.2f}")
                        print(f"  Общая распределенная сумма: {total_distributed:.2f}")
                        print(f"  Разница: {total_original - total_distributed:.2f}")
                    else:
                        print("В ответе нет данных о распределении платежа")
                
                elif result["status"] == "error":
                    print("✗ Запрос завершился с ошибкой")
                    if "message" in result:
                        print(f"Сообщение об ошибке: {result['message']}")
            elif isinstance(result, list):
                print("✓ Запрос выполнен успешно")
                print(f"Получено {len(result)} результатов расчета")
            else:
                print("Неожиданный формат ответа")
                
            # Вывод полного JSON ответа
            print("\nПОЛНЫЙ JSON ОТВЕТ:")
            print("-"*60)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print("\n✗ Ошибка: Не удалось получить ответ от сервера")
        
        print("\n" + "="*60)
        self.wait_for_key()

    def show_menu(self):
        """
        Отображение главного меню программы.
        
        Метод предоставляет пользователю выбор теста для выполнения.
        Циклично отображает меню до выбора опции выхода.
        """
        menu_items = [
            ("Поиск пользователя (/user/by-phone)", self.test_user_by_phone),
            ("Обновление данных (/user/update)", self.test_user_update),
            ("Email рассылка (/user/mailing)", self.test_user_mailing),
            ("Залоговые билеты (/ticket/list)", self.test_ticket_list),
            ("Оплата (/payment/set)", self.test_payment_set),
            ("Расчет распределения платежа (/payment/calculate-distribution)", self.test_payment_calculate_distribution),  # НОВЫЙ ПУНКТ
            ("Вход в систему (/user/login)", self.test_login),
            ("Загрузка документа (/document/load)", self.test_document_load),
            ("Подпись документа (/document/signed)", self.test_document_signed),
            ("Список документов (/document/list)", self.test_document_list),
        ]
        
        while True:
            self.clear_screen()
            print("========================================")
            print("    ТЕСТЕР API - ГЛАВНОЕ МЕНЮ")
            print("========================================")
            print()
            
            print("Доступные тесты:")
            print()
            
            # Вывод списка доступных тестов
            for i, (name, _) in enumerate(menu_items, 1):
                print(f"  {i}. [+] {name}")
            
            print()
            print("  0. Выход")
            print()
            print(f"Статус: {len(menu_items)}/{len(menu_items)} тестов доступно")
            print("========================================")
            
            # Обработка выбора пользователя
            choice = input("\nВыберите тест (0-10): ").strip()  # Изменено на 0-10
            
            if choice == '0':
                print("\nЗавершение работы...")
                break
            elif choice.isdigit() and 1 <= int(choice) <= len(menu_items):
                menu_items[int(choice) - 1][1]()
            else:
                print(f"Неверный выбор! Введите число от 0 до {len(menu_items)}.")
                self.wait_for_key()

def main():
    """
    Основная функция запуска программы.
    
    Обрабатывает исключения и обеспечивает корректное завершение работы.
    """
    try:
        # Создание экземпляра тестировщика
        tester = SecureDataExchangeTester()
        # Запуск главного меню
        tester.show_menu()
    except KeyboardInterrupt:
        # Обработка прерывания от клавиатуры (Ctrl+C)
        print("\n\nЗавершение работы...")
    except Exception as e:
        # Обработка неожиданных исключений
        print(f"Критическая ошибка: {e}")
        input("Нажмите Enter для выхода...")

if __name__ == "__main__":
    main()
