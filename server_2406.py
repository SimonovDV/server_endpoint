#!/usr/bin/env python3
"""
Secure Data Exchange Server
Веб-сервер для безопасного обмена данными между системами.

Основные функции:
- Аутентификация по Bearer token + RSA цифровым подписям
- Логирование в MSSQL БД, файл и консоль с маскированием чувствительных данных
- Health-check мониторинг состояния сервера и БД
- Подробный verbose-режим для отладки запросов/ответов
- Асинхронная обработка запросов с высокой производительностью

Архитектура:
1. Конфигурация - класс Config для хранения параметров сервера
2. Безопасность - аутентификация, RSA шифрование, валидация подписей
3. База данных - работа с MSSQL через pyodbc, выполнение запросов
4. Логирование - многоуровневое логирование (БД, файл, консоль)
5. Middleware - глобальная обработка запросов, аутентификация, логирование
6. API endpoints - обработчики HTTP запросов
7. Утилиты - вспомогательные функции для работы с данными

Ключевые endpoints:
- GET /health - проверка состояния сервера и БД
- POST /api/data - прием и обработка данных
- GET /api/data/{id} - получение данных по ID

Зависимости:
- aiohttp - асинхронный веб-сервер
- pyodbc - подключение к MSSQL
- cryptography - работа с RSA шифрованием
- argparse - обработка аргументов командной строки

Режимы работы:
- Обычный режим: базовое логирование ошибок и запуска
- Подробный режим (--verbose): полная информация о запросах/ответах

Использование:
  python3 server.py config.json          # обычный режим
  python3 server.py config.json --verbose # подробный режим
  python3 server.py --status            # проверка статуса сервера
"""

import asyncio
import json
import os
import sys
import base64
import time
import uuid
import pyodbc
import argparse
import logging
import hashlib
import requests
import random
import string
from datetime import datetime
from aiohttp import web
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from typing import Dict, Any, Optional, List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta


# --- Глобальные переменные и конфигурация ---
# Глобальный словарь для хранения запросов
request_store = {}
request_lock = asyncio.Lock()

# Переменные для управления перезагрузкой конфигурации
config_reload_interval = 0  # Интервал перезагрузки в минутах (0 - отключено)
last_config_reload_time = None  # Время последней перезагрузки конфигурации
config_reload_task = None  # Задача периодической перезагрузки

# --- Глобальные переменные статистики ---
statistics = {
    # Время запуска/обнуления статистики
    "reset_time": None,
    
    # Статистика запросов к БД
    "db_queries": {
        "total_count": 0,
        "max_execution_time": 0,
        "slowest_queries": []  # Максимум 5 записей
    },
    
    # Статистика запросов к облаку
    "cloud_requests": {
        "total_count": 0,
        "success_count": 0,
        "failed_count": 0
    },
    
    # Общая статистика запросов к серверу
    "server_requests": {
        "total_count": 0,
        "hourly_stats": {},  # { "час": количество }
        "daily_stats": {},   # { "день_недели": { "count": количество, "max_hourly": максимум } }
        "peak_hour": {"hour": None, "count": 0, "date": None},
        "peak_day": {"day": None, "count": 0, "date": None}
    },
    
    # Лимиты счетчиков (можно вынести в конфиг)
    "limits": {
        "max_total_count": 2**31 - 1,  # MAX_INT для 32-бит
        "warning_threshold": 0.8,      # 80% от максимума
        "max_slow_queries": 5
    }
}

# --- ЦВЕТА ДЛЯ ВЫВОДА В КОНСОЛЬ ---
class Colors:
    """Класс для работы с цветами вывода в консоль"""
    LIGHT_GREEN = '\033[92m'
    LIGHT_RED = '\033[91m'
    LIGHT_BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# --- КЛАСС КОНФИГУРАЦИИ ---
class Config:
    def __init__(self, config_data: Dict[str, Any]):
        """
        Название: __init__
        Назначение: Инициализация конфигурации сервера
        Описание: Загружает и валидирует параметры конфигурации из JSON файла
        Принцип работы: Парсит словарь с конфигурацией и устанавливает значения атрибутов
        Входящие параметры: config_data - словарь с данными конфигурации
        Исходящие параметры: Отсутствуют
        """
        self.host = config_data.get('host', 'localhost')
        self.port = config_data.get('port', 8000)
        self.debug = config_data.get('debug', False)
        self.config_reload_interval_minutes = config_data.get('config_reload_interval_minutes', 0)        

        # Конфигурация безопасности
        security = config_data.get('security', {})
        self.server_private_key_path = security.get('server_private_key_path', 'keys/private_server.pem')
        self.client_public_key_path = security.get('client_public_key_path', 'keys/public_client.pem')
        self.signature_ttl = security.get('signature_ttl', 300)
        self.default_token_server = security.get('default_token_server', '')
        self.allowed_tokens = set(security.get('allowed_tokens', []))
        
        # Валидация allowed_tokens
        if not self.allowed_tokens:
            raise ValueError("Список allowed_tokens не может быть пустым")
        
        # Настройки режима безопасности (true - отключено, false - включено)
        self.disable_certificates = security.get('disable_certificates', False)
        self.disable_token_auth = security.get('disable_token_auth', False)
        self.disable_signature = security.get('disable_signature', False)
        
        # Конфигурация безопасности эндпоинтов
        self.endpoint_security = {}
        endpoint_security_config = security.get('endpoint_security', {})
        for endpoint, security_level in endpoint_security_config.items():
            normalized_endpoint = endpoint.strip('/').lower()
            normalized_level = security_level.lower().strip()
            self.endpoint_security[normalized_endpoint] = normalized_level
        
        # НАСТРОЙКИ БЕЗОПАСНОСТИ ВХОДА 
        login_security_config = security.get('login_security', {})
        self.login_security = {
            'enabled': login_security_config.get('enabled', False),
            'max_failed_attempts': login_security_config.get('max_failed_attempts', 5),
            'check_period_minutes': login_security_config.get('check_period_minutes', 60),
            'allow_successful_login_during_lockout': login_security_config.get('allow_successful_login_during_lockout', False)
        }

        # Конфигурация базы данных MSSQL
        database = config_data.get('database', {})
        self.db_server = database.get('server', 'localhost')
        self.db_port = database.get('port', 1433)
        self.db_name = database.get('database', 'master')
        self.db_username = database.get('username', '')
        self.db_password = database.get('password', '')
        self.db_driver = database.get('driver', 'ODBC Driver 18 for SQL Server')
        self.db_connection_timeout = database.get('connection_timeout', 10)
        self.allow_start_without_db = database.get('allow_start_without_db', False)
        self.select_top = database.get('select_top', 1000)
        
        # НОВЫЕ ПАРАМЕТРЫ ДЛЯ УПРАВЛЕНИЯ СОЕДИНЕНИЕМ
        connection_pooling = database.get('connection_pooling', {})
        self.db_pooling_enabled = connection_pooling.get('enabled', True)
        self.db_max_pool_size = connection_pooling.get('max_pool_size', 10)
        self.db_min_pool_size = connection_pooling.get('min_pool_size', 1)
        self.db_connection_lifetime = connection_pooling.get('connection_lifetime', 300)
        
        health_check = database.get('health_check', {})
        self.db_health_check_enabled = health_check.get('enabled', True)
        self.db_health_check_interval = health_check.get('interval_seconds', 300)

        # Конфигурация логирования - ИСПРАВЛЕННАЯ ВЕРСИЯ
        logging_config = config_data.get('logging', {})
        self.log_to_db = logging_config.get('log_to_db', [])
        if isinstance(self.log_to_db, bool):
            self.log_to_db = ['INFO', 'ERROR'] if self.log_to_db else []
        elif not isinstance(self.log_to_db, list):
            self.log_to_db = []

        self.log_to_file = logging_config.get('log_to_file', [])
        if isinstance(self.log_to_file, bool):
            self.log_to_file = ['INFO', 'ERROR'] if self.log_to_file else []
        elif not isinstance(self.log_to_file, list):
            self.log_to_file = []

        self.log_file_path = logging_config.get('log_file_path', 'server.log')
        self.mask_sensitive_data = logging_config.get('mask_sensitive_data', True)

        # Конфигурация CORS
        cors = config_data.get('cors', {})
        self.cors_enabled = cors.get('enabled', True)
        self.cors_allowed_origins = cors.get('allowed_origins', ['*'])
        self.cors_allowed_methods = cors.get('allowed_methods', ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
        self.cors_allowed_headers = cors.get('allowed_headers', ['Content-Type', 'Token', 'Signature'])
        self.cors_expose_headers = cors.get('expose_headers', [])
        self.cors_allow_credentials = cors.get('allow_credentials', False)
        self.cors_max_age = cors.get('max_age', 600)

        # Конфигурация облачного хранилища
        cloud_config = config_data.get('cloud', {})
        self.cloud_enabled = cloud_config.get('enabled', False)
        self.cloud_url = cloud_config.get('url', '')
        self.cloud_username = cloud_config.get('username', '')
        self.cloud_password = cloud_config.get('password', '')
        self.cloud_repo_id = cloud_config.get('repo_id', '')
        self.cloud_upload_path = cloud_config.get('upload_path', 'preview')
        self.cloud_timeout = cloud_config.get('timeout', 30)
        self.cloud_temp_dir = cloud_config.get('temp_dir', '/tmp/cloud_uploads')
        self.allow_start_without_cloud = cloud_config.get('allow_start_without_cloud', False)

        # Максимальный размер загружаемого файла
        self.max_upload_size = cloud_config.get('max_upload_size_mb', 10)  # По умолчанию 10 МБ


    def get_endpoint_security_level(self, endpoint_path: str) -> str:
        """
        Название: get_endpoint_security_level
        Назначение: Получение уровня безопасности для указанного эндпоинта
        Описание: Определяет требуемый уровень безопасности для эндпоинта на основе конфигурации
        Принцип работы: Нормализует путь эндпоинта и ищет соответствующее правило безопасности, 
                    проверяя сначала точное совпадение, затем родительские пути
        Входящие параметры: endpoint_path - путь эндпоинта
        Исходящие параметры: str - уровень безопасности ('token', 'signature', 'disabled', 'public') или None если правило не найдено
        """
        # Нормализуем путь эндпоинта - убираем начальный и конечный слэш, приводим к нижнему регистру
        normalized_path = endpoint_path.strip('/').lower()
        
        if verbose_mode:
            print_status("INFO", f"Поиск уровня безопасности для пути: '{endpoint_path}' -> нормализован: '{normalized_path}'")
            print_status("INFO", f"Доступные правила: {list(self.endpoint_security.keys())}")
        
        # Проверяем точное совпадение
        if normalized_path in self.endpoint_security:
            security_level = self.endpoint_security[normalized_path]
            if verbose_mode:
                print_status("INFO", f"Найдено точное совпадение: {security_level}")
            return security_level
        
        # Проверяем родительские пути (например, для /help/info проверяем /help)
        path_parts = normalized_path.split('/')
        for i in range(len(path_parts) - 1, 0, -1):
            parent_path = '/'.join(path_parts[:i])
            if parent_path in self.endpoint_security:
                security_level = self.endpoint_security[parent_path]
                if verbose_mode:
                    print_status("INFO", f"Найдено совпадение по родительскому пути '{parent_path}': {security_level}")
                return security_level
        
        # Правило не найдено - используем стандартную безопасность
        if verbose_mode:
            print_status("INFO", f"Правило не найдено, используется стандартная безопасность")
        return None

    def get_response_token(self, request_token: str = None) -> str:
        """
        Название: get_response_token
        Назначение: Получение токена для использования в ответе сервера
        Описание: Определяет какой токен использовать в заголовке Token ответа
        Принцип работы: Если передан токен из запроса - использует его, иначе использует default_token_server или случайный из allowed_tokens
        Входящие параметры: request_token - токен из входящего запроса (опционально)
        Исходящие параметры: str - токен для использования в ответе
        """
        if request_token:
            return request_token
        
        if self.default_token_server and len(self.default_token_server) > 0:
            return self.default_token_server
        
        # Возвращаем первый токен из списка allowed_tokens
        return next(iter(self.allowed_tokens))
    
    def is_log_to_db_enabled(self) -> bool:
        """
        Проверяет, включено ли вообще логирование в БД
        """
        return isinstance(self.log_to_db, list) and len(self.log_to_db) > 0

    def is_log_to_file_enabled(self) -> bool:
        """
        Проверяет, включено ли вообще логирование в файл
        """
        return isinstance(self.log_to_file, list) and len(self.log_to_file) > 0    


# Глобальные объекты
config: Optional[Config] = None
private_key = None
public_key = None
db_connection = None
verbose_mode = False  # Флаг подробного режима
file_logger = None  # Логгер для записи в файл
start_time = time.time() # Временная метка старта сервера


# --- Функции для работы со статистикой ---
def init_statistics():
    """
    Инициализация статистики
    """
    global statistics
    statistics["reset_time"] = datetime.now()
    if verbose_mode:
        print_status("INFO", f"Статистика инициализирована")

def check_counters_overflow():
    """
    Проверка переполнения счетчиков
    """
    global statistics
    
    total_requests = statistics["server_requests"]["total_count"]
    max_limit = statistics["limits"]["max_total_count"]
    warning_threshold = statistics["limits"]["warning_threshold"]
    
    if total_requests >= max_limit * warning_threshold:
        if verbose_mode:
            print_status("WARNING", f"Счетчики приближаются к пределу", f"{total_requests}/{max_limit}")
        reset_statistics()
        return True
    return False

def reset_statistics():
    """
    Сброс всей статистики
    """
    global statistics
    
    old_reset_time = statistics["reset_time"]
    statistics = {
        "reset_time": datetime.now(),
        "db_queries": {
            "total_count": 0,
            "max_execution_time": 0,
            "slowest_queries": []
        },
        "cloud_requests": {
            "total_count": 0,
            "success_count": 0,
            "failed_count": 0
        },
        "server_requests": {
            "total_count": 0,
            "hourly_stats": {},
            "daily_stats": {},
            "peak_hour": {"hour": None, "count": 0, "date": None},
            "peak_day": {"day": None, "count": 0, "date": None}
        },
        "limits": statistics["limits"]
    }
    
    if verbose_mode:
        print_status("INFO", f"Статистика сброшена", 
                    f"предыдущее время: {old_reset_time.strftime('%Y-%m-%d %H:%M:%S')}")

def record_db_query(query: str, params: dict, execution_time: int):
    """
    Запись статистики запроса к БД
    """
    global statistics
    
    # Проверяем переполнение
    check_counters_overflow()
    
    # Обновляем общее количество
    statistics["db_queries"]["total_count"] += 1
    
    # Обновляем максимальное время выполнения
    if execution_time > statistics["db_queries"]["max_execution_time"]:
        statistics["db_queries"]["max_execution_time"] = execution_time
    
    # Добавляем в список медленных запросов (максимум 5)
    slow_query = {
        "query": query[:500],  # Ограничиваем длину
        "params": str(params)[:200] if params else "нет параметров",
        "execution_time_ms": execution_time,
        "timestamp": datetime.now().isoformat()
    }
    
    slow_queries = statistics["db_queries"]["slowest_queries"]
    slow_queries.append(slow_query)
    
    # Сортируем по времени выполнения и оставляем только 5 самых медленных
    slow_queries.sort(key=lambda x: x["execution_time_ms"], reverse=True)
    statistics["db_queries"]["slowest_queries"] = slow_queries[:statistics["limits"]["max_slow_queries"]]

def record_cloud_request(success: bool):
    """
    Запись статистики запроса к облаку
    """
    global statistics
    
    # Проверяем переполнение
    check_counters_overflow()
    
    statistics["cloud_requests"]["total_count"] += 1
    if success:
        statistics["cloud_requests"]["success_count"] += 1
    else:
        statistics["cloud_requests"]["failed_count"] += 1

def record_server_request():
    """
    Запись статистики запроса к серверу
    """
    global statistics
    
    # Проверяем переполнение
    if check_counters_overflow():
        return
    
    now = datetime.now()
    current_hour = now.strftime("%Y-%m-%d %H:00")
    current_day = now.strftime("%A")  # Название дня недели
    current_date = now.strftime("%Y-%m-%d")
    
    # Общее количество запросов
    statistics["server_requests"]["total_count"] += 1
    
    # Почасовой учет
    hourly_stats = statistics["server_requests"]["hourly_stats"]
    hourly_stats[current_hour] = hourly_stats.get(current_hour, 0) + 1
    
    # Учет по дням недели
    daily_stats = statistics["server_requests"]["daily_stats"]
    if current_day not in daily_stats:
        daily_stats[current_day] = {"count": 0, "max_hourly": 0}
    
    daily_stats[current_day]["count"] += 1
    
    # Обновляем максимальное почасовое значение для текущего дня
    current_hour_count = hourly_stats[current_hour]
    if current_hour_count > daily_stats[current_day]["max_hourly"]:
        daily_stats[current_day]["max_hourly"] = current_hour_count
    
    # Обновляем пиковый час
    peak_hour = statistics["server_requests"]["peak_hour"]
    if current_hour_count > peak_hour["count"]:
        peak_hour["hour"] = current_hour
        peak_hour["count"] = current_hour_count
        peak_hour["date"] = current_date
    
    # Обновляем пиковый день
    peak_day = statistics["server_requests"]["peak_day"]
    day_count = daily_stats[current_day]["count"]
    if day_count > peak_day["count"]:
        peak_day["day"] = current_day
        peak_day["count"] = day_count
        peak_day["date"] = current_date

# --- ФУНКЦИИ РАБОТЫ С ОБЛАЧНЫМ ХРАНИЛИЩЕМ ---

async def check_cloud_availability() -> bool:
    """
    Название: check_cloud_availability
    Назначение: Проверка доступности облачного хранилища через получение токена аутентификации
    Описание: Проверяет работоспособность облачного хранилища путем попытки получения токена аутентификации
    Принцип работы: Отправляет запрос аутентификации к API облачного хранилища и проверяет ответ
    Входящие параметры: Отсутствуют
    Исходящие параметры: bool - True если облачное хранилище доступно, False в противном случае
    """
    if not config.cloud_enabled:
        return False
    
    try:
        if verbose_mode:
            print_status("INFO", f"Проверка доступности облачного хранилища")
        
        auth_payload = {
            "username": config.cloud_username,
            "password": config.cloud_password
        }
        auth_headers = {
            "accept": "application/json",
            "content-type": "application/json"
        }
        
        auth_response = requests.post(
            f"{config.cloud_url}api2/auth-token/",
            json=auth_payload,
            headers=auth_headers,
            timeout=config.cloud_timeout
        )
        auth_response.raise_for_status()
        
        auth_data = auth_response.json()
        token = auth_data.get('token')
        
        if token:
            if verbose_mode:
                print_status("OK", f"Облачное хранилище доступно, токен получен")
            return True
        else:
            if verbose_mode:
                print_status("ERROR", f"Облачное хранилище недоступно: токен не получен")
            return False
            
    except requests.RequestException as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка подключения к облачному хранилищу", str(e))
        return False
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка при проверке облачного хранилища", str(e))
        return False

def save_base64_to_file(data: str, name: str, extension: str) -> str:
    """
    Название: save_base64_to_file
    Назначение: Сохранение base64 данных в файл с уникальным именем
    Описание: Декодирует base64 данные и сохраняет в файл, генерируя уникальное имя при конфликте
    Принцип работы: Декодирует base64, проверяет существование файла, генерирует уникальное имя при необходимости
    Входящие параметры:
        data - данные в формате base64
        name - исходное имя файла
        extension - расширение файла
    Исходящие параметры: str - путь к сохраненному файлу
    """
    # Создаем временную директорию если не существует
    temp_dir = config.cloud_temp_dir
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir, exist_ok=True)
        if verbose_mode:
            print_status("INFO", f"Создана временная директория", temp_dir)
    
    # Формируем базовое имя файла
    base_name = f"{name}.{extension}" if not name.endswith(f".{extension}") else name
    file_path = os.path.join(temp_dir, base_name)
    
    # Если файл уже существует, генерируем уникальное имя
    if os.path.exists(file_path):
        if verbose_mode:
            print_status("INFO", f"Файл уже существует, генерируем уникальное имя", base_name)
        
        # Генерируем временной штамп (год-месяц-день-час-минута-секунда)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        # Генерируем случайную строку из 5 латинских символов нижнего регистра
        random_chars = ''.join(random.choices(string.ascii_lowercase, k=5))
        
        # Формируем новое имя файла
        name_without_ext = os.path.splitext(name)[0]
        base_name = f"{name_without_ext}_{timestamp}_{random_chars}.{extension}"
        file_path = os.path.join(temp_dir, base_name)
        
        if verbose_mode:
            print_status("INFO", f"Сгенерировано уникальное имя", base_name)
    
    try:
        # Декодируем base64 данные
        file_content = base64.b64decode(data)
        
        # Сохраняем файл
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        if verbose_mode:
            print_status("OK", f"Файл сохранен", f"{base_name} ({len(file_content)} байт)")
        
        return file_path
        
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка сохранения файла", str(e))
        raise

async def upload_to_cloud(file_path: str, file_name: str) -> Optional[str]:
    """
    Название: upload_to_cloud
    Назначение: Загрузка файла в облачное хранилище и получение публичной ссылки
    Описание: Выполняет аутентификацию, загружает файл и создает публичную ссылку без пароля
    Принцип работы: Использует API облачного хранилища для загрузки файла и создания share-ссылки
    Входящие параметры:
        file_path - путь к файлу на сервере
        file_name - имя файла для загрузки
    Исходящие параметры: str или None - публичная ссылка на файл или None при ошибке
    """
    if not config.cloud_enabled:
        if verbose_mode:
            print_status("INFO", f"Облачное хранилище отключено в настройках")
        # Записываем статистику - облако отключено
        record_cloud_request(False)
        return None
    
    # ДОБАВИТЬ ПРОВЕРКУ РАБОТОСПОСОБНОСТИ ОБЛАЧНОГО ХРАНИЛИЩА
    if not await check_cloud_availability():
        if config.allow_start_without_cloud:
            if verbose_mode:
                print_status("WARNING", f"Облачное хранилище недоступно, но разрешен запуск без него")
            # Записываем статистику - облако недоступно
            record_cloud_request(False)
            return None
        else:
            if verbose_mode:
                print_status("ERROR", f"Облачное хранилище недоступно")
            # Записываем статистику - облако недоступно
            record_cloud_request(False)
            raise Exception("Облачное хранилище недоступно")
    
    try:
        if verbose_mode:
            print_status("INFO", f"Начало загрузки файла в облачное хранилище", file_name)
            print(f"  Путь к файлу: {file_path}")
        
        # Проверяем существование файла
        if not os.path.exists(file_path):
            if verbose_mode:
                print_status("ERROR", f"Файл не найден", file_path)
            # Записываем статистику - файл не найден
            record_cloud_request(False)
            return None
        
        # Получаем токен аутентификации
        auth_payload = {
            "username": config.cloud_username,
            "password": config.cloud_password
        }
        auth_headers = {
            "accept": "application/json",
            "content-type": "application/json"
        }
        
        if verbose_mode:
            print_status("INFO", f"Получение токена аутентификации")
        
        auth_response = requests.post(
            f"{config.cloud_url}api2/auth-token/",
            json=auth_payload,
            headers=auth_headers,
            timeout=config.cloud_timeout
        )
        auth_response.raise_for_status()
        
        auth_data = auth_response.json()
        token = auth_data.get('token')
        
        if not token:
            if verbose_mode:
                print_status("ERROR", f"Токен аутентификации не получен")
            # Записываем статистику - ошибка аутентификации
            record_cloud_request(False)
            return None
        
        if verbose_mode:
            print_status("OK", f"Токен аутентификации получен")
        
        # Заголовки с токеном для последующих запросов
        headers_with_token = {
            "accept": "application/json",
            "authorization": f"Token {token}"
        }
        
        # Проверяем существование файла в облаке и удаляем если существует
        file_path_in_cloud = f"{config.cloud_upload_path}/{file_name}"
        
        if verbose_mode:
            print_status("INFO", f"Проверка существования файла в облаке", file_path_in_cloud)
        
        try:
            # Проверяем smart link (существование файла)
            smart_link_response = requests.get(
                f"{config.cloud_url}api/v2.1/smart-link/",
                params={
                    "repo_id": config.cloud_repo_id,
                    "path": file_path_in_cloud,
                    "is_dir": "false"
                },
                headers=headers_with_token,
                timeout=config.cloud_timeout
            )
            
            # Если файл существует, удаляем его
            if smart_link_response.status_code == 200:
                if verbose_mode:
                    print_status("INFO", f"Файл существует в облаке, удаление")
                
                delete_response = requests.delete(
                    f"{config.cloud_url}api2/repos/{config.cloud_repo_id}/file/",
                    params={"p": file_path_in_cloud},
                    headers=headers_with_token,
                    timeout=config.cloud_timeout
                )
                if delete_response.status_code in [200, 202]:
                    if verbose_mode:
                        print_status("OK", f"Существующий файл в облаке удален")
        except requests.RequestException as e:
            if verbose_mode:
                print_status("INFO", f"Файл не существует в облаке или ошибка проверки", str(e))
        
        # Получаем ссылку для загрузки
        if verbose_mode:
            print_status("INFO", f"Получение ссылки для загрузки")
        
        upload_link_response = requests.get(
            f"{config.cloud_url}api2/repos/{config.cloud_repo_id}/upload-link/",
            params={"p": config.cloud_upload_path},
            headers=headers_with_token,
            timeout=config.cloud_timeout
        )
        upload_link_response.raise_for_status()
        
        upload_link = upload_link_response.text.replace('"', '')
        upload_token = upload_link.rstrip('/').split('/')[-1]
        
        if verbose_mode:
            print_status("OK", f"Ссылка для загрузки получена", upload_token)
        
        # Загружаем файл
        upload_payload = {
            "parent_dir": config.cloud_upload_path,
            "replace": "1"
        }
        
        # Определяем MIME-тип на основе расширения файла
        # Используем стандартный MIME-тип для всех файлов
        file_extension = os.path.splitext(file_name)[1].lower().lstrip('.')
        
        # Для всех типов файлов используем application/octet-stream
        # Это позволяет загружать файлы любого типа без ограничений
        mime_type = 'application/octet-stream'
        
        if verbose_mode:
            file_size = os.path.getsize(file_path)
            print_status("INFO", f"Загрузка файла в облако", 
                       f"размер: {file_size:,} байт, расширение: .{file_extension}, MIME: {mime_type}")
        
        with open(file_path, 'rb') as file:
            files = {'file': (file_name, file, mime_type)}
            
            if verbose_mode:
                print_status("INFO", f"Отправка запроса на загрузку файла")
            
            upload_response = requests.post(
                f"{config.cloud_url}seafhttp/upload-api/{upload_token}?ret-json=1",
                data=upload_payload,
                files=files,
                headers=headers_with_token,
                timeout=config.cloud_timeout
            )
            upload_response.raise_for_status()
        
        upload_result = upload_response.json()
        
        if not upload_result or 'name' not in upload_result[0]:
            if verbose_mode:
                print_status("ERROR", f"Ошибка загрузки файла", str(upload_result))
            # Записываем статистику - ошибка загрузки
            record_cloud_request(False)
            return None
        
        if verbose_mode:
            print_status("OK", f"Файл успешно загружен", upload_result[0]['name'])
        
        # Удаляем существующие share-ссылки
        if verbose_mode:
            print_status("INFO", f"Удаление существующих share-ссылок")
        
        share_links_response = requests.get(
            f"{config.cloud_url}api/v2.1/share-links/",
            params={
                "repo_id": config.cloud_repo_id,
                "path": file_path_in_cloud
            },
            headers=headers_with_token,
            timeout=config.cloud_timeout
        )
        
        if share_links_response.status_code == 200:
            existing_links = share_links_response.json()
            for link in existing_links:
                delete_share_response = requests.delete(
                    f"{config.cloud_url}api/v2.1/share-links/{link['token']}/",
                    headers=headers_with_token,
                    timeout=config.cloud_timeout
                )
                if delete_share_response.status_code in [200, 204]:
                    if verbose_mode:
                        print_status("INFO", f"Удалена существующая ссылка", link['token'])
        
        # Создаем новую публичную ссылку без пароля
        if verbose_mode:
            print_status("INFO", f"Создание публичной ссылки")
        
        share_payload = {
            "repo_id": config.cloud_repo_id,
            "path": file_path_in_cloud,
            "permissions": {
                "can_download": True,
                "can_edit": False
            }
        }
        
        share_response = requests.post(
            f"{config.cloud_url}api/v2.1/share-links/",
            json=share_payload,
            headers=headers_with_token,
            timeout=config.cloud_timeout
        )
        share_response.raise_for_status()
        
        share_result = share_response.json()
        public_link = share_result.get('link')
        
        if not public_link:
            if verbose_mode:
                print_status("ERROR", f"Публичная ссылка не получена")
            # Записываем статистику - ошибка создания ссылки
            record_cloud_request(False)
            return None
        
        if verbose_mode:
            print_status("OK", f"Публичная ссылка создана", public_link)
        
        # ЗАПИСЫВАЕМ СТАТИСТИКУ - УСПЕШНЫЙ ЗАПРОС К ОБЛАКУ
        record_cloud_request(True)
        return public_link
        
    except requests.RequestException as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка сети при работе с облачным хранилищем", str(e))
        # Записываем статистику - ошибка сети
        record_cloud_request(False)
        return None
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка при загрузке в облако", str(e))
            import traceback
            traceback.print_exc()
        # Записываем статистику - неожиданная ошибка
        record_cloud_request(False)
        return None
        
# --- ФУНКЦИИ ВЫВОДА В КОНСОЛЬ ---
def print_status(status: str, message: str, details: str = None, data_lines: list = None):
    """
    Название: print_status
    Назначение: Форматированный вывод сообщений в консоль с цветовой идентификацией и поддержкой многострочных данных
    Описание: Выводит сообщение с префиксом статуса в соответствующем цвете, поддерживает дополнительные строки данных
    Принцип работы: Определяет цвет по статусу, форматирует и выводит сообщение с дополнительными данными
    Входящие параметры:
        status - тип статуса (OK, ERROR, INFO)
        message - основное сообщение на русском языке
        details - дополнительные детали (опционально)
        data_lines - список строк с дополнительными данными для вывода (опционально)
    Исходящие параметры: Отсутствуют (побочный эффект - вывод в консоль)
    """
    color_map = {
        "OK": Colors.LIGHT_GREEN,
        "ERROR": Colors.LIGHT_RED,
        "INFO": Colors.LIGHT_BLUE
    }
    
    color = color_map.get(status, Colors.RESET)
    status_prefix = f"{color}[{status}]{Colors.RESET}"
    
    # Формируем основную строку
    if details:
        main_line = f"{status_prefix} {message} ({details})"
    else:
        main_line = f"{status_prefix} {message}"
    
    print(main_line)
    
    # Выводим дополнительные строки данных
    if data_lines:
        for line in data_lines:
            print(f"      {line}")

def print_separator():
    """
    Название: print_separator
    Назначение: Визуальное разделение вывода в verbose режиме
    Описание: Печатает разделительную линию для улучшения читаемости логов
    Принцип работы: Выводит в консоль строку из символов '-' при включенном verbose режиме
    Входящие параметры: Отсутствуют
    Исходящие параметры: Отсутствуют (побочный эффект - вывод в консоль)
    """
    if verbose_mode:
        print("\n" + "-" * 60)


# --- УТИЛИТЫ И ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def generate_request_id() -> str:
    """
    Название: generate_request_id
    Назначение: Генерация уникального идентификатора для каждого запроса
    Описание: Создает UUID4 строку для однозначной идентификации запроса в системе
    Принцип работы: Использует модуль uuid для генерации случайного UUID версии 4
    Входящие параметры: Отсутствуют
    Исходящие параметры: str - уникальный идентификатор запроса в формате UUID4
    """
    return str(uuid.uuid4())


def mask_sensitive_data(data: str) -> str:
    """
    Название: mask_sensitive_data
    Назначение: Маскирование конфиденциальных данных в логах
    Описание: Заменяет чувствительные данные (пароли, токены) на маскированные значения
    Принцип работы: Ищет в строке ключевые слова, связанные с конфиденциальными данными, и заменяет их символом '*'
    Входящие параметры: data - исходная строка для маскирования
    Исходящие параметры: str - строка с замаскированными конфиденциальными данными
    """
    sensitive_keys = ['password', 'token', 'signature', 'Token', 'bearer']
    for key in sensitive_keys:
        if key in data.lower():
            data = data.replace(key, f"{key[0]}{'*'*(len(key)-2)}{key[-1]}")
    return data


def normalize_phone(phone: str) -> str:
    """
    Название: normalize_phone
    Назначение: Нормализация номера телефона к стандартному формату
    Описание: Удаляет все нецифровые символы, оставляет только цифры. 
              Если номер начинается с +7 или 8, преобразует к формату без кода страны.
    Принцип работы: Удаляет все символы кроме цифр, обрабатывает российские форматы номеров
    Входящие параметры: phone - исходный номер телефона
    Исходящие параметры: str - нормализованный номер (10 цифр)
    """
    # Удаляем все нецифровые символы
    digits = ''.join(filter(str.isdigit, phone))
    
    if not digits:
        return ""
    
    # Обрабатываем российские форматы: +7, 8, 7 в начале
    if len(digits) == 11:
        if digits.startswith('7') or digits.startswith('8'):
            return digits[1:]  # Убираем код страны
    
    # Если номер уже в 10-значном формате
    if len(digits) == 10:
        return digits
    
    # Для других случаев возвращаем как есть (только цифры)
    return digits


# --- ФУНКЦИИ БЕЗОПАСНОСТИ ---

async def load_private_key():
    """
    Название: load_private_key
    Назначение: Асинхронная загрузка приватного RSA ключа сервера из файла
    Описание: Асинхронно загружает приватный ключ сервера из PEM файла для создания цифровых подписей ответов
    Принцип работы: Читает файл по указанному пути в отдельном потоке и десериализует приватный ключ сервера
    Входящие параметры: Отсутствуют (использует глобальную конфигурацию)
    Исходящие параметры: Объект приватного ключа сервера
    """
    global config, private_key
    
    if not config or config.disable_certificates:
        return None
        
    key_path = config.server_private_key_path  # ИСПРАВЛЕНО
    loop = asyncio.get_event_loop()
    
    def _load_key():
        with open(key_path, 'rb') as f:
            key_data = f.read()
        return serialization.load_pem_private_key(key_data, password=None)
    
    try:
        private_key = await loop.run_in_executor(None, _load_key)
        if verbose_mode:
            print_status("OK", f"Приватный ключ сервера загружен", key_path)
        return private_key
    except Exception as e:
        print_status("ERROR", f"Ошибка загрузки приватного ключа сервера", str(e))
        raise


async def load_public_key():
    """
    Название: load_public_key
    Назначение: Асинхронная загрузка публичного RSA ключа клиента из файла
    Описание: Асинхронно загружает публичный ключ клиента из PEM файла для проверки цифровых подписей запросов
    Принцип работы: Читает файл по указанному пути в отдельном потоке и десериализует публичный ключ клиента
    Входящие параметры: Отсутствуют (использует глобальную конфигурацию)
    Исходящие параметры: Объект публичного ключа клиента
    """
    global config, public_key
    
    if not config or config.disable_certificates:
        return None
        
    key_path = config.client_public_key_path  # ИСПРАВЛЕНО
    loop = asyncio.get_event_loop()
    
    def _load_key():
        with open(key_path, 'rb') as f:
            key_data = f.read()
        return serialization.load_pem_public_key(key_data)
    
    try:
        public_key = await loop.run_in_executor(None, _load_key)
        if verbose_mode:
            print_status("OK", f"Публичный ключ клиента загружен", key_path)
        return public_key
    except Exception as e:
        print_status("ERROR", f"Ошибка загрузки публичного ключа клиента", str(e))
        raise


async def verify_client_signature(signature: str, token: str) -> bool:
    """
    Название: verify_client_signature
    Назначение: Асинхронная проверка цифровой подписи клиента с использованием приватного ключа сервера
    Описание: Расшифровывает подпись приватным ключом сервера и проверяет формат <токен>.<время_истечения>
    Принцип работы: Декодирует Base64 подпись, расшифровывает приватным ключом сервера, проверяет формат и срок действия
    Входящие параметры: 
        signature - Base64-кодированная подпись из заголовка Signature
        token - токен авторизации из заголовка Token
    Исходящие параметры: bool - True если подпись валидна, False в противном случае
    """
    if not signature:
        if verbose_mode:
            print_status("ERROR", f"Отсутствует подпись", f"signature={bool(signature)}")
        return False
    
    # Загружаем приватный ключ сервера
    server_private_key = await load_server_private_key()
    if not server_private_key:
        if verbose_mode:
            print_status("ERROR", f"Не удалось загрузить приватный ключ сервера")
        return False
    
    loop = asyncio.get_event_loop()
    
    def _verify():
        try:
            if verbose_mode:
                print("=" * 60)
                print("НАЧАЛО ПРОВЕРКИ ЦИФРОВОЙ ПОДПИСИ КЛИЕНТА")
                print("=" * 60)
                print(f"Входные параметры:")
                print(f"  - Токен: {token}")
                print(f"  - Подпись (Base64): {signature}")
                print(f"  - Длина подписи: {len(signature)} символов")
                print(f"  - Путь к приватному ключу сервера: {config.server_private_key_path}")
            
            # Декодируем Base64 подпись
            signature_bytes = base64.b64decode(signature)
            
            if verbose_mode:
                print_status("OK", f"Подпись декодирована из Base64")
                print(f"  - Длина подписи в байтах: {len(signature_bytes)}")
                print(f"  - Подпись (hex): {signature_bytes.hex()}")
            
            # Расшифровываем подпись приватным ключом сервера
            if verbose_mode:
                print(f"Расшифровка подписи приватным ключом сервера...")
                print(f"  Используем PKCS1v15 padding (совместимо с PHP openssl_public_encrypt)")
            
            # Для совместимости с PHP openssl_public_encrypt используем PKCS1v15 padding
            try:
                # PHP openssl_public_encrypt по умолчанию использует OPENSSL_PKCS1_PADDING
                # что соответствует PKCS1v15 в Python cryptography
                decrypted_data = server_private_key.decrypt(
                    signature_bytes,
                    padding.PKCS1v15()
                )
                
                if verbose_mode:
                    print_status("OK", f"Успешная расшифровка с RSA-PKCS1v15")
                    print(f"  (совместимо с PHP openssl_public_encrypt)")
                    
            except Exception as e:
                if verbose_mode:
                    print_status("ERROR", f"Расшифровка с RSA-PKCS1v15 не удалась", str(e))
                    print(f"  Пробуем альтернативные методы...")
                
                # Если PKCS1v15 не сработал, пробуем другие padding схемы
                padding_methods = [
                    ("RSA-OAEP-SHA256", padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )),
                    ("RSA-OAEP-SHA1", padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None
                    )),
                ]
                
                for alg_name, padding_scheme in padding_methods:
                    try:
                        decrypted_data = server_private_key.decrypt(
                            signature_bytes,
                            padding_scheme
                        )
                        used_algorithm = alg_name
                        if verbose_mode:
                            print_status("OK", f"Успешная расшифровка с {alg_name}")
                        break
                    except Exception as e2:
                        if verbose_mode:
                            print_status("ERROR", f"{alg_name} расшифровка не удалась", str(e2))
                        continue
                else:
                    # Если ни один метод не сработал
                    if verbose_mode:
                        print_status("ERROR", f"Не удалось расшифровать подпись ни одним методом")
                    return False

            # Преобразуем расшифрованные данные в строку
            try:
                decrypted_text = decrypted_data.decode('utf-8')
                if verbose_mode:
                    print(f"Расшифрованный текст: {decrypted_text}")
            except UnicodeDecodeError:
                if verbose_mode:
                    print_status("ERROR", f"Не удалось декодировать расшифрованные данные как UTF-8", 
                                data_lines=[
                                    f"Данные (hex): {decrypted_data.hex()}",
                                    f"Данные (raw): {decrypted_data}"
                                ])
                return False
            
            # Проверяем формат: токен.время_истечения
            if '.' not in decrypted_text:
                if verbose_mode:
                    print_status("ERROR", f"Неверный формат расшифрованных данных: отсутствует разделитель '.'",
                                data_lines=[f"Полученные данные: {decrypted_text}"])
                return False
            
            parts = decrypted_text.split('.', 1)
            if len(parts) != 2:
                if verbose_mode:
                    print_status("ERROR", f"Неверный формат расшифрованных данных: ожидается 2 части, получено {len(parts)}",
                                data_lines=[f"Полученные данные: {decrypted_text}"])
                return False
            
            decrypted_token, expiry_str = parts
            
            # Проверяем токен
            if decrypted_token != token:
                if verbose_mode:
                    print_status("ERROR", f"Несовпадение токенов:",
                                data_lines=[
                                    f"Ожидаемый: {token}",
                                    f"Полученный: {decrypted_token}"
                                ])
                return False
            
            if verbose_mode:
                print_status("OK", f"Токены совпадают")
            
            # Проверяем время истечения
            try:
                current_time = int(datetime.now().timestamp())
                current_time_human = datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
                expiry_time = int(expiry_str)
                expiry_time_human = datetime.fromtimestamp(expiry_time).strftime('%Y-%m-%d %H:%M:%S')
                
                if verbose_mode:
                    print(f"Время истечения из подписи:")
                    print(f"  - Unix время: {expiry_time}")
                    print(f"  - Человекочитаемо: {expiry_time_human}")
                    print(f"  - Осталось времени: {expiry_time - current_time} секунд")
                
                # Проверяем что подпись не просрочена
                if expiry_time < current_time:
                    if verbose_mode:
                        print_status("ERROR", f"Подпись просрочена:",
                                    data_lines=[
                                        f"Текущее время: {current_time} ({current_time_human})",
                                        f"Время истечения: {expiry_time} ({expiry_time_human})",
                                        f"Просрочено на: {current_time - expiry_time} секунд"
                                    ])
                    return False
                
                # Проверяем что подпись не из далекого будущего (например, больше 24 часов)
                max_future_time = current_time + 24 * 3600  # 24 часа
                if expiry_time > max_future_time:
                    if verbose_mode:
                        print_status("ERROR", f"Время истечения слишком далеко в будущем:",
                                    data_lines=[
                                        f"Текущее время: {current_time} ({current_time_human})",
                                        f"Время истечения: {expiry_time} ({expiry_time_human})",
                                        f"Разница: {expiry_time - current_time} секунд",
                                        f"Максимально допустимо: 86400 секунд (24 часа)"
                                    ])
                    return False
                
                if verbose_mode:
                    print_status("OK", f"Время истечения валидно")
                    print("ПРОВЕРКА ПОДПИСИ УСПЕШНО ЗАВЕРШЕНА")
                    print(f"  - Результат: ПОДПИСЬ ВАЛИДНА")
                    print(f"  - Использованный алгоритм: RSA-PKCS1v15")
                    print(f"  - Осталось времени: {expiry_time - current_time} секунд")
                    print("=" * 60)
                
                return True
                
            except ValueError:
                if verbose_mode:
                    print_status("ERROR", f"Неверный формат времени истечения", expiry_str)
                return False
            
        except (ValueError, UnicodeDecodeError) as e:
            if verbose_mode:
                print_status("ERROR", f"Ошибка формата подписи:",
                            data_lines=[
                                f"Тип ошибки: {type(e).__name__}",
                                f"Сообщение: {str(e)}"
                            ])
                print("=" * 60)
            return False
        except Exception as e:
            if verbose_mode:
                print_status("ERROR", f"Неожиданная ошибка при проверке подписи:",
                            data_lines=[
                                f"Тип ошибки: {type(e).__name__}",
                                f"Сообщение: {str(e)}"
                            ])
                import traceback
                print("  Трассировка:")
                traceback.print_exc()
                print("=" * 60)
            return False
    
    return await loop.run_in_executor(None, _verify)

async def load_server_private_key():
    """
    Название: load_server_private_key
    Назначение: Асинхронная загрузка приватного ключа сервера из файла
    Описание: Загружает приватный ключ сервера для расшифровки клиентских подписей
    Принцип работы: Читает файл по указанному пути в конфигурации и десериализует приватный ключ
    Входящие параметры: Отсутствуют (использует глобальную конфигурацию)
    Исходящие параметры: Объект приватного ключа сервера или None при ошибке
    """
    global config
    
    if not config or config.disable_certificates:
        return None
        
    key_path = config.server_private_key_path
    loop = asyncio.get_event_loop()
    
    def _load_key():
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
            return serialization.load_pem_private_key(key_data, password=None)
        except Exception as e:
            print_status("ERROR", f"Ошибка загрузки приватного ключа сервера", str(e))
            return None
    
    try:
        private_key = await loop.run_in_executor(None, _load_key)
        if verbose_mode and private_key:
            print_status("OK", f"Приватный ключ сервера загружен", key_path)
        return private_key
    except Exception as e:
        print_status("ERROR", f"Ошибка загрузки приватного ключа сервера", str(e))
        return None
    
def _verify():
    try:
        # Декодируем Base64 подпись
        signature_bytes = base64.b64decode(signature)
        
        if verbose_mode:
            print_status("INFO", f"Проверка подписи для токена", token)
            print(f"  Длина подписи: {len(signature_bytes)} байт")
            print(f"  Используется публичный ключ клиента: {config.client_public_key_path}")
        
        # Получаем текущее время
        current_time = int(time.time())
        if verbose_mode:
            print(f"  Текущее время сервера: {current_time}")
        
        # Клиент должен подписывать данные в формате: token.expiry_timestamp
        # Проверяем подпись для временных меток в широком диапазоне
        max_offset = config.signature_ttl * 3  # Проверяем в 3 раза больше TTL
        found_valid = False
        
        for time_offset in range(0, max_offset, 10):  # Шаг 10 секунд
            expiry_time = current_time + time_offset
            data_to_verify = f"{token}.{expiry_time}".encode('utf-8')
            
            try:
                # Создаем хэш данных
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(data_to_verify)
                data_hash = digest.finalize()
                
                # Проверяем подпись с использованием публичного ключа клиента
                public_key.verify(
                    signature_bytes,
                    data_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                # Если подпись верна, проверяем что временная метка не просрочена
                if expiry_time >= current_time:
                    if verbose_mode:
                        print_status("OK", f"Подпись валидна для токена {token} с временем истечения {expiry_time}")
                        print(f"  Осталось времени: {expiry_time - current_time}сек")
                    found_valid = True
                    break
                else:
                    if verbose_mode:
                        print_status("INFO", f"Подпись верна но просрочена", f"время истечения: {expiry_time}")
                    found_valid = False
                    break
                    
            except InvalidSignature:
                # Продолжаем проверять другие временные метки
                continue
            except Exception as e:
                if verbose_mode and time_offset == 0:
                    print_status("ERROR", f"Ошибка при проверке подписи", str(e))
                continue
        
        if not found_valid:
            # Попробуем проверить с OAEP padding на случай если клиент использует другой алгоритм
            if verbose_mode:
                print_status("INFO", f"Попытка проверки с OAEP padding...")
            try:
                for time_offset in range(0, max_offset, 10):
                    expiry_time = current_time + time_offset
                    data_to_verify = f"{token}.{expiry_time}".encode('utf-8')
                    
                    # Пробуем с OAEP padding
                    try:
                        # Для OAEP нужно "расшифровать" подпись
                        decrypted_data = public_key.decrypt(
                            signature_bytes,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        
                        decrypted_str = decrypted_data.decode('utf-8')
                        if decrypted_str == f"{token}.{expiry_time}":
                            if expiry_time >= current_time:
                                if verbose_mode:
                                    print_status("OK", f"Подпись валидна (OAEP) для времени истечения {expiry_time}")
                                found_valid = True
                                break
                    except:
                        continue
            except Exception as e:
                if verbose_mode:
                    print_status("ERROR", f"Ошибка при проверке с OAEP", str(e))
        
        if not found_valid:
            if verbose_mode:
                print_status("ERROR", f"Подпись невалидна для токена {token} в диапазоне до {max_offset}сек")
            return False
        
        return found_valid
        
    except (ValueError, UnicodeDecodeError) as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка формата подписи", str(e))
        return False
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка при проверке подписи", str(e))
            import traceback
            traceback.print_exc()
        return False
    
async def _add_server_signature(self, data: dict) -> dict:
    """
    Добавляет серверную подпись к данным
    """
    try:
        print_status("INFO", f"Используется приватный ключ сервера", config.server_private_key_path)
        
        # Загрузка приватного ключа сервера
        with open(config.server_private_key_path, 'rb') as key_file:  # Изменено на 'rb'
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        
        # Создание данных для подписи (исключаем существующую подпись если есть)
        sign_data = data.copy()
        sign_data.pop('server_signature', None)
        
        # Создание хэша из данных
        data_str = json.dumps(sign_data, sort_keys=True, separators=(',', ':'))
        
        # Создаем хэш с cryptography
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data_str.encode('utf-8'))
        data_hash = digest.finalize()
        
        # Создание подписи
        signature = private_key.sign(
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Кодирование подписи в base64
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        # Добавление подписи к данным
        data['server_signature'] = signature_b64
        print_status("OK", f"Серверная подпись успешно добавлена")
        
        return data
        
    except FileNotFoundError:
        print_status("ERROR", f"Файл приватного ключа не найден", config.server_private_key_path)
        return data
    except Exception as e:
        print_status("ERROR", f"Ошибка добавления серверной подписи", str(e))
        return data

async def add_server_signature_to_response(response: web.Response, request_token: str = None):
    """
    Название: add_server_signature_to_response
    Назначение: Добавление серверной цифровой подписи и токена к любому HTTP ответу
    Описание: Гарантирует наличие серверной подписи и токена авторизации во всех исходящих ответах
    Принцип работы: Определяет токен для ответа, генерирует цифровую подпись с использованием ПУБЛИЧНОГО ключа клиента
    Входящие параметры: 
        response - объект HTTP ответа для добавления подписи
        request_token - токен авторизации из запроса для привязки подписи (опционально)
    Исходящие параметры: Отсутствуют (побочный эффект - модификация заголовков ответа)
    """
    if config.disable_signature or not public_key:
        if verbose_mode:
            print_status("INFO", f"Подпись отключена или публичный ключ клиента недоступен")
        # Все равно добавляем токен, даже если подпись отключена
        response_token = config.get_response_token(request_token)
        response.headers['Token'] = f"Bearer {response_token}"
        return
    
    try:
        # Определяем токен для ответа
        response_token = config.get_response_token(request_token)
        
        if verbose_mode:
            print_status("INFO", f"Генерация серверной подписи для токена", response_token)
            print(f"  Используется ПУБЛИЧНЫЙ ключ клиента: {config.client_public_key_path}")
        
        # Генерируем серверную подпись с использованием ПУБЛИЧНОГО ключа клиента
        server_signature = await generate_server_signature(response_token)
        if server_signature:
            # Добавляем оба обязательных заголовка
            response.headers['Token'] = f"Bearer {response_token}"
            response.headers['Signature'] = server_signature
            if verbose_mode:
                print_status("OK", f"Добавлены заголовки к ответу со статусом {response.status}")
                print(f"  Токен: Bearer {response_token}")
                print(f"  Подпись (первые 50 символов): {server_signature[:50]}...")
        else:
            if verbose_mode:
                print_status("ERROR", f"Не удалось сгенерировать серверную подпись")
            # Все равно добавляем токен, даже если подпись не сгенерирована
            response.headers['Token'] = f"Bearer {response_token}"
    except Exception as e:
        print_status("ERROR", f"Ошибка добавления серверной подписи", str(e))
        # В случае ошибки все равно пытаемся добавить токен
        try:
            response_token = config.get_response_token(request_token)
            response.headers['Token'] = f"Bearer {response_token}"
        except:
            pass


async def generate_server_signature(token: str, ttl_seconds: int = None) -> str:
    """
    Название: generate_server_signature
    Назначение: Асинхронная генерация цифровой подписи сервера с использованием ПУБЛИЧНОГО ключа клиента
    Описание: Создает подпись для ответов клиенту в формате <токен>.<время_истечения>, используя ПУБЛИЧНЫЙ ключ клиента
    Принцип работы: Формирует строку "токен.время_экспирации", ШИФРУЕТ публичным ключом клиента и кодирует в Base64
    Входящие параметры: 
        token - токен авторизации
        ttl_seconds - время жизни подписи в секундах (опционально)
    Исходящие параметры: str - Base64-кодированная подпись или пустая строка при ошибке
    """
    if config.disable_signature or not public_key:
        return ""
    
    loop = asyncio.get_event_loop()
    
    def _generate_signature():
        try:
            signature_ttl = ttl_seconds if ttl_seconds is not None else config.signature_ttl
                
            current_time = int(time.time())
            expiry_time = current_time + signature_ttl
            signature_data = f"{token}.{expiry_time}"
            
            if verbose_mode:
                print_status("INFO", f"Генерация подписи сервера для данных", signature_data)
                print(f"  Используется ПУБЛИЧНЫЙ ключ клиента: {config.client_public_key_path}")
                print(f"  Алгоритм: ШИФРОВАНИЕ публичным ключом клиента")
            
            # ШИФРУЕМ публичным ключом клиента (для исходящих ответов)
            encrypted_signature = public_key.encrypt(
                signature_data.encode('utf-8'),
                padding.PKCS1v15()  # Используем тот же padding что и для входящих
            )
            
            signature_b64 = base64.b64encode(encrypted_signature).decode('utf-8')
            
            if verbose_mode:
                print_status("OK", f"Сгенерирована подпись сервера длиной {len(encrypted_signature)} байт")
                print(f"  Время истечения подписи: {expiry_time} ({signature_ttl}сек от текущего времени)")
                print(f"  Метод: ШИФРОВАНИЕ публичным ключом клиента с PKCS1v15")
            
            return signature_b64
            
        except Exception as e:
            print_status("ERROR", f"Ошибка генерации серверной подписи", str(e))
            import traceback
            traceback.print_exc()
            return ""
    
    return await loop.run_in_executor(None, _generate_signature)


async def _extract_and_validate_token(request: web.Request) -> str:
    """
    Название: _extract_and_validate_token
    Назначение: Извлечение и валидация Bearer token из заголовков запроса
    Описание: Проверяет наличие и формат заголовка Token, извлекает токен и проверяет его наличие в белом списке
    Принцип работы: Проверяет заголовок Token на соответствие формату "Bearer <token>" и валидирует токен
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: str - валидный токен
    """
    token_header = request.headers.get("Token", "")
    if not token_header.startswith("Bearer "):
        raise web.HTTPForbidden(text=json.dumps({
            "status": "error",
            "message": "Требуется заголовок Token: Bearer <token>"
        }), content_type='application/json')
    
    token = token_header[7:]  # Убираем "Bearer "
    
    # Проверка токена в белом списке
    if token not in config.allowed_tokens:
        raise web.HTTPForbidden(text=json.dumps({
            "status": "error",
            "message": "Невалидный токен доступа"
        }), content_type='application/json')
    
    return token

async def _validate_signature(request: web.Request, token: str) -> None:
    """
    Название: _validate_signature
    Назначение: Валидация цифровой подписи из заголовков запроса
    Описание: Проверяет наличие заголовка Signature и его валидность с использованием токена
    Принцип работы: Проверяет наличие заголовка Signature и асинхронно проверяет его подлинность
    Входящие параметры: request - объект HTTP запроса, token - токен для проверки подписи
    Исходящие параметры: None
    """
    signature = request.headers.get("Signature", "")
    if not signature:
        raise web.HTTPForbidden(text=json.dumps({
            "status": "error",
            "message": "Требуется заголовок Signature"
        }), content_type='application/json')
    
    # Асинхронная проверка подписи
    is_signature_valid = await verify_client_signature(signature, token)
    
    if not is_signature_valid:
        raise web.HTTPForbidden(text=json.dumps({
            "status": "error",
            "message": "Невалидная или просроченная подпись"
        }), content_type='application/json')

def _get_optional_token(request: web.Request) -> str:
    """
    Название: _get_optional_token
    Назначение: Опциональное извлечение токена из запроса
    Описание: Извлекает токен если он присутствует, иначе возвращает значение по умолчанию
    Принцип работы: Проверяет наличие заголовка Token и возвращает токен или значение по умолчанию
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: str - токен или идентификатор "public"
    """
    token_header = request.headers.get("Token", "")
    if token_header.startswith("Bearer "):
        token = token_header[7:]
        # Проверяем, что токен валидный (опционально для публичных эндпоинтов)
        if token in config.allowed_tokens:
            return token
    return "public"

async def authenticate_request(request: web.Request) -> str:
    """
    Название: authenticate_request
    Назначение: Аутентификация и авторизация входящего HTTP запроса с поддержкой конфигурации безопасности эндпоинтов
    Описание: Проверяет подлинность запроса через Bearer token и RSA цифровую подпись согласно конфигурации безопасности эндпоинтов
    Принцип работы: Проверяет конфигурацию безопасности для эндпоинта, затем проверяет заголовки Token и Signature согласно требованиям
    Входящие параметры: request - объект HTTP запроса для аутентификации
    Исходящие параметры: str - аутентифицированный токен пользователя или специальный идентификатор
    """
    # Получаем путь эндпоинта
    endpoint_path = request.path
    
    # Получаем уровень безопасности для эндпоинта
    security_level = config.get_endpoint_security_level(endpoint_path)
    
    if verbose_mode:
        print_status("INFO", f"Уровень безопасности для {endpoint_path}", security_level or 'стандартный')
    
    # Обработка отключенных эндпоинтов
    if security_level == 'disabled':
        raise web.HTTPNotFound(text=json.dumps({
            "status": "error",
            "message": "Эндпоинт не найден"
        }), content_type='application/json')
    
    # Обработка публичных эндпоинтов (без аутентификации)
    if security_level == 'public':
        return _get_optional_token(request)
    
    # Обработка эндпоинтов, требующих только токен
    if security_level == 'token':
        return await _extract_and_validate_token(request)
    
    # Обработка эндпоинтов, требующих токен и подпись
    if security_level == 'signature':
        token = await _extract_and_validate_token(request)
        await _validate_signature(request, token)
        return token
    
    # Стандартная проверка (все эндпоинты требуют токен и подпись по умолчанию)
    # Проверяем, отключена ли аутентификация по токену глобально
    if config.disable_token_auth:
        # Если токен отключен, но заголовок присутствует - проверяем его
        token_header = request.headers.get("Token", "")
        if token_header.startswith("Bearer "):
            token = token_header[7:]
            # Проверка токена в белом списке (если присутствует)
            if token not in config.allowed_tokens:
                raise web.HTTPForbidden(text=json.dumps({
                    "status": "error",
                    "message": "Невалидный токен доступа"
                }), content_type='application/json')
        return "anonymous"  # Возвращаем анонимный идентификатор
    
    # Стандартная проверка токена
    token = await _extract_and_validate_token(request)
    
    # Проверяем, отключена ли проверка подписи глобально
    if config.disable_signature:
        return token  # Пропускаем проверку подписи
    
    # Стандартная проверка подписи
    await _validate_signature(request, token)
    
    return token


# --- РАБОТА С БАЗОЙ ДАННЫХ MSSQL ---

async def init_database():
    """
    Название: init_database
    Назначение: Инициализация подключения к базе данных MSSQL с настройкой параметров
    Описание: Устанавливает соединение с SQL Server и настраивает параметры для стабильности
    Принцип работы: Формирует строку подключения с параметрами из конфигурации и устанавливает соединение
    Входящие параметры: Отсутствуют (использует глобальную конфигурацию)
    Исходящие параметры: Отсутствуют (побочный эффект - установка глобального соединения)
    """
    global db_connection
    try:
        # Базовые параметры подключения
        conn_str_parts = [
            f'DRIVER={{{config.db_driver}}};',
            f'SERVER={config.db_server},{config.db_port};',
            f'DATABASE={config.db_name};',
            f'UID={config.db_username};',
            f'PWD={config.db_password};',
            f'Encrypt=no;',
            f'TrustServerCertificate=yes;',
            f'Connection Timeout={config.db_connection_timeout};'
        ]
        
        # Добавляем параметры пуллинга если включено
        if config.db_pooling_enabled:
            conn_str_parts.extend([
                f'Pooling=True;',
                f'Max Pool Size={config.db_max_pool_size};',
                f'Min Pool Size={config.db_min_pool_size};',
                f'Connection Lifetime={config.db_connection_lifetime};'
            ])
        else:
            conn_str_parts.append('Pooling=False;')
        
        # Формируем итоговую строку подключения
        conn_str = ''.join(conn_str_parts)
        
        # Создаем подключение
        db_connection = pyodbc.connect(conn_str)
        if verbose_mode:
            print_status("OK", f"Подключение к MSSQL серверу установлено")
            if config.db_pooling_enabled:
                print(f"  Пуллинг: ВКЛ (Lifetime: {config.db_connection_lifetime} сек)")
            else:
                print(f"  Пуллинг: ВЫКЛ")
        
        # Настраиваем параметры соединения
        cursor = db_connection.cursor()
        cursor.execute("SET LOCK_TIMEOUT 30000")  # Таймаут блокировок 30 секунд
        
        # Проверяем доступность базы данных
        cursor.execute("SELECT @@VERSION")
        version = cursor.fetchone()[0]
        if verbose_mode:
            print_status("OK", f"Версия сервера", version[:100] + "...")
        
        # Запускаем задачу периодической проверки соединения если включено
        if config.db_health_check_enabled:
            asyncio.create_task(start_db_health_check())
            if verbose_mode:
                print_status("INFO", f"Запущена фоновая проверка соединения")
                print(f"  Интервал проверки: {config.db_health_check_interval} сек")
        
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка подключения к MSSQL", str(e))
        if not config.allow_start_without_db:
            raise
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при подключении к БД", str(e))
        if not config.allow_start_without_db:
            raise

async def close_database():
    """
    Название: close_database
    Назначение: Корректное закрытие подключения к базе данных
    Описание: Закрывает активное соединение с SQL Server и освобождает ресурсы
    Принцип работы: Вызывает метод close() у объекта соединения и сбрасывает глобальную переменную
    Входящие параметры: Отсутствуют
    Исходящие параметры: Отсутствуют (побочный эффект - закрытие соединения)
    """
    global db_connection
    if db_connection:
        try:
            db_connection.close()
            if verbose_mode:
                print_status("OK", f"Подключение к базе данных закрыто")
        except Exception as e:
            print_status("ERROR", f"Ошибка при закрытии соединения с БД", str(e))
        finally:
            db_connection = None


async def execute_query(query: str, params: dict = None) -> List[Dict[str, Any]]:
    """
    Название: execute_query
    Назначение: Выполнение SQL запроса к базе данных с обработкой ошибок соединения
    Описание: Выполняет произвольный SQL запрос с параметризацией и автоматическим восстановлением при ошибках связи
    Принцип работы: Создает курсор, выполняет запрос с параметрами, обрабатывает результаты или изменения
    Входящие параметры: 
        query - строка SQL запроса
        params - словарь параметров для запроса (опционально)
    Исходящие параметры: List[Dict[str, Any]] - список словарей с результатами SELECT запроса
    """
    start_time = time.time()
    
    try:
        cursor = db_connection.cursor()
        
        if params:
            # Преобразуем параметры в список, заменяя None на NULL
            param_values = []
            for key in params:
                value = params[key]
                if value is None:
                    param_values.append(None)
                else:
                    param_values.append(value)
            
            cursor.execute(query, param_values)
        else:
            cursor.execute(query)
        
        if query.strip().upper().startswith('SELECT'):
            columns = [column[0] for column in cursor.description]
            results = []
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            # Записываем статистику успешного запроса
            execution_time = int((time.time() - start_time) * 1000)
            record_db_query(query, params, execution_time)
            
            return results
        else:
            db_connection.commit()
            
            # Записываем статистику успешного запроса
            execution_time = int((time.time() - start_time) * 1000)
            record_db_query(query, params, execution_time)
            
            return []
            
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка выполнения запроса", str(e))
        db_connection.rollback()
        
        # Пытаемся восстановить соединение при ошибке связи
        if "Communication link failure" in str(e) or "08S01" in str(e):
            if verbose_mode:
                print_status("INFO", f"Обнаружена ошибка соединения, пытаемся восстановить...")
            await reconnect_database()
            # Повторяем запрос после восстановления соединения
            return await execute_query(query, params)
        else:
            raise
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при выполнении запроса", str(e))
        db_connection.rollback()
        raise

async def health_check_db() -> bool:
    """
    Название: health_check_db
    Назначение: Проверка доступности и работоспособности базы данных
    Описание: Выполняет простой тестовый запрос для проверки соединения с БД
    Принцип работы: Выполняет запрос "SELECT 1" и проверяет успешность выполнения
    Входящие параметры: Отсутствуют
    Исходящие параметры: bool - True если БД доступна, False в противном случае
    """
    global db_connection
    
    if not db_connection:
        return False
    
    try:
        cursor = db_connection.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        return True
    except pyodbc.Error as e:
        if verbose_mode:
            print_status("WARNING", f"Соединение с БД неактивно", str(e))
        return False
    except Exception:
        return False
    

async def start_db_health_check():
    """
    Название: start_db_health_check
    Назначение: Периодическая проверка состояния соединения с БД
    Описание: Регулярно проверяет соединение с базой данных и восстанавливает при необходимости
    Принцип работы: Проверяет соединение с интервалом из конфигурации, переподключается при обрыве
    Входящие параметры: Отсутствуют
    Исходящие параметры: Отсутствуют
    """
    while True:
        # Используем интервал из конфигурации
        await asyncio.sleep(config.db_health_check_interval)
        
        if db_connection:
            if not await health_check_db():
                if verbose_mode:
                    print_status("WARNING", f"Периодическая проверка: соединение с БД потеряно")
                try:
                    await reconnect_database()
                    if verbose_mode:
                        print_status("OK", f"Соединение с БД восстановлено")
                except Exception as e:
                    print_status("ERROR", f"Не удалось восстановить соединение с БД", str(e))

async def reconnect_database():
    """
    Название: reconnect_database
    Назначение: Переподключение к базе данных
    Описание: Закрывает текущее соединение и устанавливает новое с параметрами из конфигурации
    Принцип работы: Закрывает существующее соединение и создает новое с настройками из конфига
    Входящие параметры: Отсутствуют
    Исходящие параметры: Отсутствуют
    """
    global db_connection
    
    try:
        if db_connection:
            db_connection.close()
            db_connection = None
            if verbose_mode:
                print_status("INFO", f"Существующее соединение с БД закрыто")
    except:
        pass
    
    try:
        # Базовые параметры подключения
        conn_str_parts = [
            f'DRIVER={{{config.db_driver}}};',
            f'SERVER={config.db_server},{config.db_port};',
            f'DATABASE={config.db_name};',
            f'UID={config.db_username};',
            f'PWD={config.db_password};',
            f'Encrypt=no;',
            f'TrustServerCertificate=yes;',
            f'Connection Timeout={config.db_connection_timeout};'
        ]
        
        # Добавляем параметры пуллинга если включено
        if config.db_pooling_enabled:
            conn_str_parts.extend([
                f'Pooling=True;',
                f'Max Pool Size={config.db_max_pool_size};',
                f'Min Pool Size={config.db_min_pool_size};',
                f'Connection Lifetime={config.db_connection_lifetime};'
            ])
        else:
            conn_str_parts.append('Pooling=False;')
        
        # Формируем итоговую строку подключения
        conn_str = ''.join(conn_str_parts)
        
        # Создаем новое подключение
        db_connection = pyodbc.connect(conn_str)
        
        # Настраиваем параметры соединения для предотвращения разрывов
        cursor = db_connection.cursor()
        cursor.execute("SET LOCK_TIMEOUT 30000")  # Таймаут блокировок 30 секунд
        
        if verbose_mode:
            print_status("OK", f"Успешно переподключились к базе данных")
            if config.db_pooling_enabled:
                print(f"  Пуллинг: ВКЛ (Lifetime: {config.db_connection_lifetime} сек)")
            else:
                print(f"  Пуллинг: ВЫКЛ")
        
    except Exception as e:
        print_status("ERROR", f"Ошибка переподключения к базе данных", str(e))
        raise


async def db_user_by_phone(phone: str) -> Optional[Dict[str, Any]]:
    """
    Название: db_user_by_phone
    Назначение: Получение данных пользователя по телефону из базы данных через хранимую процедуру
    Описание: Сначала вызывает USR_Insert для регистрации/получения пользователя, 
              затем USR_Select для получения полных данных в формате JSON
    Принцип работы: Вызывает хранимые процедуры с параметрами и обрабатывает JSON результат
    Входящие параметры: 
        phone - телефон пользователя
    Исходящие параметры: Optional[Dict[str, Any]] - данные пользователя в виде словаря или None
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    normalized_phone = normalize_phone(phone)
    if not normalized_phone:
        return None
    
    try:
        # Первый шаг: получение user_id через USR_Insert
        query = "EXECUTE [dbo].[USR_Insert] @USR_Phone = ?"
        
        cursor = db_connection.cursor()
        cursor.execute("SET LOCK_TIMEOUT 30000")
        cursor.execute(query, (normalized_phone,))
        
        user_id = cursor.fetchval()
        db_connection.commit()
        cursor.close()
        
        if verbose_mode:
            print_status("INFO", f"Получен user_id из процедуры USR_Insert: {user_id}")
        
        if user_id is None or user_id <= 0:
            return None
        
        # Второй шаг: получение данных пользователя через USR_Select
        query = "EXECUTE [dbo].[USR_Select] @USR_Id = ?"
        
        cursor = db_connection.cursor()
        cursor.execute("SET LOCK_TIMEOUT 30000")
        cursor.execute(query, (user_id,))
        
        # Получаем результаты
        results = []
        try:
            if cursor.description:  # Если есть возвращаемые колонки
                columns = [column[0] for column in cursor.description]
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
        except pyodbc.ProgrammingError:
            # Ожидаемая ошибка - нет данных для чтения
            if verbose_mode:
                print_status("INFO", f"Процедура USR_Select не возвращает данные для чтения")
            pass
        
        db_connection.commit()
        cursor.close()
        
        if verbose_mode:
            print_status("INFO", f"Процедура USR_Select выполнена")
            print(f"  Получено результатов: {len(results)}")
        
        # Обработка результата процедуры
        if results and len(results) > 0:
            result_row = results[0]
            
            # Получаем данные из первого столбца
            json_data = None
            if result_row and len(result_row) > 0:
                # Берем значение первого столбца (без имени поля)
                first_column_value = list(result_row.values())[0]
                
                if verbose_mode:
                    print_status("INFO", f"Тип полученных данных: {type(first_column_value).__name__}")
                
                if first_column_value is not None:
                    # Проверяем, не вернулся ли -1 (ошибка)
                    if isinstance(first_column_value, (int, float)):
                        if first_column_value == -1:
                            if verbose_mode:
                                print_status("WARNING", f"Процедура USR_Select вернула ошибку", "ID = -1")
                            return None
                    elif isinstance(first_column_value, str):
                        json_data = first_column_value
                        if verbose_mode:
                            print_status("INFO", f"Получены JSON данные длиной {len(json_data)} символов")
            
            if json_data:
                try:
                    # Парсим JSON строку
                    parsed_data = json.loads(json_data)
                    
                    if isinstance(parsed_data, list) and len(parsed_data) > 0:
                        # Процедура возвращает список с одним элементом
                        user_data = parsed_data[0]
                        
                        if verbose_mode:
                            print_status("OK", f"Найден пользователь", 
                                       f"ID: {user_data.get('USR_Id')}, Телефон: {user_data.get('USR_Phone')}")
                        
                        return user_data
                    else:
                        if verbose_mode:
                            print_status("WARNING", f"Неверный формат JSON данных", 
                                       f"Ожидался список, получен: {type(parsed_data).__name__}")
                        
                except json.JSONDecodeError as e:
                    if verbose_mode:
                        print_status("ERROR", f"Ошибка парсинга JSON из процедуры USR_Select", str(e))
                        print(f"  JSON данные (первые 200 символов): {json_data[:200]}...")
                except Exception as e:
                    if verbose_mode:
                        print_status("ERROR", f"Ошибка при обработке JSON данных", str(e))
            else:
                if verbose_mode:
                    print_status("INFO", f"Процедура USR_Select не вернула JSON данные")
                    print(f"  Результаты: {results}")
        else:
            if verbose_mode:
                print_status("INFO", f"Процедура USR_Select не вернула результаты")
        
        return None
        
    except pyodbc.OperationalError as e:
        if "timeout" in str(e).lower():
            print_status("ERROR", f"Таймаут выполнения хранимой процедуры", 
                        f"phone: {normalized_phone}")
            try:
                db_connection.rollback()
            except:
                pass
            raise Exception(f"Таймаут выполнения операции поиска пользователя: {str(e)}")
        else:
            print_status("ERROR", f"Операционная ошибка при поиске пользователя {normalized_phone}", str(e))
            try:
                db_connection.rollback()
            except:
                pass
            raise
            
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка базы данных при поиске пользователя {normalized_phone}", str(e))
        try:
            db_connection.rollback()
        except:
            pass
        raise
        
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при поиске пользователя {normalized_phone}", str(e))
        try:
            db_connection.rollback()
        except:
            pass
        raise

async def db_user_update(user_id: int, email: str, password: str) -> bool:
    """
    Название: db_user_update
    Назначение: Обновление данных пользователя в базе данных через хранимую процедуру
    Описание: Выполняет вызов хранимой процедуры USR_Update для обновления email и пароля пользователя
    Принцип работы: Вызывает хранимую процедуру с параметрами и обрабатывает результат
    Входящие параметры: 
        user_id - идентификатор пользователя
        email - новый email пользователя
        password - новый пароль пользователя
    Исходящие параметры: bool - True если операция успешна, False если USR_ID = -1
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    try:
        # Вызов хранимой процедуры USR_Update с таймаутом
        query = "EXECUTE [dbo].[USR_Update] @USR_ID = ?, @USR_Email = ?, @USR_Password = ?"
        
        if verbose_mode:
            print_status("INFO", f"Вызов хранимой процедуры USR_Update", 
                        f"user_id: {user_id}, email: {email}")
        
        # Создаем курсор с таймаутом
        cursor = db_connection.cursor()
        
        # Устанавливаем таймаут выполнения (30 секунд)
        cursor.execute("SET LOCK_TIMEOUT 30000")
        
        # Выполняем хранимую процедуру с обработкой параметров
        cursor.execute(query, (user_id, email, password))
        
        # Пытаемся получить результаты, если процедура их возвращает
        results = []
        try:
            if cursor.description:  # Если есть возвращаемые колонки
                columns = [column[0] for column in cursor.description]
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
        except pyodbc.ProgrammingError:
            # Ожидаемая ошибка - нет данных для чтения
            if verbose_mode:
                print_status("INFO", f"Процедура не возвращает данные для чтения")
            pass
        
        # Фиксируем изменения
        db_connection.commit()
        
        # Закрываем курсор для освобождения ресурсов
        cursor.close()
        
        if verbose_mode:
            print_status("OK", f"Хранимая процедура USR_Update выполнена успешно")
        
        # Обрабатываем результат процедуры
        if results and len(results) > 0:
            result_row = results[0]
            usr_id = result_row.get('ID')
            
            if verbose_mode:
                print_status("INFO", f"Получен USR_ID из процедуры: {usr_id}")
            
            # Если USR_ID = -1, возвращаем False, иначе True
            if usr_id == '-1':
                return False
            else:
                return True
        
        # Если процедура не возвращает результат, считаем операцию успешной
        if verbose_mode:
            print_status("INFO", "Процедура не вернула результат, операция считается успешной")
        return True
        
    except pyodbc.OperationalError as e:
        if "timeout" in str(e).lower():
            print_status("ERROR", f"Таймаут выполнения хранимой процедуры USR_Update", 
                        f"user_id: {user_id}")
            # Откатываем транзакцию при таймауте
            try:
                db_connection.rollback()
            except:
                pass
            raise Exception(f"Таймаут выполнения операции обновления пользователя: {str(e)}")
        else:
            print_status("ERROR", f"Операционная ошибка при обновлении пользователя {user_id}", str(e))
            db_connection.rollback()
            raise
            
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка базы данных при обновлении пользователя {user_id}", str(e))
        db_connection.rollback()
        raise
        
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при обновлении пользователя {user_id}", str(e))
        try:
            db_connection.rollback()
        except:
            pass
        raise

async def db_tickets(user_id: str, status: str = '') -> List[Dict[str, Any]]:
    """
    Название: db_tickets
    Назначение: Получение списка залоговых билетов пользователя из базы данных через хранимую процедуру
    Описание: Вызывает хранимую процедуру ZbTickets_Json для получения залоговых билетов в формате JSON
    Принцип работы: Выполняет хранимую процедуру с параметрами user_id и status, парсит JSON результат
    Входящие параметры:
        user_id - идентификатор пользователя
        status - статус залоговых билетов для фильтрации (опционально)
    Исходящие параметры: List[Dict[str, Any]] - список залоговых билетов или пустой список при ошибке
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    try:
        # Подготавливаем параметры для хранимой процедуры
        status_param = status if status else ''
        
        if verbose_mode:
            print_status("INFO", f"Вызов хранимой процедуры ZbTickets_Json", 
                        f"user_id: {user_id}, status: {status_param}")
        
        # Используем правильный вызов процедуры с двумя параметрами
        query = "EXECUTE [dbo].[ZbTickets_Json] @USR_Id = ?, @Status = ?"
        
        cursor = db_connection.cursor()
        
        # Устанавливаем таймаут выполнения (30 секунд)
        cursor.execute("SET LOCK_TIMEOUT 30000")
        
        # Выполняем хранимую процедуру с двумя параметрами
        cursor.execute(query, (user_id, status_param))

        # log_to_file('DEBUG',cursor.fetchval())

        # Получаем результаты
        results = []
        try:
            if cursor.description:  # Если есть возвращаемые колонки
                columns = [column[0] for column in cursor.description]
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
        except pyodbc.ProgrammingError:
            # Ожидаемая ошибка - нет данных для чтения
            if verbose_mode:
                print_status("INFO", f"Процедура не возвращает данные для чтения")
            pass
        
        # Фиксируем изменения
        db_connection.commit()
        
        # Закрываем курсор для освобождения ресурсов
        cursor.close()
        
        if verbose_mode:
            print_status("OK", f"Хранимая процедура ZbTickets_Json выполнена успешно")
            print(f"  Получено результатов: {len(results)}")
        
        # Обрабатываем результат процедуры
        tickets_list = []  # Инициализируем переменную
        
        if results and len(results) > 0:
            # Новая процедура возвращает JSON напрямую в первом столбце
            result_row = results[0]
            
            # Получаем данные из первого столбца
            json_data = None
            if result_row and len(result_row) > 0:
                # Берем значение первого столбца (без имени поля)
                first_column_value = list(result_row.values())[0]
                if first_column_value and isinstance(first_column_value, str):
                    json_data = first_column_value
                    if verbose_mode:
                        print_status("INFO", f"Получены JSON данные длиной {len(json_data)} символов")
            
            if json_data:
                try:
                    # Парсим JSON строку
                    parsed_data = json.loads(json_data)
                    
                    if isinstance(parsed_data, list):
                        # Прямой список залоговых билетов
                        tickets_list = parsed_data
                        if verbose_mode:
                            print_status("OK", f"Успешно распарсено залоговых билетов", str(len(tickets_list)))
                            
                            # Выводим информацию о первом залоговом билете для отладки
                            if tickets_list and len(tickets_list) > 0:
                                first_ticket = tickets_list[0]
                                print(f"  Первый залоговый билет: {first_ticket.get('external_id', 'N/A')} - {first_ticket.get('status', 'N/A')}")
                                print(f"  Количество предметов: {len(first_ticket.get('items', []))}")
                    
                    elif isinstance(parsed_data, dict):
                        # Если вернулся словарь, проверяем есть ли в нем поле tickets
                        if 'tickets' in parsed_data and isinstance(parsed_data['tickets'], list):
                            tickets_list = parsed_data['tickets']
                            if verbose_mode:
                                print_status("OK", f"Успешно распарсено залоговых билетов из поля 'tickets'", str(len(tickets_list)))
                        else:
                            if verbose_mode:
                                print_status("ERROR", f"Ожидался список залоговых билетов, получен словарь без поля 'tickets'")
                                print(f"  Ключи в словаре: {list(parsed_data.keys())}")
                    else:
                        if verbose_mode:
                            print_status("ERROR", f"Неверный формат данных от процедуры", type(parsed_data).__name__)
                        
                except json.JSONDecodeError as e:
                    if verbose_mode:
                        print_status("ERROR", f"Ошибка парсинга JSON из процедуры", str(e))
                        print(f"  JSON данные (первые 500 символов): {json_data[:500]}...")
                        print(f"  Длина JSON данных: {len(json_data)}")
                except Exception as e:
                    if verbose_mode:
                        print_status("ERROR", f"Ошибка при обработке JSON данных", str(e))
            else:
                if verbose_mode:
                    print_status("ERROR", f"Процедура не вернула JSON данные")
                    print(f"  Результаты: {results}")
        else:
            if verbose_mode:
                print_status("INFO", f"Процедура не вернула результаты")
        
        # Если нет результатов или пустой результат
        if verbose_mode:
            if not tickets_list:
                print_status("INFO", f"Процедура не вернула данные залоговых билетов или список пуст")
            else:
                print_status("OK", f"Успешно получено залоговых билетов", str(len(tickets_list)))
        
        return tickets_list
        
    except pyodbc.OperationalError as e:
        if "timeout" in str(e).lower():
            print_status("ERROR", f"Таймаут выполнения хранимой процедуры ZbTickets_Json", 
                        f"user_id: {user_id}, status: {status}")
            # Откатываем транзакцию при таймауте
            try:
                db_connection.rollback()
            except:
                pass
            raise Exception(f"Таймаут выполнения операции получения залоговых билетов: {str(e)}")
        else:
            print_status("ERROR", f"Операционная ошибка при получении залоговых билетов {user_id}", str(e))
            db_connection.rollback()
            raise
            
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка базы данных при получении залоговых билетов {user_id}", str(e))
        db_connection.rollback()
        raise
        
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при получении залоговых билетов {user_id}", str(e))
        try:
            db_connection.rollback()
        except:
            pass
        raise

async def db_setpayment(data: str) -> bool:
    """
    Название: db_setpayment
    Назначение: Вызов хранимой процедуры Pay_created_at для обработки платежей
    Описание: Передает JSON строку как есть в хранимую процедуру без дополнительных преобразований
    Принцип работы: Передает полученную строку напрямую в хранимую процедуру
    Входящие параметры:
        data - JSON строка с данными платежей (как получено в запросе)
    Исходящие параметры: bool - True если обработка успешна (ID = '0'), False если ошибка (ID = '-1')
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    try:
        # Проверяем, что data - это строка
        if not isinstance(data, str):
            if verbose_mode:
                print_status("ERROR", f"Параметр data должен быть строкой", f"тип: {type(data).__name__}")
            return False
        
        if verbose_mode:
            print_status("INFO", f"Передача данных в хранимую процедуру", f"длина JSON: {len(data)} символов")
            if len(data) < 500:
                print(f"  Данные: {data}")
            else:
                print(f"  Данные (первые 500 символов): {data[:500]}...")
        
        # Вызываем хранимую процедуру Pay_created_at с JSON строкой
        query = "EXECUTE [dbo].[Pay_created_at] @PAY_date = ?"
        
        cursor = db_connection.cursor()
        
        # Устанавливаем таймаут выполнения (30 секунд)
        cursor.execute("SET LOCK_TIMEOUT 30000")
        
        # Выполняем хранимую процедуру с JSON строкой
        cursor.execute(query, (data,))
        
        # Получаем результаты
        results = []
        try:
            if cursor.description:  # Если есть возвращаемые колонки
                columns = [column[0] for column in cursor.description]
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
        except pyodbc.ProgrammingError:
            # Ожидаемая ошибка - нет данных для чтения
            if verbose_mode:
                print_status("INFO", f"Процедура не возвращает данные для чтения")
            pass
        
        # Фиксируем изменения
        db_connection.commit()
        
        # Закрываем курсор для освобождения ресурсов
        cursor.close()
        
        if verbose_mode:
            print_status("OK", f"Хранимая процедура Pay_created_at выполнена успешно")
            print(f"  Получено результатов: {len(results)}")
            if results:
                print(f"  Результаты: {results}")
        
        # Обрабатываем результат процедуры
        if results and len(results) > 0:
            result_row = results[0]
            
            # Получаем значение ID из первого результата
            result_id = result_row.get('ID')
            
            if verbose_mode:
                print_status("INFO", f"Получен ID из процедуры: '{result_id}'")
            
            # Проверяем результат согласно логике хранимой процедуры
            if result_id == '0':
                # ID = '0' - операция выполнена успешно
                if verbose_mode:
                    print_status("OK", f"Операция выполнена успешно (ID = '0')")
                return True
            elif result_id == '-1':
                # ID = '-1' - ошибка выполнения операции
                if verbose_mode:
                    print_status("ERROR", f"Ошибка выполнения операции (ID = '-1')")
                return False
            else:
                # Неизвестное значение ID
                if verbose_mode:
                    print_status("ERROR", f"Неизвестный результат операции", f"ID = '{result_id}'")
                return False
        else:
            # Нет результатов или пустой результат - ошибка
            if verbose_mode:
                print_status("ERROR", f"Процедура не вернула результаты или вернула пустой результат")
            return False
        
    except pyodbc.OperationalError as e:
        if "timeout" in str(e).lower():
            print_status("ERROR", f"Таймаут выполнения хранимой процедуры Pay_created_at")
            # Откатываем транзакцию при таймауте
            try:
                db_connection.rollback()
            except:
                pass
            raise Exception(f"Таймаут выполнения операции обработки платежей: {str(e)}")
        else:
            print_status("ERROR", f"Операционная ошибка при обработке платежей", str(e))
            db_connection.rollback()
            raise
            
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка базы данных при обработке платежей", str(e))
        db_connection.rollback()
        raise
        
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при обработке платежей", str(e))
        try:
            db_connection.rollback()
        except:
            pass
        raise


async def db_login(phone: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Название: db_login
    Назначение: Аутентификация пользователя по телефону и паролю через хранимую процедуру
    Описание: Вызывает хранимую процедуру USR_Select_ID для проверки логина и пароля.
              Если процедура вернула -1, дополнительно проверяет USR_xDel,
              чтобы различить блокировку пользователя и неверные учетные данные.
    Принцип работы: Нормализует телефон, вызывает процедуру с параметрами phone и password.
    Входящие параметры:
        phone - номер телефона пользователя
        password - пароль пользователя
    Исходящие параметры: Dict[str, Any] - результат аутентификации
    """
    if not db_connection:
        raise Exception("База данных не доступна")

    normalized_phone = normalize_phone(phone)
    if not normalized_phone:
        return {"status": "invalid_credentials"}

    try:
        query = "EXECUTE [dbo].[USR_Select_ID] @USR_Phone = ?, @USR_Password = ?"

        cursor = db_connection.cursor()
        cursor.execute("SET LOCK_TIMEOUT 30000")
        cursor.execute(query, (normalized_phone, password))

        result = cursor.fetchval()
        db_connection.commit()
        cursor.close()

        if result is None:
            return {"status": "invalid_credentials"}

        result_str = str(result).strip()

        # Совместимость: если процедура когда-либо начнёт возвращать -2,
        # трактуем это как блокировку пользователя.
        if result_str == "-2":
            return {"status": "blocked"}

        if result_str == "-1":
            # USR_Select_ID возвращает -1 в нескольких случаях:
            # 1) неверный пароль,
            # 2) превышен лимит неудачных попыток,
            # 3) пользователь скрыт процедурой из-за USR_xDel = 1.
            # Чтобы не путать блокировку с неверным паролем,
            # дополнительно проверяем статус пользователя напрямую в USR.
            try:
                cursor2 = db_connection.cursor()
                cursor2.execute("SET LOCK_TIMEOUT 10000")

                cursor2.execute(
                    "SELECT COUNT(*) FROM [dbo].[USR] (nolock) "
                    "WHERE USR_Phone = ? AND (USR_xDel IS NULL OR USR_xDel = 0)",
                    normalized_phone
                )
                active_count_row = cursor2.fetchone()
                active_count = active_count_row[0] if active_count_row and active_count_row[0] is not None else 0

                cursor2.execute(
                    "SELECT COUNT(*) FROM [dbo].[USR] (nolock) "
                    "WHERE USR_Phone = ? AND USR_xDel = 1",
                    normalized_phone
                )
                blocked_count_row = cursor2.fetchone()
                blocked_count = blocked_count_row[0] if blocked_count_row and blocked_count_row[0] is not None else 0
                cursor2.close()

                if verbose_mode:
                    print_status(
                        "INFO",
                        "Проверка статуса пользователя после USR_Select_ID = -1",
                        f"phone: {normalized_phone}, active_count: {active_count}, blocked_count: {blocked_count}"
                    )

                # Для текущей модели БД USR_xDel = 1 трактуется как блокировка/деактивация.
                # Если по телефону существует хотя бы одна заблокированная запись,
                # возвращаем блокировку, чтобы не смешивать это состояние с неверным паролем.
                if blocked_count > 0:
                    if verbose_mode:
                        print_status(
                            "WARNING",
                            "Пользователь заблокирован по USR_xDel",
                            f"phone: {normalized_phone}, active_count: {active_count}, blocked_count: {blocked_count}"
                        )
                    return {"status": "blocked"}

            except Exception as check_err:
                print_status(
                    "ERROR",
                    "Ошибка дополнительной проверки блокировки пользователя",
                    f"phone: {normalized_phone}, error: {str(check_err)}"
                )
                try:
                    cursor2.close()
                except Exception:
                    pass

            return {"status": "invalid_credentials"}

        if not isinstance(result, str):
            return {"status": "error", "message": f"Неожиданный тип результата: {type(result).__name__}"}

        parsed_data = json.loads(result)

        if isinstance(parsed_data, list) and len(parsed_data) > 0:
            user_data = parsed_data[0]
            user_id = user_data.get('id', user_data.get('USR_Id', -1))
            if user_id == -1:
                return {"status": "invalid_credentials"}
            return {"status": "success", "data": user_data}

        return {"status": "error", "message": "Неверный формат ответа USR_Select_ID"}

    except json.JSONDecodeError:
        return {"status": "error", "message": "USR_Select_ID вернула невалидный JSON"}
    except pyodbc.OperationalError as e:
        stre = str(e)
        if "timeout" in stre.lower():
            print_status("ERROR", "Таймаут БД в db_login", f"phone: {normalized_phone}, error: {stre}")
            try:
                db_connection.rollback()
            except Exception:
                pass
            raise Exception(f"Таймаут БД: {stre}")
        print_status("ERROR", "Ошибка БД в db_login", f"phone: {normalized_phone}, error: {stre}")
        try:
            db_connection.rollback()
        except Exception:
            pass
        raise
    except Exception as e:
        print_status("ERROR", "Неожиданная ошибка в db_login", f"phone: {normalized_phone}, error: {str(e)}")
        try:
            db_connection.rollback()
        except Exception:
            pass
        raise

async def db_setdocument(user_id: int, name: str, extension: str, cloud_link: str, description: str = None) -> Dict[str, Any]:
    """
    Название: db_setdocument
    Назначение: Сохранение метаданных документа в базе данных
    Описание: Сохраняет информацию о документе в БД через хранимую процедуру Doc_created_at
    Принцип работы: Вызывает хранимую процедуру с параметрами документа
    Входящие параметры:
        user_id - идентификатор пользователя
        name - имя файла
        extension - расширение файла
        cloud_link - ссылка на файл в облаке
        description - описание документа (опционально)
    Исходящие параметры: Dict[str, Any] - результат операции
    """
    result = {
        "success": False,
        "record_id": None,
        "message": ""
    }
    
    if not db_connection:
        result["message"] = "База данных не доступна"
        return result
    
    try:
        # Анализируем обязательные поля хранимой процедуры Doc_created_at
        # Обязательные: USR_Id, DOC_Type, DOC_Name, DOC_Link, DOC_Date
        # Опциональные: DOC_Desc
        
        # doc_type = extension.upper() if extension else "UNKNOWN"
        doc_type = extension or ""
        doc_name = name or f"document_{int(time.time())}"
        doc_link = cloud_link or ""
        doc_desc = description or ""
        doc_date = datetime.now().date()
        
        if verbose_mode:
            print_status("INFO", f"Вызов хранимой процедуры Doc_created_at", 
                        f"user_id: {user_id}, name: {doc_name}, type: {doc_type}")
            if cloud_link:
                print(f"  Ссылка на облако: {cloud_link}")
        
        query = """
        EXECUTE [dbo].[Doc_created_at] 
            @USR_Id = ?, 
            @DOC_Type = ?, 
            @DOC_Name = ?, 
            @DOC_Link = ?, 
            @DOC_Desc = ?, 
            @DOC_Date = ?
        """
        



        # ВЫВОДИМ SQL КОМАНДУ С ПОДСТАВЛЕННЫМИ ПАРАМЕТРАМИ
        # Это важно для отладки - видим что именно отправляется на SQL Server
        sql_debug = query.replace('?', '{}').format(
            repr(user_id) if user_id is not None else 'NULL',
            repr(doc_type),
            repr(doc_name),
            repr(doc_link),
            repr(doc_desc) if doc_desc else 'NULL',
            repr(doc_date.isoformat())
        )
        
        print("\n" + "="*80)
        print("DEBUG SQL COMMAND SENT TO DATABASE:")
        print("="*80)
        print(sql_debug)
        print("="*80)
        
        if verbose_mode:
            print_status("DEBUG", f"Параметры SQL запроса:")
            print(f"  user_id: {user_id} (тип: {type(user_id).__name__})")
            print(f"  doc_type: {doc_type} (тип: {type(doc_type).__name__})")
            print(f"  doc_name: {doc_name} (тип: {type(doc_name).__name__})")
            print(f"  doc_link: {doc_link} (тип: {type(doc_link).__name__})")
            print(f"  doc_desc: {doc_desc} (тип: {type(doc_desc).__name__})")
            print(f"  doc_date: {doc_date} (тип: {type(doc_date).__name__})")



        cursor = db_connection.cursor()
        cursor.execute("SET LOCK_TIMEOUT 30000")
        cursor.execute(query, (user_id, doc_type, doc_name, doc_link, doc_desc, doc_date))
        
        record_id = cursor.fetchval()
        db_connection.commit()
        cursor.close()
        
        if record_id is not None:
            try:
                record_id_int = int(record_id)
                if record_id_int == -1:
                    result["message"] = "Ошибка сохранения в базе данных"
                    if verbose_mode:
                        print_status("ERROR", f"Процедура вернула ошибку (ID = -1)")
                    return result
                else:
                    result["success"] = True
                    result["record_id"] = record_id_int
                    result["message"] = "Документ успешно сохранен в БД"
                    
                    if verbose_mode:
                        print_status("OK", f"Успешно создана запись документа", f"ID: {record_id_int}")
                    
                    return result
                    
            except (ValueError, TypeError) as e:
                result["message"] = f"Ошибка обработки результата БД: {str(e)}"
                if verbose_mode:
                    print_status("ERROR", f"Ошибка преобразования результата", str(e))
                return result
        else:
            result["message"] = "Процедура не вернула результат"
            if verbose_mode:
                print_status("ERROR", f"Процедура не вернула результат")
            return result
        
    except pyodbc.OperationalError as e:
        error_msg = f"Таймаут операции: {str(e)}" if "timeout" in str(e).lower() else f"Ошибка БД: {str(e)}"
        result["message"] = error_msg
        try:
            db_connection.rollback()
        except:
            pass
        return result
    except Exception as e:
        result["message"] = f"Неожиданная ошибка: {str(e)}"
        try:
            db_connection.rollback()
        except:
            pass
        return result
    
async def db_documentsigned(document_id: str, is_signed: bool) -> bool:
    """
    Название: db_documentsigned
    Назначение: Обновление статуса подписания документа через хранимую процедуру
    Описание: Вызывает хранимую процедуру Doc_Update_signed для обновления статуса подписания документа
    Принцип работы: Преобразует параметры и вызывает хранимую процедуру с проверкой результата
    Входящие параметры:
        document_id - идентификатор документа
        is_signed - статус подписания (True - подписан, False - отклонен)
    Исходящие параметры: bool - True если операция успешна, False если DOC_Id = -1
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    try:
        # Преобразуем document_id в число
        try:
            doc_id_int = int(document_id)
        except (ValueError, TypeError):
            raise Exception(f"Неверный формат document_id: '{document_id}'")
        
        # Преобразуем boolean в int (1 - подписан, 0 - отклонен)
        doc_is_signed_int = 1 if is_signed else 0
        
        if verbose_mode:
            print_status("INFO", f"Вызов хранимой процедуры Doc_Update_signed", 
                        f"document_id: {doc_id_int}, is_signed: {doc_is_signed_int} ({'подписан' if is_signed else 'отклонен'})")
        
        query = "EXECUTE [dbo].[Doc_Update_signed] @DOC_Id = ?, @DOC_Is_signed = ?"
        
        cursor = db_connection.cursor()
        
        # Устанавливаем таймаут выполнения (30 секунд)
        cursor.execute("SET LOCK_TIMEOUT 30000")
        
        # Выполняем хранимую процедуру с параметрами
        cursor.execute(query, (doc_id_int, doc_is_signed_int))
        
        # Получаем результат
        result_id = cursor.fetchval()
        
        # Фиксируем изменения
        db_connection.commit()
        
        # Закрываем курсор для освобождения ресурсов
        cursor.close()
        
        if verbose_mode:
            print_status("OK", f"Хранимая процедура Doc_Update_signed выполнена успешно")
            print(f"  Получен ID: {result_id}")
        
        # Обрабатываем результат процедуры
        if result_id is not None:
            try:
                result_id_int = int(result_id)
                
                if result_id_int == -1:
                    if verbose_mode:
                        print_status("ERROR", f"Ошибка в хранимой процедуре (ID = -1)")
                    return False
                else:
                    if verbose_mode:
                        print_status("OK", f"Статус документа успешно обновлен", f"ID: {result_id_int}")
                    return True
                    
            except (ValueError, TypeError) as e:
                if verbose_mode:
                    print_status("ERROR", f"Ошибка преобразования результата", str(e))
                return False
        else:
            if verbose_mode:
                print_status("ERROR", f"Процедура не вернула результат")
            return False
        
    except pyodbc.OperationalError as e:
        if "timeout" in str(e).lower():
            print_status("ERROR", f"Таймаут выполнения хранимой процедуры Doc_Update_signed", 
                        f"document_id: {document_id}")
            try:
                db_connection.rollback()
            except:
                pass
            raise Exception(f"Таймаут выполнения операции обновления статуса документа: {str(e)}")
        else:
            print_status("ERROR", f"Операционная ошибка при обновлении статуса документа {document_id}", str(e))
            db_connection.rollback()
            raise
            
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка базы данных при обновлении статуса документа {document_id}", str(e))
        db_connection.rollback()
        raise
        
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при обновлении статуса документа {document_id}", str(e))
        try:
            db_connection.rollback()
        except:
            pass
        raise

async def db_documentlist(user_id: str) -> List[Dict[str, Any]]:
    """
    Название: db_documentlist
    Назначение: Получение списка документов пользователя через хранимую процедуру DOC_Select_ID
    Описание: Вызывает хранимую процедуру DOC_Select_ID для получения списка документов в формате JSON
    Принцип работы: Выполняет хранимую процедуру с параметром user_id, парсит JSON результат
    Входящие параметры:
        user_id - идентификатор пользователя
    Исходящие параметры: List[Dict[str, Any]] - список документов или пустой список при ошибке
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    try:
        # Преобразуем user_id в число
        try:
            user_id_int = int(user_id)
        except (ValueError, TypeError):
            raise Exception(f"Неверный формат user_id: '{user_id}'")
        
        if verbose_mode:
            print_status("INFO", f"Вызов хранимой процедуры DOC_Select_ID", 
                        f"user_id: {user_id_int}")
        
        query = "EXECUTE [dbo].[DOC_Select_ID] @USR_ID = ?"
        
        cursor = db_connection.cursor()
        
        # Устанавливаем таймаут выполнения (30 секунд)
        cursor.execute("SET LOCK_TIMEOUT 30000")
        
        # Выполняем хранимую процедуру с параметром
        cursor.execute(query, (user_id_int,))

        # Получаем результаты
        results = []
        try:
            if cursor.description:  # Если есть возвращаемые колонки
                columns = [column[0] for column in cursor.description]
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
        except pyodbc.ProgrammingError:
            # Ожидаемая ошибка - нет данных для чтения
            if verbose_mode:
                print_status("INFO", f"Процедура не возвращает данные для чтения")
            pass
        
        # Фиксируем изменения
        db_connection.commit()
        
        # Закрываем курсор для освобождения ресурсов
        cursor.close()
        
        if verbose_mode:
            print_status("OK", f"Хранимая процедура DOC_Select_ID выполнена успешно")
            print(f"  Получено результатов: {len(results)}")
        
        # Обрабатываем результат процедуры
        documents_list = []
        
        if results and len(results) > 0:
            result_row = results[0]
            
            # Получаем данные из поля ID (которое содержит JSON)
            json_data = result_row.get('ID')
            
            if verbose_mode:
                print_status("INFO", f"Получены JSON данные длиной {len(str(json_data))} символов")
            
            # Проверяем, не вернула ли процедура ошибку (-1)
            if json_data == '-1':
                if verbose_mode:
                    print_status("ERROR", f"Процедура вернула ошибку (ID = -1)")
                return documents_list
            
            if json_data and isinstance(json_data, str) and json_data != '-1':
                try:
                    # Парсим JSON строку
                    parsed_data = json.loads(json_data)
                    
                    if isinstance(parsed_data, list):
                        # Прямой список документов
                        documents_list = parsed_data
                        if verbose_mode:
                            print_status("OK", f"Успешно распарсено документов", str(len(documents_list)))
                            
                            # Выводим информацию о первом документе для отладки
                            if documents_list and len(documents_list) > 0:
                                first_doc = documents_list[0]
                                print(f"  Первый документ: {first_doc.get('ID', 'N/A')} - {first_doc.get('Name', 'N/A')}")
                    
                    elif isinstance(parsed_data, dict):
                        # Если вернулся словарь, проверяем есть ли в нем поле items или documents
                        if 'items' in parsed_data and isinstance(parsed_data['items'], list):
                            documents_list = parsed_data['items']
                            if verbose_mode:
                                print_status("OK", f"Успешно распарсено документов из поля 'items'", str(len(documents_list)))
                        elif 'documents' in parsed_data and isinstance(parsed_data['documents'], list):
                            documents_list = parsed_data['documents']
                            if verbose_mode:
                                print_status("OK", f"Успешно распарсено документов из поля 'documents'", str(len(documents_list)))
                        else:
                            # Если это одиночный документ, добавляем в список
                            documents_list = [parsed_data]
                            if verbose_mode:
                                print_status("OK", f"Получен одиночный документ")
                    else:
                        if verbose_mode:
                            print_status("ERROR", f"Неверный формат данных от процедуры", type(parsed_data).__name__)
                        
                except json.JSONDecodeError as e:
                    if verbose_mode:
                        print_status("ERROR", f"Ошибка парсинга JSON из процедуры", str(e))
                        print(f"  JSON данные (первые 500 символов): {str(json_data)[:500]}...")
                except Exception as e:
                    if verbose_mode:
                        print_status("ERROR", f"Ошибка при обработке JSON данных", str(e))
            else:
                if verbose_mode:
                    print_status("INFO", f"Процедура не вернула JSON данные или вернула ошибку")
        else:
            if verbose_mode:
                print_status("INFO", f"Процедура не вернула результаты")
        
        # Преобразуем структуру данных в требуемый формат
        formatted_documents = []
        for doc in documents_list:
            formatted_doc = doc.copy()  # или dict(doc)
            formatted_documents.append(formatted_doc)
        
        if verbose_mode:
            if not formatted_documents:
                print_status("INFO", f"Процедура не вернула данные документов или список пуст")
            else:
                print_status("OK", f"Успешно получено документов", str(len(formatted_documents)))
        
        return formatted_documents
        
    except pyodbc.OperationalError as e:
        if "timeout" in str(e).lower():
            print_status("ERROR", f"Таймаут выполнения хранимой процедуры DOC_Select_ID", 
                        f"user_id: {user_id}")
            # Откатываем транзакцию при таймауте
            try:
                db_connection.rollback()
            except:
                pass
            raise Exception(f"Таймаут выполнения операции получения списка документов: {str(e)}")
        else:
            print_status("ERROR", f"Операционная ошибка при получении списка документов {user_id}", str(e))
            db_connection.rollback()
            raise
            
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка базы данных при получении списка документов {user_id}", str(e))
        db_connection.rollback()
        raise
        
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при получении списка документов {user_id}", str(e))
        try:
            db_connection.rollback()
        except:
            pass
        raise

async def db_userid(user_id: str) -> bool:
    """
    Название: db_userid
    Назначение: Проверка существования пользователя по ID в базе данных
    Описание: Выполняет запрос к таблице USR для проверки наличия пользователя с указанным ID
    Принцип работы: Выполняет SQL запрос COUNT(*) и возвращает True если пользователь существует
    Входящие параметры: user_id - идентификатор пользователя для проверки
    Исходящие параметры: bool - True если пользователь существует, False если не существует
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    try:
        query = "SELECT COUNT(*) FROM [DLK].[dbo].[USR] WHERE [USR_Id] = ?"
        # Преобразуем user_id в bigint как ожидает процедура
        user_id_int = int(user_id)
        
        if verbose_mode:
            print_status("INFO", f"Проверка существования пользователя", f"user_id: {user_id}")
        
        cursor = db_connection.cursor()
        cursor.execute(query, (user_id_int,))
        
        result = cursor.fetchone()
        count = result[0] if result else 0
        
        if verbose_mode:
            print_status("OK", f"Результат проверки пользователя {user_id}", f"найдено записей: {count}")
        
        # Возвращаем True если количество найденных записей > 0
        return count > 0
        
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка базы данных при проверке пользователя {user_id}", str(e))
        raise
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при проверке пользователя {user_id}", str(e))
        raise

async def db_useremailing(user_id: int, consent_to_mailing: bool) -> bool:
    """
    Название: db_useremailing
    Назначение: Обновление согласия на email рассылку пользователя через хранимую процедуру
    Описание: Вызывает хранимую процедуру USR_Update_consent_to_mailing для обновления настроек рассылки
    Принцип работы: Вызывает хранимую процедуру с параметрами user_id и consent_to_mailing, проверяет результат
    Входящие параметры:
        user_id - идентификатор пользователя
        consent_to_mailing - согласие на рассылку (True - получено, False - отказано)
    Исходящие параметры: bool - True если операция успешна, False если USR_ID = -1
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    try:
        query = "EXECUTE [dbo].[USR_Update_consent_to_mailing] @USR_ID = ?, @USR_consent_to_mailing = ?"
        
        if verbose_mode:
            consent_text = "согласие получено" if consent_to_mailing else "отказ от рассылки"
            print_status("INFO", f"Вызов хранимой процедуры USR_Update_consent_to_mailing", 
                        f"user_id: {user_id}, consent: {consent_text}")
        
        cursor = db_connection.cursor()
        
        # Устанавливаем таймаут выполнения (30 секунд)
        cursor.execute("SET LOCK_TIMEOUT 30000")
        
        # Выполняем хранимую процедуру с параметрами
        cursor.execute(query, (user_id, 1 if consent_to_mailing else 0))
        
        # Получаем результат
        result_id = cursor.fetchval()
        
        # Фиксируем изменения
        db_connection.commit()
        
        # Закрываем курсор для освобождения ресурсов
        cursor.close()
        
        if verbose_mode:
            print_status("OK", f"Хранимая процедура USR_Update_consent_to_mailing выполнена успешно")
            print(f"  Получен ID: {result_id}")
        
        # Обрабатываем результат процедуры
        if result_id is not None:
            try:
                result_id_int = int(result_id)
                
                if result_id_int == '-1':
                    if verbose_mode:
                        print_status("ERROR", f"Ошибка в хранимой процедуре (ID = -1)")
                    return False
                else:
                    if verbose_mode:
                        print_status("OK", f"Согласие на рассылку успешно обновлено", f"ID: {result_id_int}")
                    return True
                    
            except (ValueError, TypeError) as e:
                if verbose_mode:
                    print_status("ERROR", f"Ошибка преобразования результата", str(e))
                return False
        else:
            if verbose_mode:
                print_status("ERROR", f"Процедура не вернула результат")
            return False
        
    except pyodbc.OperationalError as e:
        if "timeout" in str(e).lower():
            print_status("ERROR", f"Таймаут выполнения хранимой процедуры USR_Update_consent_to_mailing", 
                        f"user_id: {user_id}")
            try:
                db_connection.rollback()
            except:
                pass
            raise Exception(f"Таймаут выполнения операции обновления согласия на рассылку: {str(e)}")
        else:
            print_status("ERROR", f"Операционная ошибка при обновлении согласия на рассылку", str(e))
            db_connection.rollback()
            raise
            
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка базы данных при обновлении согласия на рассылку", str(e))
        db_connection.rollback()
        raise
        
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при обновлении согласия на рассылку", str(e))
        try:
            db_connection.rollback()
        except:
            pass
        raise

async def db_useraccess(user_id: int, period_minutes: int) -> int:
    """
    Название: db_useraccess
    Назначение: Проверка количества неудачных попыток входа пользователя через хранимую процедуру USR_Access_Select
    Описание: Вызывает хранимую процедуру для получения количества неудачных попыток входа за указанный период
    Принцип работы: Выполняет хранимую процедуру с параметрами user_id и period_minutes, обрабатывает результат
    Входящие параметры:
        user_id - идентификатор пользователя
        period_minutes - период проверки в минутах
    Исходящие параметры: int - количество неудачных попыток или -1 при ошибке
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    try:
        if verbose_mode:
            print_status("INFO", f"Вызов хранимой процедуры USR_Access_Select", 
                        f"user_id: {user_id}, period_minutes: {period_minutes}")
        
        query = "EXECUTE [dbo].[USR_Access_Select] @USR_ID = ?, @min = ?"
        
        cursor = db_connection.cursor()
        
        # Устанавливаем таймаут выполнения (30 секунд)
        cursor.execute("SET LOCK_TIMEOUT 30000")
        
        # Выполняем хранимую процедуру с параметрами
        cursor.execute(query, (user_id, period_minutes))
        
        # Получаем результат
        result = cursor.fetchval()
        
        # Фиксируем изменения
        db_connection.commit()
        
        # Закрываем курсор для освобождения ресурсов
        cursor.close()
        
        if verbose_mode:
            print_status("OK", f"Хранимая процедура USR_Access_Select выполнена успешно")
            print(f"  Получен результат: {result} (тип: {type(result)})")
        
        # Обрабатываем результат процедуры
        if result is not None:
            try:
                # Преобразуем результат в строку для обработки текстового "-1"
                result_str = str(result).strip()
                
                if result_str == '-1':
                    if verbose_mode:
                        print_status("ERROR", f"Ошибка в хранимой процедуре (возвращен -1)")
                    return -1
                else:
                    # Пытаемся преобразовать в число
                    failed_attempts = int(result_str)
                    if verbose_mode:
                        print_status("OK", f"Количество неудачных попыток", f"{failed_attempts}")
                    return failed_attempts
                    
            except (ValueError, TypeError) as e:
                if verbose_mode:
                    print_status("ERROR", f"Ошибка преобразования результата '{result}'", str(e))
                return -1
        else:
            if verbose_mode:
                print_status("ERROR", f"Процедура не вернула результат")
            return -1
        
    except pyodbc.OperationalError as e:
        if "timeout" in str(e).lower():
            print_status("ERROR", f"Таймаут выполнения хранимой процедуры USR_Access_Select", 
                        f"user_id: {user_id}, period_minutes: {period_minutes}")
            try:
                db_connection.rollback()
            except:
                pass
            raise Exception(f"Таймаут выполнения операции проверки доступа: {str(e)}")
        else:
            print_status("ERROR", f"Операционная ошибка при проверке доступа", str(e))
            db_connection.rollback()
            raise
            
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка базы данных при проверке доступа", str(e))
        db_connection.rollback()
        raise
        
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при проверке доступа", str(e))
        try:
            db_connection.rollback()
        except:
            pass
        raise

# --- РАБОТА С БАЗОЙ ДАННЫХ ДЛЯ РАСЧЕТА РАСПРЕДЕЛЕНИЯ ПЛАТЕЖА ---

async def db_calculate_payment_distribution(json_str: str) -> Optional[str]:
    """
    Название: db_calculate_payment_distribution
    Назначение: Расчет распределения платежа по залоговым билетам через хранимую процедуру
    Описание: Принимает JSON строку, передает ее в хранимую процедуру usp_CalculatePaymentDistribution
              Если результат -1, возвращает ошибку, иначе возвращает результат как есть
    Принцип работы: Передает JSON строку в хранимую процедуру без изменений, 
                    получает результат и проверяет его на ошибки
    Входящие параметры:
        json_str - JSON строка с данными для расчета
    Исходящие параметры: str или None - JSON строка результата расчета или None при ошибке
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    try:
        if verbose_mode:
            print_status("INFO", f"Вызов хранимой процедуры usp_CalculatePaymentDistribution", 
                        f"JSON строка длиной: {len(json_str)} символов")
            print(f"  Данные: {json_str[:200]}..." if len(json_str) > 200 else f"  Данные: {json_str}")
        
        # Теперь процедура принимает только один параметр - JSON строку
        query = "EXECUTE [dbo].[usp_CalculatePaymentDistribution] @Json = ?"
        
        cursor = db_connection.cursor()
        
        # Устанавливаем таймаут выполнения (30 секунд)
        cursor.execute("SET LOCK_TIMEOUT 30000")
        
        # Выполняем хранимую процедуру с JSON строкой
        cursor.execute(query, (json_str,))
        
        # Получаем результат (процедура возвращает JSON строку или -1)
        result = cursor.fetchval()
        
        # Фиксируем изменения
        db_connection.commit()
        
        # Закрываем курсор для освобождения ресурсов
        cursor.close()
        
        if verbose_mode:
            print_status("OK", f"Хранимая процедура usp_CalculatePaymentDistribution выполнена успешно")
            if result:
                result_type = type(result).__name__
                print(f"  Получен результат типа: {result_type}")
                print(f"  Значение: {result}")
        
        # Обрабатываем результат процедуры
        if result is not None:
            # Проверяем, не вернула ли процедура ошибку (-1)
            if str(result) == '-1':
                if verbose_mode:
                    print_status("ERROR", f"Процедура вернула ошибку (ID = -1)")
                raise Exception("Процедура вернула ошибку (-1)")
            
            # Проверяем, что результат - это строка
            if isinstance(result, str) and result != '-1':
                if verbose_mode:
                    print_status("OK", f"Успешно получен результат расчета распределения платежа")
                    print(f"  Длина JSON строки: {len(result)} символов")
                
                # Возвращаем JSON строку как есть
                return result
            else:
                if verbose_mode:
                    print_status("WARNING", f"Процедура вернула некорректный результат", 
                               f"тип результата: {type(result)}, значение: {result}")
                raise Exception("Процедура вернула некорректный результат")
        else:
            if verbose_mode:
                print_status("ERROR", f"Процедура не вернула результат")
            raise Exception("Процедура не вернула результат")
        
    except pyodbc.OperationalError as e:
        if "timeout" in str(e).lower():
            print_status("ERROR", f"Таймаут выполнения хранимой процедуры usp_CalculatePaymentDistribution", 
                        f"JSON: {json_str[:100]}...")
            try:
                db_connection.rollback()
            except:
                pass
            raise Exception(f"Таймаут выполнения операции расчета распределения платежа: {str(e)}")
        else:
            print_status("ERROR", f"Операционная ошибка при расчете распределения платежа", str(e))
            db_connection.rollback()
            raise
            
    except pyodbc.Error as e:
        print_status("ERROR", f"Ошибка базы данных при расчете распределения платежа", str(e))
        db_connection.rollback()
        raise
        
    except Exception as e:
        print_status("ERROR", f"Неожиданная ошибка при расчете распределения платежа", str(e))
        try:
            db_connection.rollback()
        except:
            pass
        raise


# --- ЛОГИРОВАНИЕ ---

def should_log_to_db(level: str) -> bool:
    """
    Проверяет, нужно ли логировать указанный уровень в БД
    """
    if not config or not hasattr(config, 'log_to_db'):
        return False
    if not isinstance(config.log_to_db, list):
        return False
    return level.upper() in [l.upper() for l in config.log_to_db]

def should_log_to_file(level: str) -> bool:
    """
    Проверяет, нужно ли логировать указанный уровень в файл
    """
    if not config or not hasattr(config, 'log_to_file'):
        return False
    if not isinstance(config.log_to_file, list):
        return False
    return level.upper() in [l.upper() for l in config.log_to_file]

def init_file_logging():
    """
    Название: init_file_logging
    Назначение: Инициализация системы логирования в файл с датой в имени
    Описание: Настраивает файловый логгер с поддержкой относительных/абсолютных путей и датой в имени файла
    Принцип работы: Создает логгер с файловым обработчиком, формирует путь к файлу с текущей датой
    Входящие параметры: Отсутствуют (использует глобальную конфигурацию)
    Исходящие параметры: logging.Logger или None - инициализированный логгер или None при ошибке
    """
    global file_logger
    
    # Если логирование в файл отключено (пустой список уровней)
    if not config.is_log_to_file_enabled():
        if verbose_mode:
            print_status("INFO", f"Логирование в файл отключено (нет разрешенных уровней)")
        return None
    
    try:
        # Получаем путь к файлу из конфигурации
        log_file_path = config.log_file_path
        
        # Если путь не указан, используем текущую папку
        if not log_file_path:
            log_file_path = "server.log"
        
        # Обрабатываем относительные и абсолютные пути
        if not os.path.isabs(log_file_path):
            # Если путь относительный, делаем его абсолютным относительно текущей директории
            log_file_path = os.path.join(os.getcwd(), log_file_path)
        
        # Создаем директорию для логов, если она не существует
        log_dir = os.path.dirname(log_file_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Добавляем дату к имени файла (перед расширением) в формате YYYY-MM-DD
        base_name, ext = os.path.splitext(log_file_path)
        current_date = datetime.now().strftime("%Y-%m-%d")
        dated_log_file_path = f"{base_name}_{current_date}{ext}"
        
        # Создаем логгер для файла
        file_logger = logging.getLogger('file_logger')
        
        # Устанавливаем самый низкий уровень, фильтрация будет на уровне обработчика
        file_logger.setLevel(logging.DEBUG)
        
        # Убираем обработчики по умолчанию
        file_logger.handlers = []
        
        # Создаем обработчик для файла
        file_handler = logging.FileHandler(dated_log_file_path, encoding='utf-8')
        
        # Устанавливаем уровень DEBUG для обработчика, фильтрация через конфигурацию
        file_handler.setLevel(logging.DEBUG)
        
        # Форматтер для файлового логгера
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        file_logger.addHandler(file_handler)
        file_logger.propagate = False  # Предотвращаем дублирование логов
        
        if verbose_mode:
            print_status("OK", f"Файловое логирование инициализировано", dated_log_file_path)
            print(f"  Уровни логирования: {', '.join(config.log_to_file)}")
        
        return file_logger
        
    except Exception as e:
        print_status("ERROR", f"Ошибка инициализации файлового логирования", str(e))
        return None
    

async def log_to_file_async(log_data: Dict[str, Any]):
    """
    Исправленная версия асинхронного логирования в файл
    """
    if not file_logger:
        return
    
    try:
        # Получаем реальный статус ответа из log_data
        response_code = log_data.get('response_code', 200)
        has_error = log_data.get('error') is not None
        
        # Определяем уровень логирования на основе кода ответа и наличия ошибки
        if response_code >= 400 or has_error:
            log_level = 'ERROR'
        else:
            log_level = 'INFO'
        
        # Проверяем, нужно ли логировать этот уровень в файл
        if not should_log_to_file(log_level):
            return
        
        # Проверяем, не сменилась ли дата (нужно ли создать новый файл)
        current_date = datetime.now().strftime("%Y-%m-%d")
        log_file_path = config.log_file_path
        
        # Обрабатываем путь так же как в init_file_logging
        if not log_file_path:
            log_file_path = "server.log"
        
        if not os.path.isabs(log_file_path):
            log_file_path = os.path.join(os.getcwd(), log_file_path)
        
        base_name, ext = os.path.splitext(log_file_path)
        dated_log_file_path = f"{base_name}_{current_date}{ext}"
        
        # Получаем текущий файл из обработчика
        current_handler = file_logger.handlers[0] if file_logger.handlers else None
        if current_handler and hasattr(current_handler, 'baseFilename'):
            current_log_file = current_handler.baseFilename
            
            # Если дата сменилась, переключаем файл (проверяем формат YYYY-MM-DD)
            if not current_log_file.endswith(f"_{current_date}{ext}"):
                if verbose_mode:
                    print_status("INFO", f"Смена даты, создаем новый файл лога", dated_log_file_path)
                
                # Создаем новый обработчик с актуальной датой
                new_handler = logging.FileHandler(dated_log_file_path, encoding='utf-8')
                new_handler.setLevel(logging.DEBUG)
                
                # Форматтер для файлового логгера
                formatter = logging.Formatter(
                    '%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                new_handler.setFormatter(formatter)
                
                # Заменяем старый обработчик на новый
                file_logger.removeHandler(current_handler)
                file_logger.addHandler(new_handler)
        
        # Формируем сообщение для лога с привязкой запроса к ответу
        message = (f"Запрос-ID: {log_data.get('request_id')} | "
                  f"Метод: {log_data.get('method')} | "
                  f"Эндпоинт: {log_data.get('endpoint')} | "
                  f"Статус: {response_code} | "
                  f"Время: {log_data.get('processing_time')}мс | "
                  f"Клиент: {log_data.get('client_ip')}")
        
        if log_data.get('error'):
            message += f" | Ошибка: {log_data.get('error')}"
        
        # Логируем в зависимости от уровня
        if log_level == 'ERROR':
            file_logger.error(message)
        else:
            file_logger.info(message)
            
    except Exception as e:
        print_status("ERROR", f"Ошибка файлового логирования", str(e))


async def log_to_file(message_type: str, message_text: str):
    """
    Название: log_to_file
    Назначение: Универсальная функция логирования в файл с временным штампом
    Описание: Записывает сообщение в файл лога с автоматическим добавлением временного штампа и типом сообщения
    Принцип работы: Форматирует сообщение с временным штампом и записывает в файл через файловый логгер
    Входящие параметры:
        message_type - тип сообщения (INFO, ERROR, WARNING, DEBUG)
        message_text - текст сообщения для логирования
    Исходящие параметры: Отсутствуют (побочный эффект - запись в файл)
    """
    # Проверяем, нужно ли логировать этот уровень в файл
    if not should_log_to_file(message_type):
        return
    
    if not file_logger:
        return
    
    try:
        # Форматируем сообщение с временным штампом
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] [{message_type}] {message_text}"
        
        # Логируем в зависимости от типа сообщения
        if message_type.upper() == 'ERROR':
            file_logger.error(formatted_message)
        elif message_type.upper() == 'WARNING':
            file_logger.warning(formatted_message)
        elif message_type.upper() == 'DEBUG':
            file_logger.debug(formatted_message)
        else:
            file_logger.info(formatted_message)
            
    except Exception as e:
        print_status("ERROR", f"Ошибка записи в файл лога", str(e))


async def log_to_database(log_data: Dict[str, Any]):
    """
    Исправленная версия функции логирования в БД
    """
    # Проверяем, нужно ли логировать этот тип сообщения в БД
    response_code = log_data.get('response_code', 500)
    log_level = 'ERROR' if response_code >= 400 else 'INFO'
    
    if not should_log_to_db(log_level):
        return
    
    if not db_connection:
        return
    
    try:
        # Безопасное извлечение user_id
        user_id = log_data.get('user_id')
        
        # Для неаутентифицированных запросов используем NULL
        if user_id in ['health_check', 'anonymous', 'unknown', None]:
            user_id = None
        
        # Преобразуем user_id в число если это возможно
        if user_id and isinstance(user_id, str) and user_id.isdigit():
            user_id = int(user_id)
        elif user_id and not isinstance(user_id, int):
            # Если user_id не число, используем NULL
            user_id = None

        request_id = log_data.get('request_id', 'unknown')
        endpoint = log_data.get('endpoint', 'unknown')
        params = str(log_data.get('params', ''))[:1000]  # Ограничиваем длину
        processing_time = log_data.get('processing_time', 0)
        response_code = log_data.get('response_code', 500)
        message = (log_data.get('message', '') or 'Успешный запрос')[:4000]  # Ограничиваем длину
        
        query = """
        INSERT INTO Logs (
            usr_id, Logs_request_id, Logs_endpoint, Logs_params,
            Logs_processing_time_ms, Logs_response_code, Logs_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        
        await execute_query(query, {
            "user_id": user_id,
            "request_id": request_id,
            "endpoint": endpoint,
            "params": params,
            "processing_time": processing_time,
            "response_code": response_code,
            "message": message
        })
        
    except Exception as e:
        print_status("ERROR", f"Ошибка логирования в БД", str(e))

async def log_request(request: web.Request, response: web.Response = None, 
                     processing_time: int = 0, error: str = None):
    """
    Название: log_request
    Назначение: Основная функция логирования HTTP запросов
    Описание: Координирует процесс логирования в различные системы (консоль, файл, БД)
    Принцип работы: Собирает данные о запросе и запускает асинхронные задачи для каждого типа логирования
    Входящие параметры:
        request - объект HTTP запроса
        response - объект HTTP ответа (опционально)
        processing_time - время обработки запроса в миллисекундах
        error - текст ошибки (опционально)
    Исходящие параметры: Отсутствуют (побочный эффект - логирование в multiple системы)
    """
    request_id = getattr(request, 'request_id', 'неизвестно')
    
    # Подготовка данных для логирования
    log_data = {
        "request_id": request_id,
        "endpoint": request.path,
        "params": str(dict(request.query)),
        "processing_time": processing_time,
        "response_code": getattr(response, 'status', 500) if response else 500,
        "error": error,
        "method": request.method,
        "client_ip": request.remote
    }
    
    # Логирование в консоль ТОЛЬКО в verbose режиме
    if verbose_mode:
        log_message = f"{request.method} {request.path} - {response.status if response else 'ОШИБКА'}"
        if error:
            log_message += f" - ОШИБКА: {error[:100]}..."
        print(log_message)
    
    # Асинхронное логирование в файл с использованием новой функции
    asyncio.create_task(log_to_file_async(log_data))
    
    # Дополнительное логирование через универсальную функцию
    if config.is_log_to_file_enabled():  # Проверяем, что логирование в файл вообще включено
        log_level = 'ERROR' if error else 'INFO'
        log_message = f"Запрос {request.method} {request.path} - Статус: {response.status if response else 'ERROR'} - Время: {processing_time}мс"
        if error:
            log_message += f" - Ошибка: {error}"
        asyncio.create_task(log_to_file(log_level, log_message))
    
    # Логирование в БД (не блокирует основной поток)
    if response and config.is_log_to_db_enabled():  # Проверяем, что логирование в БД вообще включено
        asyncio.create_task(log_to_database({
            "request_id": request_id,
            "endpoint": request.path,
            "params": str(dict(request.query)),
            "processing_time": processing_time,
            "response_code": response.status,
            "message": error
        }))


async def log_request_async(request: web.Request, response: web.Response, 
                           processing_time: int, error: str, request_id: str):
    """
    Исправленная версия функции логирования
    """
    try:
        # Получаем корректный статус ответа
        response_status = getattr(response, 'status', 200) if response else 200
        
        # Подготовка данных для логирования
        log_data = {
            "request_id": request_id,
            "endpoint": request.path,
            "params": str(dict(request.query)),
            "processing_time": processing_time,
            "response_code": response_status,
            "error": error,
            "method": request.method,
            "client_ip": request.remote
        }
        
        # Логирование в консоль ТОЛЬКО в verbose режиме
        if verbose_mode:
            log_message = f"{request.method} {request.path} - {response_status}"
            if error:
                log_message += f" - ОШИБКА: {error[:100]}..."
            print(log_message)
        
        # Асинхронное логирование в файл
        asyncio.create_task(log_to_file_async(log_data))
        
        # Логирование в БД только если есть подключение и включено логирование в БД
        if response and config and config.is_log_to_db_enabled() and db_connection:
            log_level = 'ERROR' if error or response_status >= 400 else 'INFO'
            # Проверяем, нужно ли логировать этот уровень в БД
            if should_log_to_db(log_level):
                # Получаем user_id безопасно
                user_id = getattr(request, 'authenticated_token', None)
                if user_id in ['health_check', 'anonymous', 'unknown', None]:
                    user_id = None
                    
                asyncio.create_task(log_to_database({
                    "user_id": user_id,
                    "request_id": request_id,
                    "endpoint": request.path,
                    "params": str(dict(request.query)),
                    "processing_time": processing_time,
                    "response_code": response_status,
                    "message": error or "Успешный запрос"
                }))
            
    except Exception as e:
        # Логируем ошибку логирования через новую функцию
        if config and config.is_log_to_file_enabled() and should_log_to_file('ERROR'):
            asyncio.create_task(log_to_file('ERROR', f"Ошибка при логировании запроса: {str(e)}"))
        # Выводим ошибку логирования в консоль ТОЛЬКО в verbose режиме
        if verbose_mode:
            print_status("ERROR", f"Ошибка при логировании", str(e))
    finally:
        # Удаляем запрос из хранилища
        await remove_request(request_id)
        

# --- VERBOSE РЕЖИМ И ОТЛАДКА ---

async def print_verbose_request(request: web.Request):
    """
    Название: print_verbose_request
    Назначение: Детальный вывод информации о входящем HTTP запросе с временным штампом
    Описание: Отображает полную информацию о запросе в verbose режиме для отладки, включая временную метку возникновения запроса
    Принцип работы: Извлекает и форматирует информацию из объекта запроса: временной штамп, URL, заголовки, параметры, тело
    Входящие параметры: request - объект HTTP запроса aiohttp.web.Request
    Исходящие параметры: Отсутствуют (побочный эффект - вывод в консоль)
    """
    if not verbose_mode:
        return
    
    print_separator()
    print("ВХОДЯЩИЙ HTTP ЗАПРОС")
    print("-" * 40)
    
    # Временной штамп запроса
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"Временной штамп: {current_time}")
    
    # Полный URL запроса (безопасное получение)
    try:
        scheme = request.scheme
        host = request.host
        path = request.path
        query_string = f"?{request.query_string}" if request.query_string else ""
        full_url = f"{scheme}://{host}{path}{query_string}"
        print(f"URL: {full_url}")
    except Exception as e:
        print(f"URL: Не удалось получить URL: {e}")
        print(f"Метод: {request.method}")
        print(f"Путь: {request.path}")
    
    # Заголовки запроса
    print("\nЗаголовки запроса:")
    for name, value in request.headers.items():
        print(f"  {name}: {value}")
    
    # Query параметры
    if request.query_string:
        print(f"\nQuery параметры: {request.query_string}")
    
    # Тело запроса (если есть) - читаем асинхронно и не блокируем
    if request.can_read_body:
        print("\nТело запроса (первые 1000 символов):")
        try:
            # Безопасное чтение тела запроса
            body = await request.read()
            if body:
                body_str = body.decode('utf-8', errors='replace')[:1000]
                # Декодируем Unicode escape последовательности для читаемости
                try:
                    decoded_body = body_str.encode('utf-8').decode('unicode-escape')
                    print(decoded_body)
                except:
                    print(body_str)
                # Восстанавливаем тело запроса для дальнейшей обработки
                request._body = body
                request._cache = {}
        except Exception as e:
            print(f"[Ошибка чтения тела запроса: {e}]")
    
    # Сразу выводим разделитель для завершения вывода
    print_separator()


def print_verbose_response(response: web.Response):
    """
    Название: print_verbose_response
    Назначение: Детальный вывод информации об исходящем HTTP ответе с временным штампом
    Описание: Отображает полную информацию об ответе сервера в verbose режиме для отладки, включая временную метку формирования ответа
    Принцип работы: Извлекает и форматирует информацию из объекта ответа: временной штамп, статус, заголовки, тело
    Входящие параметры: response - объект HTTP ответа aiohttp.web.Response
    Исходящие параметры: Отсутствуют (побочный эффект - вывод в консоль)
    """
    if not verbose_mode:
        return
    
    print("\nИСХОДЯЩИЙ HTTP ОТВЕТ")
    print("-" * 40)
    
    # Временной штамп ответа
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"Временной штамп: {current_time}")
    
    # Статус ответа
    print(f"Статус: {response.status} {response.reason}")
    
    # Заголовки ответа
    print("\nЗаголовки ответа:")
    for name, value in response.headers.items():
        print(f"  {name}: {value}")
    
    # Тело ответа (если есть)
    if hasattr(response, '_body') and response._body:
        print("\nТело ответа:")
        try:
            body_str = response._body.decode('utf-8', errors='replace')[:1000]
            # Декодируем Unicode escape последовательности для читаемости
            try:
                decoded_body = body_str.encode('utf-8').decode('unicode-escape')
                print(decoded_body)
            except:
                print(body_str)
        except Exception as e:
            print(f"[Ошибка чтения тела ответа: {e}]")
    
    print_separator()


# --- ХРАНИЛИЩЕ ЗАПРОСОВ ---

async def store_request(request: web.Request) -> str:
    """
    Название: store_request
    Назначение: Сохранение информации о запросе во временном хранилище
    Описание: Сохраняет запрос в памяти для последующего отслеживания и логирования
    Принцип работы: Генерирует уникальный ID, сохраняет запрос в словарь и выполняет очистку старых запросов
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: str - уникальный идентификатор сохраненного запроса
    """
    request_id = generate_request_id()
    request.request_id = request_id
    
    async with request_lock:
        request_store[request_id] = {
            'request': request,
            'timestamp': time.time(),
            'method': request.method,
            'path': request.path,
            'client_ip': request.remote
        }
    
    # Очистка старых запросов (больше 5 минут)
    cleanup_time = time.time() - 300
    async with request_lock:
        for rid in list(request_store.keys()):
            if request_store[rid]['timestamp'] < cleanup_time:
                del request_store[rid]
    
    return request_id

async def get_request(request_id: str) -> Optional[Dict[str, Any]]:
    """
    Название: get_request
    Назначение: Получение информации о запросе из временного хранилища
    Описание: Извлекает сохраненный запрос по его уникальному идентификатору
    Принцип работы: Выполняет поиск в словаре request_store по ключу request_id
    Входящие параметры: request_id - уникальный идентификатор запроса
    Исходящие параметры: Dict[str, Any] или None - данные запроса или None если не найден
    """
    async with request_lock:
        return request_store.get(request_id)

async def remove_request(request_id: str):
    """
    Название: remove_request
    Назначение: Удаление запроса из временного хранилища
    Описание: Освобождает память путем удаления обработанного запроса
    Принцип работы: Удаляет запись из словаря request_store по ключу request_id
    Входящие параметры: request_id - уникальный идентификатор запроса для удаления
    Исходящие параметры: Отсутствуют (побочный эффект - изменение глобального словаря)
    """
    async with request_lock:
        if request_id in request_store:
            del request_store[request_id]


# --- MIDDLEWARE ---

async def cors_middleware(app, handler):
    """
    Название: cors_middleware
    Назначение: Middleware для обработки CORS (Cross-Origin Resource Sharing)
    Описание: Добавляет CORS заголовки к ответам и обрабатывает preflight OPTIONS запросы
    Принцип работы: Перехватывает запросы, добавляет соответствующие CORS заголовки к ответам
    Входящие параметры:
        app - объект приложения aiohttp
        handler - следующий обработчик в цепочке middleware
    Исходящие параметры: Функция-обработчик middleware
    """
    async def middleware_handler(request: web.Request) -> web.Response:
        # Если CORS отключен, пропускаем обработку
        if not config.cors_enabled:
            return await handler(request)
        
        # Обработка preflight OPTIONS запросов
        if request.method == 'OPTIONS':
            response = web.Response()
        else:
            response = await handler(request)
        
        # Добавляем CORS заголовки
        origin = request.headers.get('Origin', '')
        
        # Проверяем разрешен ли origin
        if config.cors_allowed_origins == ['*'] or origin in config.cors_allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin if config.cors_allowed_origins != ['*'] else '*'
            
            if config.cors_expose_headers:
                response.headers['Access-Control-Expose-Headers'] = ', '.join(config.cors_expose_headers)
            
            if config.cors_allow_credentials:
                response.headers['Access-Control-Allow-Credentials'] = 'true'
        
        # Для OPTIONS запросов добавляем дополнительные заголовки
        if request.method == 'OPTIONS':
            response.headers['Access-Control-Allow-Methods'] = ', '.join(config.cors_allowed_methods)
            response.headers['Access-Control-Allow-Headers'] = ', '.join(config.cors_allowed_headers)
            response.headers['Access-Control-Max-Age'] = str(config.cors_max_age)
        
        return response
    
    return middleware_handler


async def auth_middleware(app, handler):
    """
    Название: auth_middleware
    Назначение: Middleware для аутентификации и сквозного логирования запросов с гарантированной серверной подписью и токеном
    Описание: Обрабатывает все входящие запросы: аутентификация, логирование, обработка ошибок и гарантированное добавление серверной подписи и токена ко всем ответам
    Принцип работы: Перехватывает запросы, выполняет аутентификацию, логирование, обработку исключений и добавляет серверную подпись и токен ко всем ответам независимо от статуса
    Входящие параметры:
        app - объект приложения aiohttp
        handler - следующий обработчик в цепочке middleware
    Исходящие параметры: Функция-обработчик middleware
    """
    async def middleware_handler(request: web.Request) -> web.Response:
        # Сохраняем запрос в памяти
        request_id = await store_request(request)
        start_time = time.time()
        response = None
        error = None
        authenticated_token = None

        # Учитываем запрос к серверу (кроме health-эндпоинтов)
        if not request.path.startswith('/health'):
            record_server_request()
        
        # Вывод подробной информации о запросе в verbose режиме
        await print_verbose_request(request)
        
        try:
            # Аутентификация для ВСЕХ запросов
            try:
                authenticated_token = await authenticate_request(request)
                # Сохраняем токен в объекте запроса для использования в обработчиках
                request.authenticated_token = authenticated_token
                if verbose_mode:
                    print_status("OK", f"Аутентификация успешна", f"токен {authenticated_token[:8]}...")
            except web.HTTPException as auth_error:
                # Сохраняем ошибку аутентификации, но продолжаем обработку
                error = auth_error.text
                response = auth_error
                if verbose_mode:
                    print_status("ERROR", f"Ошибка аутентификации", error)
                # Для ошибок аутентификации все равно нужно добавить подпись и токен
                # Извлекаем токен из заголовка Token для подписи
                auth_header = request.headers.get("Token", "")
                token_for_signature = None
                if auth_header.startswith("Bearer "):
                    token_for_signature = auth_header[7:]
                    if verbose_mode:
                        print_status("INFO", f"Используем токен из заголовка для подписи", f"{token_for_signature[:8]}...")
                await add_server_signature_to_response(response, token_for_signature)
                return response
            
            # Обрабатываем favicon.ico - возвращаем 404 с подписью и токеном
            if request.path == '/favicon.ico':
                response = web.HTTPNotFound(text=json.dumps({
                    "status": "error",
                    "message": "Эндпоинт не найден"
                }), content_type='application/json')
                await add_server_signature_to_response(response, authenticated_token)
                return response
            else:
                response = await handler(request)
                # Добавляем подпись и токен к успешным ответам
                await add_server_signature_to_response(response, authenticated_token)
                return response
            
        except web.HTTPException as he:
            response = he
            error = he.text
            if verbose_mode:
                print_status("ERROR", f"HTTP исключение",
                            data_lines=[
                                f"Статус: {he.status}",
                                f"Текст: {error}"
                            ])
            # Добавляем подпись и токен к HTTP исключениям
            token_for_signature = getattr(request, 'authenticated_token', None)
            await add_server_signature_to_response(response, token_for_signature)
            raise
        except Exception as e:
            error = str(e)
            if verbose_mode:
                print_status("ERROR", f"Неожиданная ошибка", str(e))
                import traceback
                traceback.print_exc()
            response = web.HTTPBadRequest(text=json.dumps({
                "status": "error",
                "message": "Ошибка обработки запроса"
            }), content_type='application/json')
            # Добавляем подпись и токен к исключениям
            token_for_signature = getattr(request, 'authenticated_token', None)
            await add_server_signature_to_response(response, token_for_signature)
            raise response
        finally:
            # Вывод подробной информации об ответе в verbose режиме
            if response:
                print_verbose_response(response)
            
            processing_time = int((time.time() - start_time) * 1000)
            
            # Асинхронное логирование (не блокирует основной поток)
            asyncio.create_task(log_request_async(request, response, processing_time, error, request_id))
    
    return middleware_handler

async def debug_logging_system(request: web.Request, response: web.Response):
    """Временная функция для отладки системы логирования"""
    print("=== DEBUG LOGGING SYSTEM ===")
    print(f"Request: {request.method} {request.path}")
    print(f"Response status: {response.status}")
    print(f"Response reason: {response.reason}")
    print(f"Response type: {type(response)}")
    
    # Проверяем, является ли response исключением
    if isinstance(response, web.HTTPException):
        print(f"Это HTTP исключение: {response.status} {response.text}")
    
    # Проверяем заголовки ответа
    print("Response headers:")
    for name, value in response.headers.items():
        print(f"  {name}: {value}")
    
    print("=== END DEBUG ===")


# --- ОБРАБОТЧИКИ HTTP-ЗАПРОСОВ (ENDPOINTS) ---

async def health_check(request: web.Request) -> web.Response:
    """
    Название: health_check
    Назначение: Основной health check эндпоинт с общей информацией о состоянии сервера
    Описание: Возвращает обобщенную информацию о состоянии сервера, аналогичную выводу при запуске в консоли
    Принцип работы: Собирает базовую информацию о сервере, БД, безопасности и логировании, формирует JSON ответ
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: web.Response - JSON ответ с кодом статуса 200 и общей информацией о сервере
    """
    def format_uptime(seconds):
        """Форматирование времени работы от лет до секунд"""
        intervals = [
            ('год', 31536000),
            ('месяц', 2592000),
            ('день', 86400),
            ('час', 3600),
            ('минута', 60),
            ('секунда', 1)
        ]
        
        result = []
        seconds = int(seconds)
        
        for name, count in intervals:
            value = seconds // count
            if value:
                seconds -= value * count
                result.append(f"{value} {name}")
        
        return ', '.join(result) if result else "0 секунд"

    # Проверка состояния базы данных
    db_available = await health_check_db() if db_connection else False
    
    # Проверка безопасности
    security_issues = []
    if config.disable_certificates:
        security_issues.append("Отключены сертификаты")
    if config.disable_token_auth:
        security_issues.append("Отключена аутентификация по токену")
    if config.disable_signature:
        security_issues.append("Отключена проверка подписей")
    
    # Проверка логирования
    logging_issues = []
    if config.is_log_to_db_enabled() and not db_connection:
        logging_issues.append("Логирование в БД включено, но БД недоступна")
    if config.is_log_to_file_enabled() and not file_logger:
        logging_issues.append("Логирование в файл включено, но не инициализировано")
    
    # Общий статус здоровья системы
    overall_status = "healthy"
    if not db_available and not config.allow_start_without_db:
        overall_status = "unhealthy"
    elif not db_available or security_issues or logging_issues:
        overall_status = "warning"

    # Информация о перезагрузке конфигурации
    config_reload_info = {
        "enabled": config_reload_interval > 0,
        "interval_minutes": config_reload_interval,
        "interval_human": format_time_remaining(config_reload_interval),
        "last_reload_time": last_config_reload_time.isoformat() if last_config_reload_time else None,
        "next_reload_in": calculate_next_reload_info()
    }

    health_data = {
        "status": overall_status,
        "server": {
            "version": "1.0.0",
            "host": config.host,
            "port": config.port,
            "uptime": format_uptime(time.time() - start_time) if 'start_time' in globals() else "0 секунд",
            "verbose_mode": verbose_mode,
            "debug_mode": config.debug
        },
        "configuration_reload": config_reload_info,        
        "database": {
            "status": "connected" if db_connection else "disconnected",
            "server": config.db_server,
            "name": config.db_name,
            "select_top_limit": config.select_top,
            "available": db_available
        },
        "security": {
            "certificates": not config.disable_certificates,
            "token_auth": not config.disable_token_auth,
            "signature_verification": not config.disable_signature,
            "mode": "secure" if not (config.disable_certificates and config.disable_token_auth and config.disable_signature) else "unsecure",
            "issues": security_issues
        },
        "logging": {
            "file_logging": {
                "enabled": config.is_log_to_file_enabled(),
                "levels": config.log_to_file,
                "status": "active" if file_logger else "inactive"
            },
            "database_logging": {
                "enabled": config.is_log_to_db_enabled(),
                "levels": config.log_to_db,
                "status": "available" if db_connection else "unavailable"
            },
            "console_logging": {
                "enabled": verbose_mode,
                "description": "Только в verbose режиме"
            },
            "issues": logging_issues
        },
        "network": {
            "cors_enabled": config.cors_enabled,
            "allowed_origins": config.cors_allowed_origins
        },
        "issues": {
            "critical": not db_available and not config.allow_start_without_db,
            "warnings": len(security_issues) + len(logging_issues) + (0 if db_available else 1)
        },
        "endpoints": {
            "health": f"http://{config.host}:{config.port}/health",
            "help": f"http://{config.host}:{config.port}/help"
        },
        "timestamp": datetime.now().isoformat()
    }
    
    response = web.json_response(health_data, status=200)
    await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'health_check'))
    return response


def calculate_next_reload_info():
    """
    Название: calculate_next_reload_info
    Назначение: Расчет оставшегося времени до следующей перезагрузки конфигурации
    Описание: Вычисляет сколько времени осталось до следующей автоматической перезагрузки конфигурации
    Принцип работы: Использует последнее время перезагрузки и интервал для расчета оставшегося времени
    Входящие параметры: Отсутствуют
    Исходящие параметры: str - отформатированное оставшееся время или "не применяется"
    """
    global config_reload_interval, last_config_reload_time
    
    if config_reload_interval <= 0:
        return "не применяется"
    
    if last_config_reload_time is None:
        return "ожидание первой перезагрузки"
    
    # ЗАМЕНА: используем time вместо datetime для расчета
    current_time = time.time()
    last_reload_timestamp = last_config_reload_time.timestamp()
    next_reload_timestamp = last_reload_timestamp + (config_reload_interval * 60)
    time_remaining = next_reload_timestamp - current_time
    
    if time_remaining <= 0:
        return "в процессе перезагрузки"
    
    # Форматируем оставшееся время
    total_seconds = int(time_remaining)
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    
    parts = []
    if days > 0:
        parts.append(f"{days} {pluralize(days, 'день', 'дня', 'дней')}")
    if hours > 0:
        parts.append(f"{hours} {pluralize(hours, 'час', 'часа', 'часов')}")
    if minutes > 0:
        parts.append(f"{minutes} {pluralize(minutes, 'минуту', 'минуты', 'минут')}")
    
    return ", ".join(parts) if parts else "менее минуты"


async def health_security(request: web.Request) -> web.Response:
    """
    Название: health_security
    Назначение: Детальная информация о режиме безопасности сервера с анализом текущего запроса
    Описание: Возвращает подробную информацию о текущих настройках безопасности, анализирует заголовки запроса,
              расшифровывает подпись, проверяет временные метки и предоставляет диагностику ошибок безопасности
    Принцип работы: Собирает информацию о сертификатах, токенах, анализирует заголовки текущего запроса,
                   проверяет подпись и предоставляет рекомендации по исправлению
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: web.Response - JSON ответ с кодом статуса 200 и детальной информацией о безопасности
    """
    # Проверяем доступность ключей
    private_key_available = os.path.exists(config.server_private_key_path) if not config.disable_certificates else False
    public_key_available = os.path.exists(config.client_public_key_path) if not config.disable_certificates else False
    
    # Анализ текущих заголовков запроса
    current_headers = {}
    security_analysis = {
        "errors": [],
        "warnings": [],
        "recommendations": []
    }
    
    # Собираем все заголовки запроса
    for name, value in request.headers.items():
        current_headers[name] = value
    
    # Анализ заголовка Token
    token_header = request.headers.get("Token", "")
    token_analysis = {
        "header_present": bool(token_header),
        "format_correct": token_header.startswith("Bearer "),
        "token_value": token_header[7:] if token_header.startswith("Bearer ") else token_header,
        "token_valid": False
    }
    
    if token_header:
        if not token_header.startswith("Bearer "):
            security_analysis["errors"].append("Заголовок Token должен иметь формат: 'Bearer <токен>'")
        else:
            token = token_header[7:]
            if token in config.allowed_tokens:
                token_analysis["token_valid"] = True
            else:
                security_analysis["errors"].append(f"Токен '{token}' не найден в списке разрешенных токенов")
    else:
        security_analysis["warnings"].append("Отсутствует заголовок Token")
    
    # Анализ заголовка Signature
    signature_header = request.headers.get("Signature", "")
    signature_analysis = {
        "header_present": bool(signature_header),
        "signature_length": len(signature_header) if signature_header else 0,
        "decoded_data": None,
        "timestamp_valid": False,
        "signature_valid": False,
        "error_details": None
    }
    
    if signature_header:
        try:
            # Декодируем Base64 подпись
            signature_bytes = base64.b64decode(signature_header)
            signature_analysis["signature_length_bytes"] = len(signature_bytes)
            
            # Пытаемся расшифровать подпись и получить данные
            if token_analysis["token_value"] and public_key:
                current_time = int(time.time())
                max_offset = config.signature_ttl * 3
                
                # Проверяем подпись для временных меток в диапазоне
                for time_offset in range(0, max_offset, 10):
                    expiry_time = current_time + time_offset
                    data_to_verify = f"{token_analysis['token_value']}.{expiry_time}".encode('utf-8')
                    
                    try:
                        # Проверяем подпись с публичным ключом клиента
                        public_key.verify(
                            signature_bytes,
                            data_to_verify,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        
                        # Если подпись верна
                        signature_analysis["decoded_data"] = {
                            "token": token_analysis["token_value"],
                            "expiry_timestamp": expiry_time,
                            "expiry_time_human": datetime.fromtimestamp(expiry_time).strftime('%Y-%m-%d %H:%M:%S'),
                            "time_remaining": expiry_time - current_time,
                            "timestamp_valid": expiry_time >= current_time
                        }
                        signature_analysis["timestamp_valid"] = expiry_time >= current_time
                        signature_analysis["signature_valid"] = True
                        
                        if not signature_analysis["timestamp_valid"]:
                            security_analysis["errors"].append(f"Подпись просрочена. Время истечения: {signature_analysis['decoded_data']['expiry_time_human']}")
                        
                        break
                    except InvalidSignature:
                        continue
                    except Exception as e:
                        continue
                
                if not signature_analysis["signature_valid"]:
                    security_analysis["errors"].append("Не удалось верифицировать подпись. Возможные причины: неверный токен, истекшее время или несоответствие ключей")
            
        except Exception as e:
            signature_analysis["error_details"] = str(e)
            security_analysis["errors"].append(f"Ошибка декодирования подписи: {str(e)}")
    else:
        security_analysis["warnings"].append("Отсутствует заголовок Signature")
    
    # Формируем рекомендации
    if security_analysis["errors"]:
        security_analysis["recommendations"].append("Для успешной аутентификации необходимо:")
        if not token_header:
            security_analysis["recommendations"].append("- Добавить заголовок Token: Bearer <ваш_токен>")
        elif not token_header.startswith("Bearer "):
            security_analysis["recommendations"].append("- Исправить формат заголовка Token на: Bearer <ваш_токен>")
        elif not token_analysis["token_valid"]:
            security_analysis["recommendations"].append("- Использовать валидный токен из списка разрешенных")
        
        if not signature_header:
            security_analysis["recommendations"].append("- Добавить заголовок Signature с цифровой подписью")
        elif not signature_analysis["signature_valid"]:
            security_analysis["recommendations"].append("- Убедиться что подпись создана для правильного токена и временной метки")
            security_analysis["recommendations"].append("- Проверить что используется правильный приватный ключ для подписи")
    
    # Формируем полный ответ
    security_data = {
        "status": "healthy" if not security_analysis["errors"] else "security_issues",
        "request_analysis": {
            "headers_received": current_headers,
            "token_analysis": token_analysis,
            "signature_analysis": signature_analysis,
            "security_diagnostics": security_analysis
        },
        "certificates": {
            "enabled": not config.disable_certificates,
            "private_key": {
                "path": config.server_private_key_path,
                "role": "server_signing",
                "status": "available" if private_key_available else "unavailable",
                "loaded": private_key is not None
            },
            "public_key": {
                "path": config.client_public_key_path, 
                "role": "client_verification",
                "status": "available" if public_key_available else "unavailable",
                "loaded": public_key is not None
            }
        },
        "token_authentication": {
            "enabled": not config.disable_token_auth,
            "allowed_tokens_count": len(config.allowed_tokens),
            "static_tokens": len([t for t in config.allowed_tokens if len(t) == 36]),  # UUID формата
            "custom_tokens": len([t for t in config.allowed_tokens if len(t) != 36])
        },
        "signature_verification": {
            "enabled": not config.disable_signature,
            "signature_ttl_seconds": config.signature_ttl,
            "client_signature_required": True,
            "server_signature_enabled": True
        },
        "security_mode": "secure" if not (config.disable_certificates and config.disable_token_auth and config.disable_signature) else "unsecure",
        "statistics": {
            "active_requests": len(request_store),
            "recent_requests": sum(1 for req in request_store.values() if time.time() - req['timestamp'] < 300)
        },
        "timestamp": datetime.now().isoformat(),
        "server_time_unix": int(time.time()),
        "server_time_human": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    response = web.json_response(security_data)
    await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'health_security'))
    return response


from datetime import datetime, timedelta  # ДОБАВИТЬ timedelta

async def health_database(request: web.Request) -> web.Response:
    """
    Название: health_database
    Назначение: Детальная информация о подключении к базе данных
    Описание: Возвращает подробную информацию о текущем подключении к БД, настройках и статистике
    Принцип работы: Собирает информацию о подключении, настройках БД и проверяет доступность
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: web.Response - JSON ответ с кодом статуса 200 и детальной информацией о БД
    """
    try:
        # Проверка состояния базы данных
        db_available = False
        db_status = "disconnected"
        db_version = "unknown"
        
        if db_connection:
            try:
                db_available = await health_check_db()
                db_status = "connected" if db_available else "disconnected"
                
                # Получаем информацию о версии БД если доступно
                cursor = db_connection.cursor()
                cursor.execute("SELECT @@VERSION")
                version_result = cursor.fetchone()
                if version_result:
                    db_version = version_result[0][:100]  # Обрезаем длинную строку версии
            except Exception as e:
                db_status = f"error: {str(e)}"
                if verbose_mode:
                    print_status("ERROR", f"Ошибка при проверке БД", str(e))
        
        # Рассчитываем время до следующей проверки
        next_check_seconds = config.db_health_check_interval
        next_check_time = (datetime.now() + timedelta(seconds=next_check_seconds)).strftime('%H:%M:%S')
        
        database_data = {
            "status": db_status,
            "connection": {
                "server": config.db_server,
                "port": config.db_port,
                "database": config.db_name,
                "driver": config.db_driver,
                "connection_timeout": config.db_connection_timeout,
                "username": config.db_username,
                "password_set": bool(config.db_password)
            },
            "settings": {
                "allow_start_without_db": config.allow_start_without_db,
                "select_top_limit": config.select_top,
                "connection_pooling": {
                    "enabled": config.db_pooling_enabled,
                    "max_pool_size": config.db_max_pool_size,
                    "min_pool_size": config.db_min_pool_size,
                    "connection_lifetime_seconds": config.db_connection_lifetime
                },
                "health_check": {
                    "enabled": config.db_health_check_enabled,
                    "interval_seconds": config.db_health_check_interval,
                    "next_check_time": next_check_time
                }
            },
            "server_info": {
                "version": db_version,
                "health_check": db_available
            },
            "statistics": {
                "total_queries": statistics["db_queries"]["total_count"],
                "max_execution_time_ms": statistics["db_queries"]["max_execution_time"]
            },
            "timestamp": datetime.now().isoformat()
        }
        
        response = web.json_response(database_data)
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'health_database'))
        return response
        
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Критическая ошибка в health_database", str(e))
        
        # Возвращаем ошибку в стандартном формате
        error_data = {
            "status": "error",
            "message": f"Ошибка при получении информации о базе данных: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }
        response = web.json_response(error_data, status=500)
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'health_database'))
        return response

        
async def health_logging(request: web.Request) -> web.Response:
    """
    Название: health_logging
    Назначение: Детальная информация о режиме логирования
    Описание: Возвращает подробную информацию о текущих настройках логирования и verbose режиме
    Принцип работы: Собирает информацию о файловом, БД и консольном логировании, а также о verbose режиме
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: web.Response - JSON ответ с кодом статуса 200 и детальной информацией о логировании
    """
    # Получаем текущий путь к файлу лога
    current_log_file = "unknown"
    if file_logger and file_logger.handlers:
        current_handler = file_logger.handlers[0]
        if hasattr(current_handler, 'baseFilename'):
            current_log_file = current_handler.baseFilename
    
    logging_data = {
        "status": "healthy",
        "file_logging": {
            "enabled": config.is_log_to_file_enabled(),
            "levels": config.log_to_file,
            "file_path": config.log_file_path,
            "current_log_file": current_log_file,
            "status": "active" if file_logger else "inactive"
        },
        "database_logging": {
            "enabled": config.is_log_to_db_enabled(),
            "levels": config.log_to_db,
            "status": "available" if db_connection else "unavailable"
        },
        "console_logging": {
            "enabled": verbose_mode,  # Консольное логирование теперь зависит от verbose режима
            "description": "Только в verbose режиме"
        },
        "settings": {
            "mask_sensitive_data": config.mask_sensitive_data
        },
        "verbose_mode": {
            "enabled": verbose_mode,
            "description": "Detailed request/response logging"
        },
        "timestamp": datetime.now().isoformat()
    }
    
    response = web.json_response(logging_data)
    await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'health_logging'))
    return response


async def health_network(request: web.Request) -> web.Response:
    """
    Название: health_network
    Назначение: Детальная сетевая информация о сервере
    Описание: Возвращает подробную информацию о сетевых настройках и CORS конфигурации
    Принцип работы: Собирает информацию о хосте, порте и настройках CORS
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: web.Response - JSON ответ с кодом статуса 200 и детальной сетевой информацией
    """
    network_data = {
        "status": "healthy",
        "server": {
            "host": config.host,
            "port": config.port,
            "url": f"http://{config.host}:{config.port}"
        },
        "cors": {
            "enabled": config.cors_enabled,
            "allowed_origins": config.cors_allowed_origins,
            "allowed_methods": config.cors_allowed_methods,
            "allowed_headers": config.cors_allowed_headers,
            "expose_headers": config.cors_expose_headers,
            "allow_credentials": config.cors_allow_credentials,
            "max_age": config.cors_max_age
        },
        "endpoints": [
            "GET /health",
            "GET /health/security", 
            "GET /health/database",
            "GET /health/logging",
            "GET /health/network",
            "POST /user/by-phone",
            "POST /user/update",
            "POST /user/mailing",
            "POST /ticket/list",
            "POST /payment/set",
            "POST /payment/calculate-distribution",            
            "POST /login",
            "POST /document/load",
            "POST /document/signed",
            "POST /document/list",            
            "GET /help"
        ],
        "timestamp": datetime.now().isoformat()
    }
    
    response = web.json_response(network_data)
    await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'health_network'))
    return response

async def health_cloud(request: web.Request) -> web.Response:
    """
    Название: health_cloud
    Назначение: Детальная информация о состоянии облачного хранилища
    Описание: Возвращает подробную информацию о конфигурации и доступности облачного хранилища
    Принцип работы: Собирает информацию о настройках облака и проверяет его доступность
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: web.Response - JSON ответ с кодом статуса 200 и детальной информацией о облачном хранилище
    """
    # Проверяем доступность облачного хранилища
    cloud_available = False
    if config.cloud_enabled:
        cloud_available = await check_cloud_availability()
    
    # Формируем данные о конфигурации облачного хранилища (без конфиденциальной информации)
    cloud_data = {
        "status": "available" if cloud_available else "unavailable",
        "enabled": config.cloud_enabled,
        "configuration": {
            "url_configured": bool(config.cloud_url),
            "username_configured": bool(config.cloud_username),
            "password_configured": bool(config.cloud_password),
            "repo_id_configured": bool(config.cloud_repo_id),
            "upload_path": config.cloud_upload_path,
            "timeout": config.cloud_timeout,
            "temp_dir": config.cloud_temp_dir,
            "allow_start_without_cloud": config.allow_start_without_cloud
        },
        "availability_check": {
            "method": "token_authentication",
            "success": cloud_available,
            "description": "Проверка доступности через получение токена аутентификации"
        },
        "statistics": {
            "requests_processed": 0,  # Можно добавить счетчик при необходимости
            "last_check_time": datetime.now().isoformat()
        },
        "timestamp": datetime.now().isoformat()
    }
    
    response = web.json_response(cloud_data)
    await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'health_cloud'))
    return response    

async def help_handler(request: web.Request) -> web.Response:
    """
    Название: help_handler
    Назначение: Обработчик для вывода содержимого HTML файла справки
    Описание: Возвращает содержимое файла help.html или сообщение об ошибке в HTML формате если файл недоступен
    Принцип работы: Проверяет наличие файла help.html, читает его содержимое или возвращает простое HTML сообщение об ошибке
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: web.Response - HTML ответ с содержимым help.html или сообщением об ошибке
    """
    help_file_path = "help.html"
    
    try:
        if not os.path.exists(help_file_path):
            # Файл не найден - возвращаем простое HTML сообщение об ошибке
            error_html = "<html><body><h1>Файл справки не найден</h1><p>Файл help.html отсутствует в текущей директории сервера.</p></body></html>"
            response = web.Response(text=error_html, content_type='text/html', status=404)
            await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'help'))
            return response
        
        # Читаем содержимое HTML файла
        with open(help_file_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Создаем HTML ответ
        response = web.Response(text=html_content, content_type='text/html')
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'help'))
        return response
        
    except Exception as e:
        # Любая ошибка - возвращаем простое HTML сообщение
        error_html = f"<html><body><h1>Ошибка сервера</h1><p>Не удалось обработать запрос справки: {str(e)}</p></body></html>"
        response = web.Response(text=error_html, content_type='text/html', status=500)
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'help'))
        return response
    
async def health_statistics(request: web.Request) -> web.Response:
    """
    Название: health_statistics
    Назначение: Статистика работы сервера
    Описание: Возвращает подробную статистику запросов к серверу, БД и облаку
    Принцип работы: Собирает статистику из глобальных переменных и формирует ответ
    Входящие параметры: request - объект HTTP запроса
    Исходящие параметры: web.Response - JSON ответ с кодом статуса 200 и статистикой
    """
    global statistics
    
    # Рассчитываем время работы статистики
    uptime = datetime.now() - statistics["reset_time"]
    uptime_hours = uptime.total_seconds() / 3600
    
    # Рассчитываем средние показатели
    total_requests = statistics["server_requests"]["total_count"]
    requests_per_hour = total_requests / uptime_hours if uptime_hours > 0 else 0
    
    # Формируем данные статистики
    stat_data = {
        "status": "healthy",
        "statistics_period": {
            "reset_time": statistics["reset_time"].isoformat(),
            "uptime_seconds": int(uptime.total_seconds()),
            "uptime_human": str(uptime).split('.')[0]  # Без микросекунд
        },
        "database_statistics": {
            "total_queries": statistics["db_queries"]["total_count"],
            "max_execution_time_ms": statistics["db_queries"]["max_execution_time"],
            "queries_per_hour": statistics["db_queries"]["total_count"] / uptime_hours if uptime_hours > 0 else 0,
            "slowest_queries": statistics["db_queries"]["slowest_queries"]
        },
        "cloud_statistics": {
            "total_requests": statistics["cloud_requests"]["total_count"],
            "successful_requests": statistics["cloud_requests"]["success_count"],
            "failed_requests": statistics["cloud_requests"]["failed_count"],
            "success_rate": statistics["cloud_requests"]["success_count"] / statistics["cloud_requests"]["total_count"] * 100 if statistics["cloud_requests"]["total_count"] > 0 else 0
        },
        "server_statistics": {
            "total_requests": total_requests,
            "requests_per_hour": round(requests_per_hour, 2),
            "hourly_distribution": statistics["server_requests"]["hourly_stats"],
            "daily_statistics": statistics["server_requests"]["daily_stats"],
            "peak_performance": {
                "peak_hour": statistics["server_requests"]["peak_hour"],
                "peak_day": statistics["server_requests"]["peak_day"]
            }
        },
        "counters_status": {
            "current_total": total_requests,
            "max_limit": statistics["limits"]["max_total_count"],
            "usage_percentage": round((total_requests / statistics["limits"]["max_total_count"]) * 100, 2),
            "status": "normal" if (total_requests / statistics["limits"]["max_total_count"]) < statistics["limits"]["warning_threshold"] else "warning"
        },
        "timestamp": datetime.now().isoformat()
    }
    
    response = web.json_response(stat_data)
    await add_server_signature_to_response(response, getattr(request, 'authenticated_token', 'health_statistics'))
    return response


def validate_required_params(data: dict, required_params: list) -> dict:
    """
    Название: validate_required_params
    Назначение: Универсальная проверка обязательных параметров в данных запроса
    Описание: Проверяет наличие и валидность обязательных параметров в словаре данных
    Принцип работы: Проверяет каждый параметр из списка required_params на наличие и соответствие базовым правилам валидации
    Входящие параметры:
        data - словарь с данными для проверки
        required_params - список обязательных параметров для проверки
    Исходящие параметры: dict - результат проверки:
        - {"status": "ok"} если все параметры валидны
        - {"status": "error", "code": 1, "message": "сообщение об ошибках"} если есть ошибки
    """
    errors = []
    
    for param in required_params:
        # Проверка наличия параметра
        if param not in data:
            errors.append(f"Отсутствует обязательное поле '{param}'")
            continue
        
        value = data[param]
        
        # Проверка на пустоту для строковых параметров
        if isinstance(value, str) and not value.strip():
            errors.append(f"Поле '{param}' не может быть пустой строкой")
            continue
            
        # Проверка на None
        if value is None:
            errors.append(f"Поле '{param}' не может быть null")
            continue
            
        # Проверка типа для строковых параметров (если ожидается строка)
        if not isinstance(value, str) and param in ['phone', 'email', 'name']:  # Примеры параметров, которые должны быть строками
            errors.append(f"Поле '{param}' должно быть строкой")
            continue
    
    if errors:
        # Объединяем все ошибки в одно сообщение
        error_message = "; ".join(errors)
        return {
            "status": "error", 
            "code": 1,
            "message": error_message
        }
    else:
        return {"status": "ok"}

def hash_password(password: str) -> str:
    """
    Простое хеширование пароля без соли
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


async def find_user_by_phone(phone: str) -> Optional[Dict[str, Any]]:
    """
    Название: find_user_by_phone
    Назначение: Поиск пользователя в базе данных по номеру телефона через хранимую процедуру
    Описание: Выполняет вызов хранимой процедуры USR_Insert для поиска или создания пользователя по нормализованному номеру телефона
    Принцип работы: Нормализует номер телефона, выполняет вызов хранимой процедуры с параметризацией через курсор
    Входящие параметры: phone - номер телефона для поиска
    Исходящие параметры: Dict[str, Any] или None - данные пользователя или None если не найден
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    normalized_phone = normalize_phone(phone)
    if not normalized_phone:
        return None
    
    try:
        # Вызов хранимой процедуры USR_Insert
        query = "EXECUTE [dbo].[USR_Insert] @USR_Phone = ?"
        
        if verbose_mode:
            print_status("INFO", f"Вызов хранимой процедуры USR_Insert", 
                        f"phone: {normalized_phone}")
        
        # Создаем курсор с таймаутом
        cursor = db_connection.cursor()
        
        # Устанавливаем таймаут выполнения (30 секунд)
        cursor.execute("SET LOCK_TIMEOUT 30000")
        
        # Выполняем хранимую процедуру с обработкой параметров
        cursor.execute(query, (normalized_phone,))
        
        # Пытаемся получить результаты, если процедура их возвращает
        results = []
        try:
            if cursor.description:  # Если есть возвращаемые колонки
                columns = [column[0] for column in cursor.description]
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
        except Exception as fetch_error:
            # Если нет результатов для выборки (например, только операция вставки)
            if verbose_mode:
                print_status("INFO", f"Нет возвращаемых данных от процедуры", str(fetch_error))
            pass
        
        # Закрываем курсор
        cursor.close()
        
        if results and len(results) > 0:
            user_data = results[0]
            
            # Проверяем, найден ли пользователь (ID > 0)
            user_id = user_data.get('USR_ID') or user_data.get('ID')
            if user_id and user_id > 0:
                if verbose_mode:
                    print_status("OK", f"Пользователь найден через хранимую процедуру", 
                                f"ID: {user_id}, phone: {normalized_phone}")
                return user_data
            
            if verbose_mode:
                print_status("INFO", f"Пользователь не найден через хранимую процедуру", 
                            f"ID: {user_id}, phone: {normalized_phone}")
        
        return None
        
    except Exception as e:
        print(f"❌ Ошибка поиска пользователя по телефону {normalized_phone} через хранимую процедуру: {e}")
        # Закрываем курсор в случае ошибки
        try:
            cursor.close()
        except:
            pass
        raise

async def getinfo_user_by_phone(phone: str) -> Optional[Dict[str, Any]]:
    """
    Название: find_user_by_phone
    Назначение: Поиск пользователя в базе данных по номеру телефона
    Описание: Выполняет запрос к таблице USR для поиска пользователя по нормализованному номеру телефона
    Принцип работы: Нормализует номер телефона, выполняет SQL запрос с параметризацией
    Входящие параметры: phone - номер телефона для поиска
    Исходящие параметры: Dict[str, Any] или None - данные пользователя или None если не найден
    """
    if not db_connection:
        raise Exception("База данных не доступна")
    
    normalized_phone = normalize_phone(phone)
    if not normalized_phone:
        return None
    
    try:
        query = """
        SELECT USR_Id, USR_Phone, USR_Email, USR_Password, USR_DReg, USR_xDel
        FROM USR 
        WHERE USR_Phone = ? AND (USR_xDel IS NULL OR USR_xDel = 0)
        """
        
        results = await execute_query(query, {"phone": normalized_phone})
        
        if results and len(results) > 0:
            return results[0]
        return None
        
    except Exception as e:
        print(f"❌ Ошибка поиска пользователя по телефону {normalized_phone}: {e}")
        raise    
    
async def get_user_by_phone(request: web.Request) -> web.Response:
    """
    Название: get_user_by_phone
    Назначение: Эндпоинт для получения информации о пользователе по номеру телефона с серверной подписью
    Описание: Принимает номер телефона, ищет пользователя в БД и возвращает ответ с подписью сервера
    Принцип работы: Проверяет входные данные, нормализует телефон, ищет в БД, добавляет подпись к ответу
    Входящие параметры: request - HTTP запрос с JSON телом содержащим phone
    Исходящие параметры: web.Response - JSON ответ с кодом статуса, данными пользователя и подписью сервера
    """
    try:
        # Аутентификация по токену (с проверкой подписи клиента)
        token = await authenticate_request(request)
        if verbose_mode:
            print_status("OK", f"Аутентификация пройдена", f"токен {token[:8]}...")
        
        # Парсим JSON тело запроса
        data = await request.json()
        if verbose_mode:
            print_status("INFO", f"Получены данные", str(data))
        
        # УНИВЕРСАЛЬНАЯ ПРОВЕРКА ОБЯЗАТЕЛЬНЫХ ПАРАМЕТРОВ
        validation_result = validate_required_params(data, ['phone'])
        
        if validation_result['status'] == 'error':
            # ВОЗВРАЩАЕМ ОТВЕТ В ЕДИНОМ СТАНДАРТЕ С КОДОМ 200
            response = web.json_response(validation_result, status=200)
            if verbose_mode:
                print_status("ERROR", f"Ошибка валидации параметров", validation_result['message'])
        else:
            phone = data['phone']
            if verbose_mode:
                print_status("INFO", f"Поиск пользователя по телефону", phone)
            
            # Ищем пользователя в базе данных
            user = await db_user_by_phone(phone)
            
            if not user:
                # Пользователь не существует - возвращаем 200 с ошибкой
                response_data = {
                    "status": "success",
                    "code": 3,
                    "message": "Пользователь не найден"
                }
                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    print_status("INFO", f"Пользователь с телефоном {phone} не найден (возвращаем 200)")
            else:
                # Формируем ответ
                response_data = {
                    "status": "success",
                    "code": user.get('_code', 0),  # Используем 0 как значение по умолчанию
                }
                
                # Создаем data объект, включающий все поля из user,
                # которые не начинаются с нижнего подчеркивания
                data_object = {}
                for key, value in user.items():
                    # Проверяем, что ключ не начинается с "_"
                    if not key.startswith('_'):
                        data_object[key] = value
                
                response_data["data"] = data_object
                
                response = web.json_response(response_data)
                if verbose_mode:
                    print_status("OK", f"Пользователь найден", 
                               f"ID: {user.get('USR_Id')}, Код: {response_data['code']}")
                    print(f"  Включено полей в data: {len(data_object)}")
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи к заголовкам ответа
        await add_server_signature_to_response(response, token)
        if verbose_mode:
            print_status("OK", f"Добавлена серверная подписи к ответу")
        
        return response
        
    except web.HTTPException as he:
        # Перехватываем HTTP исключения (403, 404 и т.д.) и добавляем подпись
        # Для HTTP исключений также используем единый стандарт
        response_data = {
            "status": "error",
            "code": 1,
            "message": he.text
        }
        response = web.json_response(response_data, status=he.status)
        if verbose_mode:
            print_status("ERROR", f"HTTP исключение в get_user_by_phone",
                        data_lines=[
                            f"Статус: {he.status}",
                            f"Текст: {he.text}"
                        ])
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', None))
        return response
    except json.JSONDecodeError as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка декодирования JSON", str(e))
        response_data = {
            "status": "error",
            "code": 1,
            "message": "Невалидный JSON в теле запроса"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "json_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка в get_user_by_phone", str(e))
            import traceback
            traceback.print_exc()
        response_data = {
            "status": "error",
            "code": 1,
            "message": f"Ошибка при поиске пользователя: {str(e)}"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "unexpected_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response

async def get_user_update(request: web.Request) -> web.Response:
    """
    Название: get_user_update
    Назначение: Эндпоинт для обновления данных пользователя с серверной подписью
    """
    try:
        # Аутентификация по токену (с проверкой подписи клиента)
        token = await authenticate_request(request)
        if verbose_mode:
            print_status("OK", f"Аутентификация пройдена", f"токен {token[:8]}...")
        
        # Парсим JSON тело запроса
        data = await request.json()
        if verbose_mode:
            print_status("INFO", f"Получены данные для обновления", str(data))
        
        # УНИВЕРСАЛЬНАЯ ПРОВЕРКА ОБЯЗАТЕЛЬНЫХ ПАРАМЕТРОВ
        validation_result = validate_required_params(data, ['id'])
        
        if validation_result['status'] == 'error':
            response = web.json_response(validation_result, status=200)
            if verbose_mode:
                print_status("ERROR", f"Ошибка валидации параметров", validation_result['message'])
        else:
            user_id = data['id']
            email = data.get('email', '')
            password = data.get('password', '')

            # ПРОВЕРКА СУЩЕСТВОВАНИЯ ПОЛЬЗОВАТЕЛЯ
            user_exists = await db_userid(user_id)
            if not user_exists:
                raise Exception(f"Пользователь с ID {user_id} не найден")            

            if verbose_mode:
                print_status("INFO", f"Обновление пользователя", f"ID: {user_id}, Email: {email}")
            
            # Проверяем что ID является числом
            try:
                user_id_int = int(user_id)
            except (ValueError, TypeError):
                response_data = {
                    "status": "error",
                    "message": "Параметр id должен быть числом"
                }
                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    print_status("ERROR", f"Неверный формат ID пользователя", user_id)
            else:
                # Хешируем пароль если он предоставлен (БЕЗ СОЛИ)
                hashed_password_for_db = ""
                if password:
                    # Простое хеширование пароля без соли
                    hashed_password_for_db = hash_password(password)
                    if verbose_mode:
                        print_status("INFO", f"Пароль хеширован", f"длина хеша: {len(hashed_password_for_db)}")
                else:
                    if verbose_mode:
                        print_status("INFO", f"Пароль не предоставлен для обновления")
                
                # Обновляем пользователя в базе данных с хешированным паролем
                update_success = await db_user_update(user_id_int, email, hashed_password_for_db)
                
                if update_success:
                    response_data = {
                        "status": "success",
                        "message": "Данные пользователя успешно обновлены"
                    }
                    response = web.json_response(response_data, status=200)
                    if verbose_mode:
                        print_status("OK", f"Пользователь {user_id} успешно обновлен")
                else:
                    response_data = {
                        "status": "error", 
                        "message": "Пользователь не найден или ошибка обновления"
                    }
                    response = web.json_response(response_data, status=200)
                    if verbose_mode:
                        print_status("ERROR", f"Пользователь с ID {user_id} не найден (USR_Id = -1)")
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи к заголовкам ответа
        await add_server_signature_to_response(response, token)
        if verbose_mode:
            print_status("OK", f"Добавлена серверная подпись к ответу")
        
        return response
        
    except Exception as e:
        # Обработка неожиданных ошибок
        error_message = f"Внутренняя ошибка сервера: {str(e)}"
        response_data = {
            "status": "error",
            "message": error_message
        }
        response = web.json_response(response_data, status=200)
        
        try:
            token = getattr(request, 'token', '')
            await add_server_signature_to_response(response, token)
        except:
            pass
            
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка в get_user_update", str(e))
        
        return response




async def get_tickets(request: web.Request) -> web.Response:
    """
    Название: get_tickets
    Назначение: Эндпоинт для получения списка залоговых билетов пользователя с серверной подписью
    Описание: Принимает user_id и опциональный status, возвращает список залоговых билетов с подписью сервера
    Принцип работы: Проверяет входные данные, получает залоговые билеты из БД, формирует ответ с подписью
    Входящие параметры: request - HTTP запрос с JSON телом содержащим user_id и опционально status
    Исходящие параметры: web.Response - JSON ответ с кодом статуса, данными залоговых билетов и подписью сервера
    """
    try:
        # Аутентификация по токену (с проверкой подписи клиента)
        token = await authenticate_request(request)
        if verbose_mode:
            print_status("OK", f"Аутентификация пройдена", f"токен {token[:8]}...")
        
        # Парсим JSON тело запроса
        data = await request.json()
        if verbose_mode:
            print_status("INFO", f"Получены данные для получения залоговых билетов", str(data))
        
        # УНИВЕРСАЛЬНАЯ ПРОВЕРКА ОБЯЗАТЕЛЬНЫХ ПАРАМЕТРОВ
        validation_result = validate_required_params(data, ['user_id'])
        
        if validation_result['status'] == 'error':
            # ВОЗВРАЩАЕМ ОТВЕТ В ЕДИНОМ СТАНДАРТЕ С КОДОМ 200
            response = web.json_response(validation_result, status=200)
            if verbose_mode:
                print_status("ERROR", f"Ошибка валидации параметров", validation_result['message'])
        else:
            user_id = data['user_id']
            status = data.get('status', '')  # Опциональный параметр, по умолчанию пустая строка

            # ПРОВЕРКА СУЩЕСТВОВАНИЯ ПОЛЬЗОВАТЕЛЯ
            user_exists = await db_userid(user_id)
            if not user_exists:
                # Если пользователя нет, вызываем исключение для обработки в блоке except Exception as e:
                raise Exception(f"Пользователь с ID {user_id} не найден")        
            
            if verbose_mode:
                if status:
                    print_status("INFO", f"Поиск залоговых билетов пользователя", f"user_id: {user_id}, status: {status}")
                else:
                    print_status("INFO", f"Поиск всех залоговых билетов пользователя", f"user_id: {user_id}")
            

            # Получаем залоговые билеты из базы данных
            tickets = await db_tickets(user_id, status)
            
            if verbose_mode:
                print_status("INFO", f"Получено залоговых билетов из БД", str(len(tickets)))
                
                # Дополнительная информация для отладки
                if tickets:
                    print(f"  Пример залогового билета: {tickets[0].get('external_id', 'N/A')} - {tickets[0].get('status', 'N/A')}")
                    if 'items' in tickets[0]:
                        print(f"  Количество предметов в первом залоговом билете: {len(tickets[0]['items'])}")
            
            # Проверяем, найдены ли залоговые билеты
            if not tickets:
                # Залоговые билеты не найдены - возвращаем ошибку
                response_data = {
                    "status": "error",
                    "message": f"Залоговые билеты не найдены для пользователя {user_id}" + (f" со статусом {status}" if status else "")
                }
                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    print_status("INFO", f"Залоговые билеты не найдены, возвращаем ошибку")
            else:
                # Залоговые билеты найдены - возвращаем успешный ответ
                response_data = {
                    "status": "success",
                    "tickets": tickets
                }
                response = web.json_response(response_data)
                if verbose_mode:
                    print_status("OK", f"Успешно возвращено залоговых билетов", str(len(tickets)))
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи к заголовкам ответа
        await add_server_signature_to_response(response, token)
        if verbose_mode:
            print_status("OK", f"Добавлена серверная подпись к ответу")
        
        return response
        
    except web.HTTPException as he:
        # Перехватываем HTTP исключения (403, 404 и т.д.) и добавляем подпись
        response_data = {
            "status": "error",
            "message": he.text
        }
        response = web.json_response(response_data, status=he.status)
        if verbose_mode:
            print_status("ERROR", f"HTTP исключение в get_tickets",
                        data_lines=[
                            f"Статус: {he.status}",
                            f"Текст: {he.text}"
                        ])
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', None))
        return response
    except json.JSONDecodeError as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка декодирования JSON", str(e))
        response_data = {
            "status": "error",
            "message": "Невалидный JSON в теле запроса"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "json_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка в get_tickets", str(e))
            import traceback
            traceback.print_exc()
        response_data = {
            "status": "error",
            "message": f"Ошибка при получении залоговых билетов: {str(e)}"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "unexpected_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
        
    except web.HTTPException as he:
        # Перехватываем HTTP исключения (403, 404 и т.д.) и добавляем подпись
        response_data = {
            "status": "error",
            "message": he.text
        }
        response = web.json_response(response_data, status=he.status)
        if verbose_mode:
            print_status("ERROR", f"HTTP исключение в get_tickets",
                        data_lines=[
                            f"Статус: {he.status}",
                            f"Текст: {he.text}"
                        ])
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', None))
        return response
    except json.JSONDecodeError as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка декодирования JSON", str(e))
        response_data = {
            "status": "error",
            "message": "Невалидный JSON в теле запроса"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "json_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка в get_tickets", str(e))
            import traceback
            traceback.print_exc()
        response_data = {
            "status": "error",
            "message": f"Ошибка при получении тикетов: {str(e)}"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "unexpected_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
        
    except web.HTTPException as he:
        # Перехватываем HTTP исключения (403, 404 и т.д.) и добавляем подпись
        response_data = {
            "status": "error",
            "message": he.text
        }
        response = web.json_response(response_data, status=he.status)
        if verbose_mode:
            print_status("ERROR", f"HTTP исключение в get_tickets",
                        data_lines=[
                            f"Статус: {he.status}",
                            f"Текст: {he.text}"
                        ])
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', None))
        return response
    except json.JSONDecodeError as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка декодирования JSON", str(e))
        response_data = {
            "status": "error",
            "message": "Невалидный JSON в теле запроса"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "json_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка в get_tickets", str(e))
            import traceback
            traceback.print_exc()
        response_data = {
            "status": "error",
            "message": f"Ошибка при получении тикетов: {str(e)}"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "unexpected_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response


async def get_setpayment(request: web.Request) -> web.Response:
    """
    Название: get_setpayment
    Назначение: Эндпоинт для обработки платежей через хранимую процедуру ZbPaymentsTest_Json
    Описание: Принимает данные о платежах как JSON строку и передает их в хранимую процедуру для обработки
    Принцип работы: Получает тело запроса как строку и передает как есть в хранимую процедуру
    Входящие параметры: request - HTTP запрос с JSON телом
    Исходящие параметры: web.Response - JSON ответ с кодом статуса и результатом обработки
    """
    try:
        # Аутентификация по токену (с проверкой подписи клиента)
        token = await authenticate_request(request)
        if verbose_mode:
            print_status("OK", f"Аутентификация пройдена", f"токен {token[:8]}...")
        
        # Получаем тело запроса как строку (без парсинга в JSON объект)
        try:
            raw_body = await request.read()
            # Проверяем, что тело запроса не пустое
            if not raw_body:
                response_data = {
                    "status": "error",
                    "message": "Тело запроса пустое"
                }
                response = web.json_response(response_data, status=200)
                await add_server_signature_to_response(response, token)
                return response
                
            # Декодируем в UTF-8
            json_str = raw_body.decode('utf-8')
            
            if verbose_mode:
                print_status("INFO", f"Получены данные для обработки платежей")
                print(f"  Длина JSON строки: {len(json_str)} символов")
                print(f"  Данные (первые 500 символов): {json_str[:500]}..." if len(json_str) > 500 else f"  Данные: {json_str}")
            
            # Пытаемся проверить, что это валидный JSON (но не парсим)
            try:
                # Только проверяем синтаксис, но не преобразуем в объект
                json.loads(json_str)
            except json.JSONDecodeError as e:
                response_data = {
                    "status": "error",
                    "message": f"Невалидный JSON формат: {str(e)}"
                }
                response = web.json_response(response_data, status=200)
                await add_server_signature_to_response(response, token)
                return response
            
        except UnicodeDecodeError as e:
            response_data = {
                "status": "error", 
                "message": "Ошибка декодирования UTF-8"
            }
            response = web.json_response(response_data, status=200)
            await add_server_signature_to_response(response, token)
            return response
        except Exception as e:
            response_data = {
                "status": "error",
                "message": f"Ошибка чтения тела запроса: {str(e)}"
            }
            response = web.json_response(response_data, status=200)
            await add_server_signature_to_response(response, token)
            return response
        
        # ПРОВЕРКА СУЩЕСТВОВАНИЯ ПОЛЬЗОВАТЕЛЯ (если можем извлечь user_id из JSON)
        try:
            # Пытаемся извлечь user_id для проверки (если есть в JSON)
            data_obj = json.loads(json_str)  # Парсим только для проверки пользователя
            user_id = data_obj.get('user_id')
            if user_id:
                user_exists = await db_userid(user_id)
                if not user_exists:
                    raise Exception(f"Пользователь с ID {user_id} не найден")
        except Exception as e:
            if "не найден" in str(e):
                raise  # Перебрасываем только ошибку "не найден"
            # Игнорируем другие ошибки при парсинге для проверки пользователя
        
        if verbose_mode:
            print_status("INFO", f"Передача данных в хранимую процедуру")
        
        # Обрабатываем платежи через хранимую процедуру - передаем JSON строку как есть
        result = await db_setpayment(json_str)
        
        if result:
            # Успешная обработка
            response_data = {
                "status": "success",
                "message": "Платежи успешно обработаны"
            }
            response = web.json_response(response_data, status=200)
            if verbose_mode:
                print_status("OK", f"Платежи успешно обработаны")
        else:
            # Ошибка обработки
            response_data = {
                "status": "error", 
                "message": "Ошибка обработки платежей"
            }
            response = web.json_response(response_data, status=200)
            if verbose_mode:
                print_status("ERROR", f"Ошибка обработки платежей")
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи к заголовкам ответа
        await add_server_signature_to_response(response, token)
        if verbose_mode:
            print_status("OK", f"Добавлена серверная подписи к ответу")
        
        return response
        
    except Exception as e:
        if "не найден" in str(e):
            response_data = {
                "status": "error",
                "message": str(e)
            }
            response = web.json_response(response_data, status=200)
        else:
            if verbose_mode:
                print_status("ERROR", f"Неожиданная ошибка в get_setpayment", str(e))
                import traceback
                traceback.print_exc()
            response_data = {
                "status": "error",
                "message": f"Ошибка при обработке платежей: {str(e)}"
            }
            response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "unexpected_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response


async def get_login(request: web.Request) -> web.Response:
    """
    Название: get_login
    Назначение: Эндпоинт для аутентификации пользователя по телефону и паролю.
                Варианты code:
                  1 – неверный телефон или пароль / превышен лимит попыток
                  2 – пользователь заблокирован
                  3 – успешная аутентификация
    Примечание: HTTP-статус всегда 200 для совместимости с фронтом.
                При блокировке: status = "error", error_code = "USER_BLOCKED".
                При неверных данных: status = "error", error_code = "INVALID_CREDENTIALS".
    """
    try:
        # Аутентификация по токену (с проверкой подписи клиента)
        token = await authenticate_request(request)
        if verbose_mode:
            print_status("OK", "Аутентификация пройдена", f"токен {token[:8]}...")

        # Парсим JSON тело запроса
        data = await request.json()
        if verbose_mode:
            print_status("INFO", "Получены данные для аутентификации", str(data))

        # УНИВЕРСАЛЬНАЯ ПРОВЕРКА ОБЯЗАТЕЛЬНЫХ ПАРАМЕТРОВ
        validation_result = validate_required_params(data, ['phone', 'password'])

        if validation_result['status'] == 'error':
            response = web.json_response(validation_result, status=200)
            if verbose_mode:
                print_status("ERROR", "Ошибка валидации параметров", validation_result['message'])
        else:
            phone = data['phone']
            password = data['password']

            if verbose_mode:
                print_status("INFO", "Аутентификация пользователя", f"phone: {phone}")

            # Шаг 1: хешируем пароль для сравнения с хешем в БД
            hashed_password = hash_password(password)
            if verbose_mode:
                print_status("INFO", "Пароль хеширован для проверки",
                             f"длина хеша: {len(hashed_password)}")

            # Шаг 2: вызываем USR_Select_ID через db_login
            login_result = await db_login(phone, hashed_password)

            status = login_result.get("status")
            user_data = login_result.get("data")

            if status == "blocked" or status == "locked":
                # Пользователь заблокирован. locked оставлен для обратной совместимости.
                asyncio.create_task(log_to_database({
                    "request_id": getattr(request, 'request_id', str(uuid.uuid4())),
                    "endpoint": request.path,
                    "params": f"phone={phone}",
                    "processing_time": 0,
                    "response_code": 200,
                    "message": "USER_BLOCKED_LOGIN"
                }))
                response_data = {
                    "status": "error",
                    "code": 2,
                    "error_code": "USER_BLOCKED",
                    "message": "Пользователь заблокирован. Обратитесь в поддержку."
                }
                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    print_status("ERROR", "Доступ запрещён — пользователь заблокирован",
                                 f"phone: {phone}")
            elif status == "invalid_credentials":
                # Неверный телефон или пароль (USR_Select_ID вернул -1 или пусто)
                response_data = {
                    "status": "error",
                    "code": 1,
                    "error_code": "INVALID_CREDENTIALS",
                    "message": "Неверный телефон или пароль"
                }
                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    print_status("INFO",
                                 "Аутентификация не удалась (invalid_credentials)",
                                 f"phone: {phone}")
            elif status == "success":
                # Успешная аутентификация
                response_data = {
                    "status": "success",
                    "code": 3,
                    "data": user_data
                }

                # Фильтруем None значения из данных пользователя
                if isinstance(user_data, dict):
                    response_data['data'] = {k: v for k, v in user_data.items() if v is not None}

                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    user_id = None
                    if isinstance(user_data, dict):
                        user_id = user_data.get('id') or user_data.get('USR_Id')
                    print_status("OK", "Аутентификация успешна",
                                 f"user_id: {user_id if user_id is not None else 'N/A'}")
            else:
                # Неожиданная ошибка на уровне db_login / USR_Select_ID
                response_data = {
                    "status": "error",
                    "message": login_result.get("message", "Ошибка при аутентификации")
                }
                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    print_status("ERROR",
                                 "Неожиданное состояние login_result",
                                 str(login_result))

        await add_server_signature_to_response(response, token)
        if verbose_mode:
            print_status("OK", "Добавлена серверная подпись к ответу")

        return response

    except Exception as e:
        if verbose_mode:
            print_status("ERROR", "Неожиданная ошибка в get_login", str(e))

        response_data = {
            "status": "error",
            "message": f"Ошибка при аутентификации: {str(e)}"
        }
        response = web.json_response(response_data, status=200)

        auth_header = request.headers.get("Token", "")
        token_for_signature = "unexpected_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)

        return response

async def get_setdocument(request: web.Request) -> web.Response:
    """
    Название: get_setdocument
    Назначение: Эндпоинт для сохранения файлов любого типа с контролем размера
    Описание: Принимает данные файла в формате base64, проверяет размер файла,
            сохраняет временный файл, загружает в облачное хранилище и 
            сохраняет метаданные в базу данных
    Принцип работы:
    1. Проверяет аутентификацию и авторизацию запроса
    2. Валидирует размер запроса по заголовку Content-Length
    3. Парсит JSON тело запроса и проверяет обязательные поля
    4. Проверяет фактический размер файла из данных base64
    5. Сохраняет файл из base64 во временную директорию
    6. Загружает файл в облачное хранилище (если включено)
    7. Сохраняет метаданные документа в базу данных
    8. Возвращает результат с серверной подписью
    Особенности:
    - Принимает файлы любого типа
    - Проверяет размер файла до и после декодирования base64
    - Использует лимит из конфигурации (config.max_upload_size)
    - Автоматически очищает временные файлы
    - Поддерживает работу без облачного хранилища
    Входящие параметры:
    request - HTTP запрос с JSON телом содержащим:
        data:      (обязательное) Данные файла в формате base64
        extension: (обязательное) Расширение файла (например: pdf, jpg, doc, zip и т.д.)
        name:      (опциональное) Имя файла, по умолчанию генерируется
        description: (опциональное) Описание документа
        user_id:   (опциональное) ID пользователя для привязки документа
    Исходящие параметры:
    web.Response - JSON ответ с кодом статуса 200 и структурой:
        Успех: {"status": "success", "link": "URL_к_файлу"}
        Ошибка: {"status": "error", "message": "Описание_ошибки"}
    Ошибки:
    413 - Размер запроса превышает лимит (Payload Too Large)
    400 - Невалидный JSON или отсутствуют обязательные поля
    403 - Ошибка аутентификации/авторизации
    200 - Бизнес-логические ошибки (пользователь не найден, ошибка БД и т.д.)
    """
    temp_file_path = None
    
    try:
        # Шаг 1: Аутентификация и авторизация запроса
        token = await authenticate_request(request)
        if verbose_mode:
            print_status("OK", f"Аутентификация пройдена", f"токен {token[:8]}...")

        # Шаг 2: Предварительная проверка размера запроса
        content_length = request.content_length
        if content_length:
            max_size_bytes = config.max_upload_size * 1024 * 1024
            
            if verbose_mode:
                content_mb = content_length / 1024 / 1024
                max_mb = config.max_upload_size
                print_status("INFO", f"Проверка размера запроса",
                            f"{content_length:,} байт ({content_mb:.2f} МБ) из "
                            f"{max_size_bytes:,} допустимых ({max_mb} МБ)")
            
            if content_length > max_size_bytes:
                response_data = {
                    "status": "error",
                    "message": f"Размер запроса ({content_mb:.1f} МБ) "
                            f"превышает максимально допустимый ({max_mb} МБ)"
                }
                response = web.json_response(response_data, status=413)
                await add_server_signature_to_response(response, token)
                return response
        
        # Шаг 3: Парсинг и валидация JSON тела запроса
        data = await request.json()
        
        if verbose_mode:
            received_fields = list(data.keys())
            print_status("INFO", f"Получены данные для сохранения файла", 
                        f"поля: {received_fields}")
            if 'data' in data:
                data_size = len(data['data'])
                print(f"  Размер данных base64: {data_size:,} байт "
                    f"({data_size / 1024 / 1024:.2f} МБ)")
        
        # Шаг 4: Проверка обязательных полей
        validation_result = validate_required_params(data, ['data', 'extension','user_id'])
        
        if validation_result['status'] == 'error':
            response = web.json_response(validation_result, status=200)
            if verbose_mode:
                print_status("ERROR", f"Ошибка валидации параметров", validation_result['message'])
        else:
            # Извлекаем параметры из запроса
            file_data = data['data']           # Base64 данные файла
            extension = data['extension']      # Расширение файла
            name = data.get('name', f"file_{int(time.time())}")  # Имя или сгенерированное
            description = data.get('description')  # Описание документа (опционально)
            user_id = data.get('user_id')      # ID пользователя 
            doc_type = data.get('type')  # Тип документа (опционально)


            # Шаг 5: Валидация расширения файла (принимаем любые расширения)
            extension_lower = extension.lower().strip()
            
            if verbose_mode:
                print_status("INFO", f"Получено расширение файла",
                            f"'{extension}' -> нормализовано: '{extension_lower}'")
            
            # Проверяем существование пользователя (если user_id указан)
            if user_id:
                user_exists = await db_userid(user_id)
                if not user_exists:
                    raise Exception(f"Пользователь с ID {user_id} не найден")            
            
            if verbose_mode:
                print_status("INFO", f"Обработка файла", 
                            f"name: {name}, extension: {extension_lower}")
                if description:
                    print(f"  Описание: {description}")
                if user_id:
                    print(f"  User ID: {user_id}")
            
            # Шаг 6: Проверка фактического размера файла из base64
            try:
                import base64
                file_size_bytes = len(base64.b64decode(file_data))
                max_size_bytes = config.max_upload_size * 1024 * 1024
                
                if verbose_mode:
                    size_mb = file_size_bytes / 1024 / 1024
                    max_mb = config.max_upload_size
                    print_status("INFO", f"Фактический размер файла", 
                                f"{size_mb:.2f} МБ из {max_mb} допустимых")
                
                if file_size_bytes > max_size_bytes:
                    response_data = {
                        "status": "error",
                        "message": f"Размер файла ({size_mb:.1f} МБ) "
                                f"превышает максимально допустимый ({max_mb} МБ)"
                    }
                    response = web.json_response(response_data, status=200)
                    await add_server_signature_to_response(response, token)
                    return response
                    
            except Exception as e:
                if verbose_mode:
                    print_status("WARNING", f"Не удалось проверить размер файла", str(e))
                # Продолжаем обработку если не удалось проверить размер
            
            # Шаг 7: Преобразование user_id в число для базы данных
            user_id_int = None
            if user_id:
                try:
                    user_id_int = int(user_id)
                    if verbose_mode:
                        print_status("INFO", f"User ID преобразован в число", f"{user_id_int}")
                except (ValueError, TypeError):
                    if verbose_mode:
                        print_status("ERROR", f"Неверный формат user_id", f"'{user_id}' не является числом")
                    response_data = {
                        "status": "error",
                        "message": "Параметр user_id должен быть числом"
                    }
                    response = web.json_response(response_data, status=200)
                    await add_server_signature_to_response(response, token)
                    return response
            else:
                if verbose_mode:
                    print_status("INFO", f"User ID не указан, будет использовано значение по умолчанию")
            
            # Шаг 8: Сохранение файла из base64 во временную директорию
            try:
                # Добавляем расширение к имени файла если его нет
                if not name.lower().endswith(f'.{extension_lower}'):
                    name = f"{name}.{extension_lower}"
                    if verbose_mode:
                        print_status("INFO", f"Нормализация имени файла", 
                                    f"добавлено расширение .{extension_lower}: {name}")
                
                temp_file_path = save_base64_to_file(file_data, name, extension_lower)
                file_name = os.path.basename(temp_file_path)
                
                if verbose_mode:
                    file_size = os.path.getsize(temp_file_path)
                    print_status("OK", f"Файл временно сохранен", 
                                f"{file_name} ({file_size / 1024 / 1024:.2f} МБ)")
            except Exception as e:
                response_data = {
                    "status": "error",
                    "message": f"Ошибка сохранения файла: {str(e)}"
                }
                response = web.json_response(response_data, status=200)
                await add_server_signature_to_response(response, token)
                return response
            
            # Шаг 9: Загрузка файла в облачное хранилище
            cloud_link = None
            if config.cloud_enabled:
                try:
                    cloud_link = await upload_to_cloud(temp_file_path, file_name)
                    
                    if not cloud_link:
                        response_data = {
                            "status": "error",
                            "message": "Ошибка загрузки файла в облачное хранилище"
                        }
                        response = web.json_response(response_data, status=200)
                        await add_server_signature_to_response(response, token)
                        return response
                    
                    if verbose_mode:
                        print_status("OK", f"Файл загружен в облако", cloud_link)
                except Exception as e:
                    response_data = {
                        "status": "error",
                        "message": f"Ошибка загрузки файла в облако: {str(e)}"
                    }
                    response = web.json_response(response_data, status=200)
                    await add_server_signature_to_response(response, token)
                    return response
            else:
                if verbose_mode:
                    print_status("INFO", f"Облачное хранилище отключено")
            
            # Шаг 10: Сохранение метаданных файла в базу данных
            # Используем расширение файла в верхнем регистре для типа документа
            # doc_type = extension_lower.upper() if extension_lower else 'UNKNOWN'
            
            save_result = await db_setdocument(user_id_int, name, doc_type, cloud_link, description)
            
            if save_result["success"]:
                response_data = {
                    "status": "success",
                    "link": cloud_link or f"https://example.com/documents/{save_result['record_id']}"
                }
                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    print_status("OK", f"Файл успешно сохранен", 
                                f"ID: {save_result['record_id']}, тип: {doc_type}, ссылка: {response_data['link']}")
            else:
                response_data = {
                    "status": "error", 
                    "message": save_result["message"]
                }
                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    print_status("ERROR", f"Ошибка сохранения файла", save_result["message"])
        
        # Шаг 11: Добавление серверной подписи к ответу
        await add_server_signature_to_response(response, token)
        if verbose_mode:
            print_status("OK", f"Добавлена серверная подпись к ответу")
        
        return response
        
    except web.HTTPException as he:
        response_data = {
            "status": "error",
            "message": he.text
        }
        response = web.json_response(response_data, status=he.status)
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', None))
        return response
        
    except json.JSONDecodeError as e:
        response_data = {
            "status": "error",
            "message": "Невалидный JSON в теле запроса"
        }
        response = web.json_response(response_data, status=200)
        auth_header = request.headers.get("Token", "")
        token_for_signature = auth_header[7:] if auth_header.startswith("Bearer ") else "json_error"
        await add_server_signature_to_response(response, token_for_signature)
        return response
        
    except Exception as e:
        response_data = {
            "status": "error",
            "message": f"Ошибка при сохранении файла: {str(e)}"
        }
        response = web.json_response(response_data, status=200)
        auth_header = request.headers.get("Token", "")
        token_for_signature = auth_header[7:] if auth_header.startswith("Bearer ") else "unexpected_error"
        await add_server_signature_to_response(response, token_for_signature)
        return response
        
    finally:
        # Шаг 12: Очистка временных файлов
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
                if verbose_mode:
                    print_status("INFO", f"Временный файл удален", temp_file_path)
            except Exception as e:
                if verbose_mode:
                    print_status("ERROR", f"Ошибка удаления временного файла", str(e))
                if config.is_log_to_file_enabled():
                    asyncio.create_task(log_to_file('ERROR', 
                        f"Ошибка удаления временного файла {temp_file_path}: {str(e)}"))
                    
async def get_documentsigned(request: web.Request) -> web.Response:
    """
    Название: get_documentsigned
    Назначение: Эндпоинт для обновления статуса подписания документа
    Описание: Принимает document_id и is_signed, обновляет статус в БД через хранимую процедуру
    Принцип работы: Проверяет входные данные, вызывает хранимую процедуру, возвращает результат
    Входящие параметры: request - HTTP запрос с JSON телом содержащим document_id и is_signed
    Исходящие параметры: web.Response - JSON ответ с кодом статуса и результатом операции
    """
    try:
        # Аутентификация по токену (с проверкой подписи клиента)
        token = await authenticate_request(request)
        if verbose_mode:
            print_status("OK", f"Аутентификация пройдена", f"токен {token[:8]}...")
        
        # Парсим JSON тело запроса
        data = await request.json()
        if verbose_mode:
            print_status("INFO", f"Получены данные для обновления статуса документа", str(data))
        
        # УНИВЕРСАЛЬНАЯ ПРОВЕРКА ОБЯЗАТЕЛЬНЫХ ПАРАМЕТРОВ
        validation_result = validate_required_params(data, ['document_id', 'is_signed'])
        
        if validation_result['status'] == 'error':
            # ВОЗВРАЩАЕМ ОТВЕТ В ЕДИНОМ СТАНДАРТЕ С КОДОМ 200
            response = web.json_response(validation_result, status=200)
            if verbose_mode:
                print_status("ERROR", f"Ошибка валидации параметров", validation_result['message'])
        else:
            document_id = data['document_id']
            is_signed = data['is_signed']
            
            if verbose_mode:
                status_text = "подписан" if is_signed else "отклонен"
                print_status("INFO", f"Обновление статуса документа", 
                            f"document_id: {document_id}, статус: {status_text}")
            
            # Проверяем тип is_signed
            if not isinstance(is_signed, bool):
                response_data = {
                    "status": "error",
                    "message": "Параметр is_signed должен быть boolean (true/false)"
                }
                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    print_status("ERROR", f"Неверный тип is_signed", type(is_signed).__name__)
            else:
                # Обновляем статус документа в базе данных
                update_success = await db_documentsigned(document_id, is_signed)
                
                if update_success:
                    response_data = {
                        "status": "success"
                    }
                    response = web.json_response(response_data, status=200)
                    if verbose_mode:
                        print_status("OK", f"Статус документа {document_id} успешно обновлен")
                else:
                    response_data = {
                        "status": "error", 
                        "message": "Ошибка обновления статуса документа. Документ не найден или ошибка в БД."
                    }
                    response = web.json_response(response_data, status=200)
                    if verbose_mode:
                        print_status("ERROR", f"Ошибка обновления статуса документа {document_id}")
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи к заголовкам ответа
        await add_server_signature_to_response(response, token)
        if verbose_mode:
            print_status("OK", f"Добавлена серверная подпись к ответу")
        
        return response
        
    except web.HTTPException as he:
        # Перехватываем HTTP исключения (403, 404 и т.д.) и добавляем подпись
        response_data = {
            "status": "error",
            "message": he.text
        }
        response = web.json_response(response_data, status=he.status)
        if verbose_mode:
            print_status("ERROR", f"HTTP исключение в get_documentsigned",
                        data_lines=[
                            f"Статус: {he.status}",
                            f"Текст: {he.text}"
                        ])
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', None))
        return response
    except json.JSONDecodeError as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка декодирования JSON", str(e))
        response_data = {
            "status": "error",
            "message": "Невалидный JSON в теле запроса"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "json_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка в get_documentsigned", str(e))
            import traceback
            traceback.print_exc()
        response_data = {
            "status": "error",
            "message": f"Ошибка при обновлении статуса документа: {str(e)}"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "unexpected_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response


async def get_documentlist(request: web.Request) -> web.Response:
    """
    Название: get_documentlist
    Назначение: Эндпоинт для получения списка документов пользователя
    Описание: Принимает user_id, возвращает список документов с серверной подписью
    Принцип работы: Проверяет входные данные, получает документы из БД, формирует ответ с подписью
    Входящие параметры: request - HTTP запрос с JSON телом содержащим user_id
    Исходящие параметры: web.Response - JSON ответ с кодом статуса, данными документов и подписью сервера
    """
    try:
        # Аутентификация по токену (с проверкой подписи клиента)
        token = await authenticate_request(request)
        if verbose_mode:
            print_status("OK", f"Аутентификация пройдена", f"токен {token[:8]}...")
        
        # Парсим JSON тело запроса
        data = await request.json()
        if verbose_mode:
            print_status("INFO", f"Получены данные для получения списка документов", str(data))
        
        # УНИВЕРСАЛЬНАЯ ПРОВЕРКА ОБЯЗАТЕЛЬНЫХ ПАРАМЕТРОВ
        validation_result = validate_required_params(data, ['user_id'])
        
        if validation_result['status'] == 'error':
            # ВОЗВРАЩАЕМ ОТВЕТ В ЕДИНОМ СТАНДАРТЕ С КОДОМ 200
            response = web.json_response(validation_result, status=200)
            if verbose_mode:
                print_status("ERROR", f"Ошибка валидации параметров", validation_result['message'])
        else:
            user_id = data['user_id']

            # ПРОВЕРКА СУЩЕСТВОВАНИЯ ПОЛЬЗОВАТЕЛЯ
            user_exists = await db_userid(user_id)
            if not user_exists:
                raise Exception(f"Пользователь с ID {user_id} не найден")            
            
            if verbose_mode:
                print_status("INFO", f"Поиск документов пользователя", f"user_id: {user_id}")
            
            # Получаем документы из базы данных
            documents = await db_documentlist(user_id)
            
            if verbose_mode:
                print_status("INFO", f"Получено документов из БД", str(len(documents)))
                
                # Дополнительная информация для отладки
                if documents:
                    print(f"  Пример документа: {documents[0].get('id', 'N/A')} - {documents[0].get('name', 'N/A')}")
                    print(f"  Подписан: {documents[0].get('is_signed', False)}")
            
            # Формируем успешный ответ
            if documents:
                response_data = {
                    "status": "success",
                    "items": documents
                }
            else:
                response_data = {
                    "status": "success",
                    "items":[]
                }

            response = web.json_response(response_data)
            if verbose_mode:
                print_status("OK", f"Успешно возвращено документов", str(len(documents)))
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи к заголовкам ответа
        await add_server_signature_to_response(response, token)
        if verbose_mode:
            print_status("OK", f"Добавлена серверная подпись к ответу")
        
        return response
        
    except web.HTTPException as he:
        # Перехватываем HTTP исключения (403, 404 и т.д.) и добавляем подпись
        response_data = {
            "status": "error",
            "message": he.text
        }
        response = web.json_response(response_data, status=he.status)
        if verbose_mode:
            print_status("ERROR", f"HTTP исключение в get_documentlist",
                        data_lines=[
                            f"Статус: {he.status}",
                            f"Текст: {he.text}"
                        ])
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', None))
        return response
    except json.JSONDecodeError as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка декодирования JSON", str(e))
        response_data = {
            "status": "error",
            "message": "Невалидный JSON в теле запроса"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "json_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка в get_documentlist", str(e))
            import traceback
            traceback.print_exc()
        response_data = {
            "status": "error",
            "message": f"Ошибка при получении списка документов: {str(e)}"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "unexpected_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response



async def get_useremailing(request: web.Request) -> web.Response:
    """
    Название: get_useremailing
    Назначение: Эндпоинт для управления согласием на email рассылку пользователя
    Описание: Принимает user_id и consent_to_mailing, обновляет настройки рассылки в БД
    Принцип работы: Проверяет входные данные, вызывает хранимую процедуру, возвращает результат
    Входящие параметры: request - HTTP запрос с JSON телом содержащим user_id и consent_to_mailing
    Исходящие параметры: web.Response - JSON ответ с кодом статуса и результатом операции
    """
    try:
        # Аутентификация по токену (с проверкой подписи клиента)
        token = await authenticate_request(request)
        if verbose_mode:
            print_status("OK", f"Аутентификация пройдена", f"токен {token[:8]}...")
        
        # Парсим JSON тело запроса
        data = await request.json()
        if verbose_mode:
            print_status("INFO", f"Получены данные для обновления согласия на рассылку", str(data))
        
        # УНИВЕРСАЛЬНАЯ ПРОВЕРКА ОБЯЗАТЕЛЬНЫХ ПАРАМЕТРОВ
        validation_result = validate_required_params(data, ['user_id', 'consent_to_mailing'])
        
        if validation_result['status'] == 'error':
            # ВОЗВРАЩАЕМ ОТВЕТ В ЕДИНОМ СТАНДАРТЕ С КОДОМ 200
            response = web.json_response(validation_result, status=200)
            if verbose_mode:
                print_status("ERROR", f"Ошибка валидации параметров", validation_result['message'])
        else:
            user_id = data['user_id']
            consent_to_mailing = data['consent_to_mailing']

            # ПРОВЕРКА СУЩЕСТВОВАНИЯ ПОЛЬЗОВАТЕЛЯ
            user_exists = await db_userid(user_id)
            if not user_exists:
                raise Exception(f"Пользователь с ID {user_id} не найден")            
            
            if verbose_mode:
                consent_text = "согласие получено" if consent_to_mailing else "отказ от рассылки"
                print_status("INFO", f"Обновление согласия на рассылку", 
                            f"user_id: {user_id}, статус: {consent_text}")
            
            # Проверяем тип consent_to_mailing
            if not isinstance(consent_to_mailing, bool):
                response_data = {
                    "status": "error",
                    "message": "Параметр consent_to_mailing должен быть boolean (true/false)"
                }
                response = web.json_response(response_data, status=200)
                if verbose_mode:
                    print_status("ERROR", f"Неверный тип consent_to_mailing", type(consent_to_mailing).__name__)
            else:
                # Преобразуем user_id в число
                try:
                    user_id_int = int(user_id)
                except (ValueError, TypeError):
                    response_data = {
                        "status": "error",
                        "message": "Параметр user_id должен быть числом"
                    }
                    response = web.json_response(response_data, status=200)
                    if verbose_mode:
                        print_status("ERROR", f"Неверный формат user_id", user_id)
                else:
                    # Обновляем согласие на рассылку в базе данных
                    update_success = await db_useremailing(user_id_int, consent_to_mailing)
                    
                    if update_success:
                        response_data = {
                            "status": "success"
                        }
                        response = web.json_response(response_data, status=200)
                        if verbose_mode:
                            print_status("OK", f"Согласие на рассылку для пользователя {user_id} успешно обновлено")
                    else:
                        response_data = {
                            "status": "error", 
                            "message": "Ошибка обновления согласия на рассылку. Пользователь не найден или ошибка в БД."
                        }
                        response = web.json_response(response_data, status=200)
                        if verbose_mode:
                            print_status("ERROR", f"Ошибка обновления согласия на рассылку для пользователя {user_id}")
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи к заголовкам ответа
        await add_server_signature_to_response(response, token)
        if verbose_mode:
            print_status("OK", f"Добавлена серверная подпись к ответу")
        
        return response
        
    except web.HTTPException as he:
        # Перехватываем HTTP исключения (403, 404 и т.д.) и добавляем подпись
        response_data = {
            "status": "error",
            "message": he.text
        }
        response = web.json_response(response_data, status=he.status)
        if verbose_mode:
            print_status("ERROR", f"HTTP исключение в get_useremailing",
                        data_lines=[
                            f"Статус: {he.status}",
                            f"Текст: {he.text}"
                        ])
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', None))
        return response
    except json.JSONDecodeError as e:
        if verbose_mode:
            print_status("ERROR", f"Ошибка декодирования JSON", str(e))
        response_data = {
            "status": "error",
            "message": "Невалидный JSON в теле запроса"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "json_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка в get_useremailing", str(e))
            import traceback
            traceback.print_exc()
        response_data = {
            "status": "error",
            "message": f"Ошибка при обновлении согласия на рассылку: {str(e)}"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = "unexpected_error"
        if auth_header.startswith("Bearer "):
            token_for_signature = auth_header[7:]
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
    
# --- ОБРАБОТЧИК ЭНДПОИНТА ДЛЯ РАСЧЕТА РАСПРЕДЕЛЕНИЯ ПЛАТЕЖА ---

async def get_payment_calculate_distribution(request: web.Request) -> web.Response:
    """
    Название: get_payment_calculate_distribution
    Назначение: Эндпоинт для расчета распределения платежа по залоговым билетам
    Описание: Принимает массив платежей, проверяет их валидность,
              передает в функцию db_calculate_payment_distribution и форматирует ответ
    Принцип работы: 
        1. Проверяет валидность JSON формата
        2. Принимает как объект с полем 'payments' или как массив напрямую
        3. Передает строку в db_calculate_payment_distribution
        4. Добавляет поле status к ответу
        5. Формирует ответ в требуемом формате
    Входящие параметры: request - HTTP запрос с JSON телом
    Исходящие параметры: web.Response - JSON ответ с результатом расчета
    """
    try:
        # Аутентификация по токену (с проверкой подписи клиента)
        token = await authenticate_request(request)
        if verbose_mode:
            print_status("OK", f"Аутентификация пройдена", f"токен {token[:8]}...")
        
        # Получаем тело запроса как строку для проверки JSON валидности
        raw_body = await request.read()
        
        # Шаг 1: Проверка валидности JSON формата
        try:
            # Пробуем декодировать и проверить структуру JSON
            json_str = raw_body.decode('utf-8')
            json_data = json.loads(json_str)
            
            if verbose_mode:
                print_status("OK", f"JSON валиден", f"длина: {len(json_str)} символов")
                print(f"  Тип полученных данных: {type(json_data).__name__}")
                
        except json.JSONDecodeError as e:
            if verbose_mode:
                print_status("ERROR", f"Невалидный JSON в теле запроса", str(e))
            
            response_data = {
                "status": "error",
                "message": f"Невалидный JSON формат: {str(e)}"
            }
            response = web.json_response(response_data, status=200)
            await add_server_signature_to_response(response, token)
            return response
        except UnicodeDecodeError as e:
            if verbose_mode:
                print_status("ERROR", f"Ошибка декодирования тела запроса", str(e))
            
            response_data = {
                "status": "error",
                "message": "Тело запроса должно быть в UTF-8 кодировке"
            }
            response = web.json_response(response_data, status=200)
            await add_server_signature_to_response(response, token)
            return response
        
        # Шаг 2: Обработка разных форматов входных данных
        payments_data = None
        
        if isinstance(json_data, list):
            # Если пришел массив напрямую - используем его как платежи
            if verbose_mode:
                print_status("INFO", f"Получен массив платежей", f"количество: {len(json_data)}")
            payments_data = json_data
        elif isinstance(json_data, dict):
            # Если пришел объект - ищем поле 'payments'
            if 'payments' in json_data and isinstance(json_data['payments'], list):
                if verbose_mode:
                    print_status("INFO", f"Получен объект с полем 'payments'", 
                               f"количество: {len(json_data['payments'])}")
                payments_data = json_data['payments']
            else:
                # Проверяем, может ли объект быть интерпретирован как платеж
                if 'ticket_id' in json_data and 'amount' in json_data:
                    if verbose_mode:
                        print_status("INFO", f"Получен одиночный платеж как объект")
                    payments_data = [json_data]
                else:
                    # Попробуем обработать объект как есть
                    if verbose_mode:
                        print_status("INFO", f"Передаем объект как есть", 
                                   f"поля: {list(json_data.keys())}")
                    payments_data = json_data
        else:
            if verbose_mode:
                print_status("ERROR", f"Неверный формат данных", 
                           f"ожидался массив или объект, получен: {type(json_data).__name__}")
            
            response_data = {
                "status": "error",
                "message": f"Неверный формат данных: ожидался массив или объект"
            }
            response = web.json_response(response_data, status=200)
            await add_server_signature_to_response(response, token)
            return response
        
        # Шаг 3: Подготовка данных для передачи в БД
        try:
            if verbose_mode:
                if isinstance(payments_data, list):
                    print_status("INFO", f"Подготовка данных для передачи в БД", 
                               f"количество платежей: {len(payments_data)}")
                    for i, payment in enumerate(payments_data[:3]):  # Выводим первые 3 для отладки
                        print(f"  Платеж {i+1}: {payment.get('ticket_id', 'N/A')} - {payment.get('amount', 'N/A')}")
                else:
                    print_status("INFO", f"Подготовка данных для передачи в БД", 
                               f"тип: {type(payments_data).__name__}")
            
            # Конвертируем данные обратно в JSON строку для передачи в БД
            # Важно: передаем payments_data как есть, функция БД сама решит как обрабатывать
            json_for_db = json.dumps(payments_data, ensure_ascii=False)
            
            if verbose_mode:
                print_status("INFO", f"Передача JSON строки в базу данных", 
                           f"длина: {len(json_for_db)} символов")
            
            # Передаем JSON строку в функцию (как есть, без изменений)
            result_json_str = await db_calculate_payment_distribution(json_for_db)
            
            if verbose_mode:
                print_status("OK", f"Получен результат от базы данных", 
                           f"длина: {len(result_json_str)} символов")
            
            # Шаг 4: Парсим результат для добавления поля status
            try:
                result_data = json.loads(result_json_str)
                
                # Формируем финальный ответ с полем status
                response_data = {
                    "status": "success",
                    "tickets": result_data  # результат функции db_calculate_payment_distribution
                }
                
                response = web.json_response(response_data, status=200)
                
                if verbose_mode:
                    print_status("OK", f"Сформирован ответ", 
                               f"количество тикетов: {len(result_data) if isinstance(result_data, list) else 'один'}")
                    
            except json.JSONDecodeError as e:
                if verbose_mode:
                    print_status("ERROR", f"Ошибка парсинга результата из БД", str(e))
                    print(f"  Результат (первые 500 символов): {result_json_str[:500]}")
                
                response_data = {
                    "status": "error",
                    "message": f"Ошибка обработки результата из базы данных: {str(e)}"
                }
                response = web.json_response(response_data, status=200)
        
        except Exception as e:
            if verbose_mode:
                print_status("ERROR", f"Ошибка при расчете распределения платежа", str(e))
            
            response_data = {
                "status": "error",
                "message": f"Ошибка расчета распределения платежа: {str(e)}"
            }
            response = web.json_response(response_data, status=200)
        
        # Шаг 5: ГАРАНТИРОВАННОЕ добавление серверной подписи к заголовкам ответа
        await add_server_signature_to_response(response, token)
        if verbose_mode:
            print_status("OK", f"Добавлена серверная подпись к ответу")
        
        return response
        
    except web.HTTPException as he:
        # Перехватываем HTTP исключения (403, 404 и т.д.)
        response_data = {
            "status": "error",
            "message": he.text
        }
        response = web.json_response(response_data, status=he.status)
        if verbose_mode:
            print_status("ERROR", f"HTTP исключение в get_payment_calculate_distribution",
                        data_lines=[
                            f"Статус: {he.status}",
                            f"Текст: {he.text}"
                        ])
        await add_server_signature_to_response(response, getattr(request, 'authenticated_token', None))
        return response
        
    except Exception as e:
        if verbose_mode:
            print_status("ERROR", f"Неожиданная ошибка в get_payment_calculate_distribution", str(e))
            import traceback
            traceback.print_exc()
        
        response_data = {
            "status": "error",
            "message": f"Внутренняя ошибка сервера: {str(e)}"
        }
        response = web.json_response(response_data, status=200)
        
        # ГАРАНТИРОВАННОЕ добавление серверной подписи даже к ошибке
        auth_header = request.headers.get("Token", "")
        token_for_signature = auth_header[7:] if auth_header.startswith("Bearer ") else "unexpected_error"
        await add_server_signature_to_response(response, token_for_signature)
        
        return response
    
# --- СЛУЖЕБНЫЕ ОБРАБОТЧИКИ ---

async def options_handler(request):
    """
    Название: options_handler
    Назначение: Обработчик CORS preflight OPTIONS запросов
    Описание: Обрабатывает предварительные OPTIONS запросы для CORS, разрешая междоменные запросы
    Принцип работы: Возвращает пустой ответ с CORS заголовками для проверки разрешений до отправки основного запроса
    Входящие параметры: request - объект HTTP OPTIONS запроса
    Исходящие параметры: web.Response - пустой ответ с CORS заголовками
    """
    return web.Response()

async def favicon_handler(request):
    """
    Название: favicon_handler
    Назначение: Обработчик запросов к favicon.ico
    Описание: Возвращает стандартный ответ 404 для запросов к favicon.ico с серверной подписью
    Принцип работы: Создает HTTP 404 ответ с JSON сообщением и добавляет серверную подпись
    Входящие параметры: request - объект HTTP запроса к favicon.ico
    Исходящие параметры: web.Response - JSON ответ с кодом 404 и серверной подписью
    """
    return web.HTTPNotFound(text=json.dumps({
        "status": "error",
        "message": "Эндпоинт не найден"
    }), content_type='application/json')


# --- ФУНКЦИЯ ПРОВЕРКИ СТАТУСА СЕРВЕРА ---

def check_server_status():
    """
    Название: check_server_status
    Назначение: Комплексная проверка статуса работы сервера без его запуска
    Описание: Анализирует конфигурацию сервера, проверяет доступность всех компонентов
              (безопасность, БД, облако, логирование) и выводит детальную диагностическую
              информацию в структурированном виде
    Принцип работы:
      1. Загружает конфигурацию из файла config.json
      2. Проверяет текущий статус сервера (запущен/остановлен)
      3. Анализирует конфигурацию безопасности (ключи, токены, подписи)
      4. Проверяет доступность базы данных
      5. Проверяет конфигурацию облачного хранилища
      6. Анализирует настройки логирования
      7. Проверяет конфигурацию CORS
      8. Выводит список доступных эндпоинтов
      9. Формирует сводную информацию о состоянии системы
    Особенности:
      - Определяет PID запущенного сервера через системные утилиты (ss/netstat)
      - Проверяет корректность всех путей к файлам (ключи, лог-файлы)
      - Тестирует подключение к базе данных
      - Выявляет критические проблемы, препятствующие запуску
      - Предоставляет диагностические рекомендации
    Входящие параметры: Отсутствуют
    Исходящие параметры: Отсутствуют (побочный эффект - вывод информации в консоль)
    Зависимости:
      - Требует наличия файла config.json в текущей директории
      - Использует системные утилиты ss или netstat для проверки портов
      - Использует ps для получения информации о процессе
    """
    global config
    
    # Шаг 1: Заголовок и инициализация
    print(f"{Colors.BOLD}СТАТУС СЕРВЕРА SECURE DATA EXCHANGE{Colors.RESET}")
    print("=" * 50)
    
    # Загрузка конфигурации из файла
    config_path = 'config.json'
    if not os.path.exists(config_path):
        print_status("ERROR", f"Файл конфигурации не найден", config_path)
        print(f"  Убедитесь что файл {config_path} находится в текущей директории:")
        print(f"  {os.getcwd()}")
        return
    
    try:
        # Чтение и парсинг JSON конфигурации
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        
        # Создание объекта конфигурации
        config = Config(config_data)
        print_status("OK", f"Конфигурация загружена", config_path)
        
    except json.JSONDecodeError as e:
        # Ошибка формата JSON в конфигурационном файле
        print_status("ERROR", f"Ошибка формата JSON в файле конфигурации", str(e))
        print(f"  Проверьте синтаксис файла {config_path}")
        return
    except Exception as e:
        # Любые другие ошибки при загрузке конфигурации
        print_status("ERROR", f"Ошибка загрузки конфигурации", str(e))
        return

    # Шаг 2: Проверка текущего статуса сервера (запущен/остановлен)
    # Используем системные утилиты для определения процесса, слушающего порт
    server_status = "ВЫКЛЮЧЕН"
    status_color = Colors.LIGHT_RED
    pid_info = ""
    server_process_info = ""
    
    try:
        import subprocess
        import re
        
        # Проверяем через ss (современная утилита, доступна в большинстве дистрибутивов)
        result = subprocess.run(
            ['ss', '-tlnp'], 
            capture_output=True, 
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            # Ищем процесс, который слушает наш порт из конфигурации
            port_pattern = f":{config.port}\\s"
            for line in result.stdout.split('\n'):
                if re.search(port_pattern, line) and "LISTEN" in line:
                    # Извлекаем PID из вывода ss
                    pid_match = re.search(r'pid=(\d+)', line)
                    if pid_match:
                        pid = pid_match.group(1)
                        # Получаем детальную информацию о процессе
                        ps_result = subprocess.run(
                            ['ps', '-p', pid, '-o', 'pid,user,etime,cmd', '--no-headers'],
                            capture_output=True, 
                            text=True,
                            timeout=5
                        )
                        if ps_result.returncode == 0 and ps_result.stdout.strip():
                            process_info = ps_result.stdout.strip()
                            # Проверяем, это ли наш сервер
                            if 'server.py' in process_info or 'python' in process_info:
                                server_status = "ВКЛЮЧЕН"
                                status_color = Colors.LIGHT_GREEN
                                pid_info = f" (PID: {pid})"
                                
                                # Парсим информацию о процессе для детального вывода
                                parts = process_info.split(maxsplit=3)
                                if len(parts) >= 4:
                                    pid_num, user, etime, cmd = parts
                                    server_process_info = f"Пользователь: {user}, Время работы: {etime}"
                                break
    
    except Exception as e:
        # Если не удалось проверить через ss, пробуем через netstat (устаревший, но широко доступный)
        try:
            result = subprocess.run(
                ['netstat', '-tlnp'], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                port_pattern = f":{config.port}\\s"
                for line in result.stdout.split('\n'):
                    if re.search(port_pattern, line) and "LISTEN" in line:
                        # Извлекаем PID из вывода netstat
                        pid_match = re.search(r'(\d+)/python', line)
                        if pid_match:
                            pid = pid_match.group(1)
                            server_status = "ВКЛЮЧЕН"
                            status_color = Colors.LIGHT_GREEN
                            pid_info = f" (PID: {pid})"
                            break
        except:
            # Если обе утилиты недоступны, просто пропускаем проверку
            pass
    
    # Вывод информации о статусе сервера
    print(f"Состояние сервера: {status_color}{server_status}{pid_info}{Colors.RESET}")
    if server_process_info:
        print(f"  {server_process_info}")
    print("-" * 50)
    
    # Шаг 3: Основные параметры сервера
    print(f"\n{Colors.BOLD}ОСНОВНЫЕ ПАРАМЕТРЫ СЕРВЕРА:{Colors.RESET}")
    print_status("INFO", f"Адрес сервера", config.host)
    print_status("INFO", f"Порт", str(config.port))
    print_status("INFO", f"Режим отладки", "ВКЛЮЧЕН" if config.debug else "ВЫКЛЮЧЕН")
    print_status("INFO", f"URL сервера", f"http://{config.host}:{config.port}")

    # Шаг 4: Конфигурация безопасности
    print(f"\n{Colors.BOLD}КОНФИГУРАЦИЯ БЕЗОПАСНОСТИ:{Colors.RESET}")
    print_status("INFO", f"Сертификаты", "ВКЛЮЧЕНЫ" if not config.disable_certificates else "ОТКЛЮЧЕНЫ")
    print_status("INFO", f"Аутентификация по токену", "ВКЛЮЧЕНА" if not config.disable_token_auth else "ОТКЛЮЧЕНА")
    print_status("INFO", f"Проверка подписи", "ВКЛЮЧЕНА" if not config.disable_signature else "ОТКЛЮЧЕНА")
    print_status("INFO", f"TTL подписи", f"{config.signature_ttl} секунд")
    print_status("INFO", f"Количество разрешенных токенов", str(len(config.allowed_tokens)))

    if config.default_token_server:
        print_status("INFO", f"Токен сервера по умолчанию", "УСТАНОВЛЕН")
    else:
        print_status("INFO", f"Токен сервера по умолчанию", "НЕ УСТАНОВЛЕН")

    # Шаг 5: Конфигурация безопасности эндпоинтов
    if config.endpoint_security:
        print(f"\n{Colors.BOLD}БЕЗОПАСНОСТЬ ЭНДПОИНТОВ:{Colors.RESET}")
        for endpoint, security_level in config.endpoint_security.items():
            level_display = {
                'public': 'ПУБЛИЧНЫЙ',
                'token': 'ТОКЕН',
                'signature': 'ПОДПИСЬ',
                'disabled': 'ОТКЛЮЧЕН'
            }.get(security_level, security_level.upper())
            print_status("INFO", f"Эндпоинт /{endpoint}", level_display)

    # Шаг 6: Проверка ключей безопасности
    if not config.disable_certificates:
        print(f"\n{Colors.BOLD}ПРОВЕРКА КЛЮЧЕЙ БЕЗОПАСНОСТИ:{Colors.RESET}")
        server_key_exists = os.path.exists(config.server_private_key_path)
        client_key_exists = os.path.exists(config.client_public_key_path)

        if server_key_exists:
            print_status("OK", f"Приватный ключ сервера", config.server_private_key_path)
        else:
            print_status("ERROR", f"Приватный ключ сервера не найден", config.server_private_key_path)

        if client_key_exists:
            print_status("OK", f"Публичный ключ клиента", config.client_public_key_path)
        else:
            print_status("ERROR", f"Публичный ключ клиента не найден", config.client_public_key_path)
    else:
        print_status("INFO", f"Проверка ключей", "ОТКЛЮЧЕНА (сертификаты отключены в конфигурации)")

    # Шаг 7: Конфигурация базы данных
    print(f"\n{Colors.BOLD}КОНФИГУРАЦИЯ БАЗЫ ДАННЫХ:{Colors.RESET}")
    print_status("INFO", f"Сервер БД", f"{config.db_server}:{config.db_port}")
    print_status("INFO", f"Имя базы данных", config.db_name)
    print_status("INFO", f"Драйвер", config.db_driver)
    print_status("INFO", f"Имя пользователя", config.db_username or "НЕ УКАЗАНО")
    print_status("INFO", f"Пароль", "УСТАНОВЛЕН" if config.db_password else "НЕ УСТАНОВЛЕН")
    print_status("INFO", f"Таймаут подключения", f"{config.db_connection_timeout} секунд")
    print_status("INFO", f"Запуск без БД", "РАЗРЕШЕН" if config.allow_start_without_db else "ЗАПРЕЩЕН")
    print_status("INFO", f"Лимит выборки", f"{config.select_top} строк")
    print_status("INFO", f"Пуллинг соединений", "ВКЛЮЧЕН" if config.db_pooling_enabled else "ВЫКЛЮЧЕН")
    if config.db_pooling_enabled:
        print_status("INFO", f"Время жизни соединения", f"{config.db_connection_lifetime} сек")
        print_status("INFO", f"Размер пула", f"{config.db_min_pool_size}-{config.db_max_pool_size}")
    
    print_status("INFO", f"Фоновая проверка соединения", "ВКЛЮЧЕНА" if config.db_health_check_enabled else "ВЫКЛЮЧЕНА")
    if config.db_health_check_enabled:
        print_status("INFO", f"Интервал проверки", f"{config.db_health_check_interval} сек")

    # Шаг 8: Проверка подключения к базе данных
    try:
        conn_str = (
            f'DRIVER={{{config.db_driver}}};'
            f'SERVER={config.db_server},{config.db_port};'
            f'DATABASE={config.db_name};'
            f'UID={config.db_username};'
            f'PWD={config.db_password};'
            f'Encrypt=no;'
            f'TrustServerCertificate=yes;'
            f'Connection Timeout={config.db_connection_timeout};'
        )

        db_test = pyodbc.connect(conn_str)
        cursor = db_test.cursor()
        cursor.execute("SELECT @@VERSION")
        version_result = cursor.fetchone()
        db_version = version_result[0] if version_result else "неизвестно"
        db_test.close()
        print_status("OK", f"Подключение к базе данных", "УСПЕШНО")
        # Обрезаем длинную строку версии для читаемости
        if len(db_version) > 100:
            print_status("INFO", f"Версия сервера БД", db_version[:100] + "...")
        else:
            print_status("INFO", f"Версия сервера БД", db_version)
    except Exception as e:
        print_status("ERROR", f"Ошибка подключения к базе данных", str(e))

    # Шаг 9: Конфигурация логирования
    print(f"\n{Colors.BOLD}КОНФИГУРАЦИЯ ЛОГИРОВАНИЯ:{Colors.RESET}")
    print_status("INFO", f"Логирование в файл", "ВКЛЮЧЕНО" if config.is_log_to_file_enabled() else "ВЫКЛЮЧЕНО")
    if config.is_log_to_file_enabled():
        log_path = config.log_file_path
        if not os.path.isabs(log_path):
            log_path = os.path.join(os.getcwd(), log_path)
        print_status("INFO", f"Путь к файлу лога", log_path)
        # Проверяем доступность директории для логов
        log_dir = os.path.dirname(log_path)
        if not os.path.exists(log_dir):
            print_status("WARNING", f"Директория для логов не существует", log_dir)

    print_status("INFO", f"Логирование в БД", "ВКЛЮЧЕНО" if config.is_log_to_db_enabled() else "ВЫКЛЮЧЕНО")
    print_status("INFO", f"Логирование в консоль", "ВКЛЮЧЕНО (verbose mode)" if verbose_mode else "ВЫКЛЮЧЕНО")
    print_status("INFO", f"Маскирование данных", "ВКЛЮЧЕНО" if config.mask_sensitive_data else "ВЫКЛЮЧЕНО")

    # Формирование строки с уровнями логирования
    log_info = []
    if config.is_log_to_file_enabled():
        log_info.append(f"файл({','.join(config.log_to_file)})")
    if config.is_log_to_db_enabled():
        log_info.append(f"БД({','.join(config.log_to_db)})")

    log_levels_str = ", ".join(log_info) if log_info else "отключено"
    print_status("INFO", f"Уровни логирования", log_levels_str)

    # Шаг 10: Конфигурация CORS (Cross-Origin Resource Sharing)
    print(f"\n{Colors.BOLD}КОНФИГУРАЦИЯ CORS:{Colors.RESET}")
    print_status("INFO", f"CORS", "ВКЛЮЧЕН" if config.cors_enabled else "ВЫКЛЮЧЕН")
    if config.cors_enabled:
        origins = config.cors_allowed_origins
        if origins == ['*']:
            print_status("INFO", f"Разрешены домены", "ВСЕ (*)")
        else:
            print_status("INFO", f"Разрешены домены", ", ".join(origins))

        print_status("INFO", f"Разрешенные методы", ", ".join(config.cors_allowed_methods))
        print_status("INFO", f"Разрешенные заголовки", ", ".join(config.cors_allowed_headers))

        if config.cors_expose_headers:
            print_status("INFO", f"Экспортируемые заголовки", ", ".join(config.cors_expose_headers))

        print_status("INFO", f"Разрешены учетные данные", "ДА" if config.cors_allow_credentials else "НЕТ")
        print_status("INFO", f"Максимальное время кэша", f"{config.cors_max_age} секунд")

    # Шаг 11: Конфигурация облачного хранилища
    print(f"\n{Colors.BOLD}КОНФИГУРАЦИЯ ОБЛАЧНОГО ХРАНИЛИЩА:{Colors.RESET}")
    print_status("INFO", f"Облачное хранилище", "ВКЛЮЧЕНО" if config.cloud_enabled else "ВЫКЛЮЧЕНО")
    if config.cloud_enabled:
        print_status("INFO", f"URL облака", config.cloud_url)
        print_status("INFO", f"Путь загрузки", config.cloud_upload_path)
        print_status("INFO", f"Временная директория", config.cloud_temp_dir)
        print_status("INFO", f"Таймаут операций", f"{config.cloud_timeout} секунд")
        print_status("INFO", f"Максимальный размер файла", f"{config.max_upload_size} МБ")
        print_status("INFO", f"Запуск без облака", "РАЗРЕШЕН" if config.allow_start_without_cloud else "ЗАПРЕЩЕН")
        
        # Проверяем доступность временной директории
        if config.cloud_temp_dir and not os.path.exists(config.cloud_temp_dir):
            print_status("WARNING", f"Временная директория не существует", config.cloud_temp_dir)
    else:
        print_status("INFO", f"Облачное хранилище", "ОТКЛЮЧЕНО (файлы будут сохраняться только в БД)")

    # Шаг 12: Доступные эндпоинты сервера
    print(f"\n{Colors.BOLD}ДОСТУПНЫЕ ЭНДПОИНТЫ СЕРВЕРА:{Colors.RESET}")
    endpoints = [
        "GET    /health              # Основной health-check",
        "GET    /health/security     # Детальная информация о безопасности",
        "GET    /health/database     # Информация о базе данных", 
        "GET    /health/logging      # Информация о логировании",
        "GET    /health/network      # Сетевая информация и CORS",
        "GET    /health/cloud        # Состояние облачного хранилища",
        "GET    /health/stat         # Статистика работы сервера",
        "POST   /user/by-phone       # Поиск пользователя по телефону",
        "POST   /user/update         # Обновление данных пользователя",
        "POST   /user/mailing        # Управление email рассылкой",
        "POST   /ticket/list         # Получение списка залоговых билетов",
        "POST   /payment/set         # Обработка платежей",
        "POST   /payment/calculate-distribution  # Разбить платеж",        
        "POST   /user/login          # Аутентификация пользователя",
        "POST   /document/load       # Загрузка PDF документов",
        "POST   /document/signed     # Обновление статуса подписания документа",
        "POST   /document/list       # Получение списка документов",
        "GET    /help                # HTML справка по API"
    ]
    
    for endpoint in endpoints:
        # Разделяем строку на части для форматирования
        if '#' in endpoint:
            method_path, comment = endpoint.split('#', 1)
            method_path = method_path.strip()
            comment = comment.strip()
        else:
            method_path = endpoint.strip()
            comment = ""
        
        # Разделяем метод и путь
        parts = method_path.split(maxsplit=1)
        if len(parts) == 2:
            method, path = parts
            full_url = f"http://{config.host}:{config.port}{path}"
            if comment:
                print(f"  {method:6} {path:<25} {full_url}  # {comment}")
            else:
                print(f"  {method:6} {path:<25} {full_url}")
        else:
            print(f"  {method_path}")

    # Шаг 13: Сводная информация и диагностика проблем
    print(f"\n{Colors.BOLD}ДИАГНОСТИКА И СВОДНАЯ ИНФОРМАЦИЯ:{Colors.RESET}")

    # Определяем общий статус системы на основе критических проблем
    system_status = "ГОТОВ К РАБОТЕ"
    system_color = Colors.LIGHT_GREEN

    # Собираем критические проблемы, препятствующие запуску
    critical_issues = []

    # Проверка: наличие разрешенных токенов
    if not config.allowed_tokens:
        critical_issues.append("Нет разрешенных токенов (список allowed_tokens пуст)")

    # Проверка: ключи безопасности (если сертификаты включены)
    if not config.disable_certificates:
        if not os.path.exists(config.server_private_key_path):
            critical_issues.append(f"Отсутствует приватный ключ сервера: {config.server_private_key_path}")
        if not os.path.exists(config.client_public_key_path):
            critical_issues.append(f"Отсутствует публичный ключ клиента: {config.client_public_key_path}")

    # Проверка: подключение к базе данных (если запуск без БД запрещен)
    if not config.allow_start_without_db:
        try:
            conn_str = (
                f'DRIVER={{{config.db_driver}}};'
                f'SERVER={config.db_server},{config.db_port};'
                f'DATABASE={config.db_name};'
                f'UID={config.db_username};'
                f'PWD={config.db_password};'
                f'Encrypt=no;'
                f'TrustServerCertificate=yes;'
                f'Connection Timeout=5;'
            )
            db_test = pyodbc.connect(conn_str)
            cursor = db_test.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            db_test.close()
        except Exception as e:
            critical_issues.append(f"Нет подключения к базе данных: {str(e)}")

    # Проверка: временная директория для облачных загрузок (если облако включено)
    if config.cloud_enabled and config.cloud_temp_dir:
        temp_dir = config.cloud_temp_dir
        # Проверяем возможность создания/доступа к директории
        try:
            if not os.path.exists(temp_dir):
                # Проверяем, можем ли мы создать директорию
                test_path = os.path.join(temp_dir, "test_write.tmp")
                # Не создаем фактически, просто проверяем путь
                pass
        except Exception as e:
            critical_issues.append(f"Проблема с временной директорией {temp_dir}: {str(e)}")

    # Вывод информации о критических проблемах
    if critical_issues:
        system_status = "ТРЕБУЕТСЯ ВНИМАНИЕ"
        system_color = Colors.LIGHT_RED
        print_status("ERROR", f"Общий статус системы", system_status)
        print(f"  Обнаружены критические проблемы:")
        for i, issue in enumerate(critical_issues, 1):
            print(f"    {i}. {issue}")
    else:
        print_status("OK", f"Общий статус системы", system_status)

    # Шаг 14: Команды управления и справочная информация
    print(f"\n{Colors.BOLD}КОМАНДЫ УПРАВЛЕНИЯ СЕРВЕРОМ:{Colors.RESET}")
    print(f"  Запуск сервера:          python3 server.py config.json")
    print(f"  Запуск с подробным логом: python3 server.py config.json --verbose")
    print(f"  Проверка статуса:        python3 server.py --status")
    print(f"  Помощь по командам:      python3 server.py --help")

    print(f"\n{Colors.BOLD}СПРАВОЧНАЯ ИНФОРМАЦИЯ:{Colors.RESET}")
    print(f"  Конфигурационный файл:   {os.path.abspath(config_path)}")
    print(f"  Рабочая директория:      {os.getcwd()}")
    print(f"  Текущее время:           {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Информация о системе
    try:
        import platform
        print(f"  Операционная система:   {platform.system()} {platform.release()}")
        print(f"  Python версия:          {platform.python_version()}")
    except:
        pass

    # Шаг 15: Итоговое сообщение в зависимости от статуса
    if server_status == 'ВКЛЮЧЕН':
        final_color = Colors.LIGHT_GREEN
        final_message = "✓ Сервер запущен и работает корректно"
        # Дополнительная информация для запущенного сервера
        print(f"\n{Colors.BOLD}ДОПОЛНИТЕЛЬНЫЕ ДЕЙСТВИЯ:{Colors.RESET}")
        print(f"  • Проверить health-check: curl http://{config.host}:{config.port}/health")
        print(f"  • Посмотреть документацию: http://{config.host}:{config.port}/help")
        print(f"  • Проверить безопасность: http://{config.host}:{config.port}/health/security")
    else:
        final_color = Colors.LIGHT_RED  
        final_message = "⚙ Сервер готов к запуску"
        # Рекомендации для не запущенного сервера
        if not critical_issues:
            print(f"\n{Colors.BOLD}РЕКОМЕНДАЦИИ К ЗАПУСКУ:{Colors.RESET}")
            print(f"  • Запустите сервер командой: python3 server.py config.json")
            print(f"  • Для отладки используйте: python3 server.py config.json --verbose")
            print(f"  • После запуска проверьте: http://{config.host}:{config.port}/health")
    
    print(f"\n{final_color}{final_message}{Colors.RESET}")

# --- КОНФИГУРАЦИЯ И ИНИЦИАЛИЗАЦИЯ ---
    
async def init_app():
    """
    Название: init_app
    Назначение: Инициализация всего приложения и загрузка конфигурации
    Описание: Основная функция инициализации: парсит аргументы, загружает конфигурацию, инициализирует компоненты
    Принцип работы: Читает аргументы командной строки, загружает конфигурацию, инициализирует БД, ключи и логирование
    Входящие параметры: Отсутствуют
    Исходящие параметры: web.Application - полностью инициализированное веб-приложение
    """
    global config, private_key, public_key, verbose_mode, config_reload_interval, config_reload_task

    # Инициализация базового логирования для отладки запуска
    print_status("INFO", f"Начало инициализации приложения")

    parser = argparse.ArgumentParser(description='Secure Data Exchange Server')
    parser.add_argument('--config', '-c', help='Путь к файлу конфигурации')
    parser.add_argument('--verbose', '-v', action='store_true', help='Включить подробный режим')
    parser.add_argument('--status', action='store_true', help='Проверить статус сервера без запуска')
    parser.add_argument('--validate-config', action='store_true', help='Проверить конфигурационный файл и выйти')
    args = parser.parse_args()
    
    # Обработка флага --status
    if args.status:
        check_server_status()
        sys.exit(0)
    
    # Обработка флага --validate-config
    if args.validate_config:
        config_path = args.config or 'config.json'
        if validate_config_file(config_path):
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Если параметры не указаны, устанавливаем значения по умолчанию
    if args.config is None:
        args.config = 'config.json'
    if not args.verbose:
        args.verbose = False  # По умолчанию verbose выключен

    verbose_mode = args.verbose
    config_path = args.config
    
    if verbose_mode:
        print_status("INFO", f"Подробный режим включен")
        print_status("INFO", f"Используется файл конфигурации", config_path)
    
    # Сначала проверяем валидность конфигурационного файла
    if not validate_config_file(config_path):
        print_status("ERROR", f"Конфигурационный файл содержит ошибки", config_path)
        sys.exit(1)
    
    # === УПРОЩЕННАЯ ИНИЦИАЛИЗАЦИЯ ===
    # Просто вызываем reload_configuration для первоначальной загрузки
    if verbose_mode:
        print_status("INFO", f"Загрузка конфигурации из файла", config_path)
    
    if not await reload_configuration(config_path, is_initial_load=True):
        print_status("ERROR", f"Не удалось загрузить конфигурацию", config_path)
        sys.exit(1)
    
    if verbose_mode:
        print_status("OK", f"Конфигурация успешно загружена")
        print(f"  Хост: {config.host}")
        print(f"  Порт: {config.port}")
        print(f"  Режим отладки: {config.debug}")
    
    # Исправляем хост, если он содержит порт
    if ':' in config.host:
        host_parts = config.host.split(':')
        config.host = host_parts[0]
        if len(host_parts) > 1:
            try:
                config.port = int(host_parts[1])
                if verbose_mode:
                    print_status("INFO", f"Порт извлечен из хоста", f"{config.port}")
            except ValueError:
                print_status("INFO", f"Неверный формат порта в хосте", config.host)
    
    # Инициализация файлового логирования (ПЕРЕМЕЩЕНО ВЫШЕ - ДО загрузки ключей и БД)
    if verbose_mode:
        print_status("INFO", f"Инициализация файлового логирования")
    
    init_file_logging()
    
    if verbose_mode:
        if file_logger:
            print_status("OK", f"Файловое логирование инициализировано")
        else:
            print_status("INFO", f"Файловое логирование не требуется или не настроено")
    
    # Загрузка ключей только если сертификаты не отключены
    if not config.disable_certificates:
        if verbose_mode:
            print_status("INFO", f"Загрузка ключей безопасности")
        
        try:
            private_key = await load_private_key()
            public_key = await load_public_key()
            if verbose_mode:
                print_status("OK", f"Ключи безопасности загружены")
                print(f"  - Приватный ключ сервера: {config.server_private_key_path}")
                print(f"  - Публичный ключ клиента: {config.client_public_key_path}")
        except Exception as e:
            print_status("ERROR", f"Ошибка загрузки ключей", str(e))
            # Логируем ошибку в файл если возможно
            if file_logger:
                file_logger.error(f"Ошибка загрузки ключей безопасности: {str(e)}")
            sys.exit(1)
    else:
        if verbose_mode:
            print_status("INFO", f"Режим сертификатов отключен")
    
    # Инициализация БД с поддержкой автоматического восстановления соединения
    if verbose_mode:
        print_status("INFO", f"Инициализация подключения к базе данных")
    
    try:
        await init_database()
        if verbose_mode:
            if db_connection:
                print_status("OK", f"Подключение к базе данных установлено")
                print_status("INFO", f"Запущена фоновая проверка состояния соединения")
            else:
                print_status("INFO", f"Подключение к базе данных не требуется")
    except Exception as e:
        error_msg = f"Ошибка инициализации базы данных: {e}"
        
        # Логируем ошибку в файл если возможно
        if file_logger:
            file_logger.error(f"Ошибка инициализации БД: {str(e)}")
        
        if config.allow_start_without_db:
            print_status("ERROR", error_msg)
            if verbose_mode:
                print_status("INFO", f"Продолжение работы без базы данных...")
        else:
            print_status("ERROR", error_msg)
            print_status("ERROR", f"Запуск сервера запрещен (allow_start_without_db = false)")
            sys.exit(1)

    # Инициализация Облачного хранилища
    if verbose_mode:
        print_status("INFO", f"Проверка доступности облачного хранилища")

    try:
        cloud_available = await check_cloud_availability()
        if not cloud_available:
            if config.allow_start_without_cloud:
                print_status("WARNING", f"Облачное хранилище недоступно, но разрешен запуск без него")
            else:
                print_status("ERROR", f"Облачное хранилище недоступно")
                if not config.allow_start_without_cloud:
                    sys.exit(1)
    except Exception as e:
        error_msg = f"Ошибка проверки облачного хранилища: {e}"
        if config.allow_start_without_cloud:
            print_status("WARNING", error_msg)
            if verbose_mode:
                print_status("INFO", f"Продолжение работы без облачного хранилища...")
        else:
            print_status("ERROR", error_msg)
            print_status("ERROR", f"Запуск сервера запрещен (allow_start_without_cloud = false)")
            sys.exit(1)            
    
    # Запускаем задачу периодической перезагрузки конфигурации
    config_reload_interval = config.config_reload_interval_minutes
    
    if config_reload_interval > 0:
        config_reload_task = asyncio.create_task(start_config_reload_task())
        if verbose_mode:
            print_status("OK", f"Задача периодической перезагрузки конфигурации запущена")
            print(f"  Интервал перезагрузки: {config_reload_interval} минут")
    else:
        if verbose_mode:
            print_status("INFO", f"Периодическая перезагрузка конфигурации отключена")


    # Инициализация статистики
    init_statistics()

    # Создаем и возвращаем приложение
    if verbose_mode:
        print_status("INFO", f"Создание веб-приложения")
    
    app = await app_factory()
    
    if verbose_mode:
        print_status("OK", f"Веб-приложение успешно создано")
        print(f"  Зарегистрировано маршрутов: {len(app.router.routes())}")
    
    return app

async def reload_configuration(config_path: str = 'config.json', is_initial_load: bool = False) -> bool:
    """
    Название: reload_configuration
    Назначение: Загрузка и применение конфигурации из файла
    Описание: Читает конфигурационный файл и применяет настройки (используется при старте и периодической перезагрузке)
    Принцип работы: Читает файл конфигурации, создает новый объект Config и применяет все настройки
    Входящие параметры: 
        config_path - путь к файлу конфигурации
        is_initial_load - флаг первоначальной загрузки (для специальной обработки)
    Исходящие параметры: bool - True если конфигурация успешно применена, False при ошибке
    """
    global config, last_config_reload_time
    
    if verbose_mode and not is_initial_load:
        print_status("INFO", f"Начало перезагрузки конфигурации")
    
    try:
        if not os.path.exists(config_path):
            print_status("ERROR", f"Файл конфигурации не найден", config_path)
            return False
        
        # Читаем файл с обработкой ошибок кодировки
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            print_status("ERROR", f"Ошибка кодировки файла конфигурации", "Файл должен быть в UTF-8")
            return False
        
        # Проверяем базовый синтаксис файла
        if not content.strip():
            print_status("ERROR", f"Файл конфигурации пуст", config_path)
            return False
        
        # Парсим JSON с подробной информацией об ошибках
        try:
            config_data = json.loads(content)
        except json.JSONDecodeError as e:
            print_status("ERROR", f"Ошибка формата JSON в файле конфигурации", str(e))
            
            # Показываем контекст ошибки
            lines = content.split('\n')
            error_line = e.lineno if hasattr(e, 'lineno') else 0
            error_col = e.colno if hasattr(e, 'colno') else 0
            
            if error_line > 0 and error_line <= len(lines):
                problematic_line = lines[error_line - 1]
                print(f"  Ошибка в строке {error_line}, столбец {error_col}:")
                print(f"  {problematic_line}")
                if error_col > 0:
                    print(f"  {' ' * (error_col - 1)}^")
            
            return False
        
        # Создаем новый объект конфигурации
        try:
            new_config = Config(config_data)
        except Exception as e:
            print_status("ERROR", f"Ошибка создания объекта конфигурации", str(e))
            return False
        
        # Сохраняем старую конфигурацию для сравнения (если это не первая загрузка)
        old_config = config
        
        # === КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: ОБНОВЛЯЕМ ГЛОБАЛЬНУЮ КОНФИГУРАЦИЮ ===
        if is_initial_load or old_config is None:
            # Первая загрузка - просто присваиваем новый объект
            config = new_config
            if verbose_mode:
                print_status("OK", f"Первоначальная загрузка конфигурации выполнена")
        else:
            # Перезагрузка - полностью заменяем объект конфигурации
            config = new_config
            if verbose_mode:
                print_status("OK", f"Конфигурация успешно перезагружена")
                # Логируем основные изменения
                _log_configuration_changes(old_config, new_config)
        
        # Обновляем интервал перезагрузки конфигурации
        global config_reload_interval
        config_reload_interval = config.config_reload_interval_minutes
        
        # Обновляем время последней перезагрузки
        last_config_reload_time = datetime.now()
        
        if verbose_mode and not is_initial_load:
            print(f"  Следующая перезагрузка через: {format_time_remaining(config_reload_interval)}")
        
        # Переинициализируем файловое логирование если нужно (только при изменениях)
        if config.log_to_file and (is_initial_load or not old_config or 
                                 (old_config and (old_config.log_file_path != new_config.log_file_path or
                                  old_config.log_level != new_config.log_level))):
            init_file_logging()
            
        # Перезагружаем ключи безопасности если изменились настройки сертификатов
        if not is_initial_load and old_config and not config.disable_certificates:
            await _reload_security_keys(old_config, new_config)
        
        return True
        
    except Exception as e:
        error_msg = "загрузки" if is_initial_load else "перезагрузки"
        print_status("ERROR", f"Неожиданная ошибка {error_msg} конфигурации", str(e))
        if verbose_mode:
            import traceback
            traceback.print_exc()
        return False
    
def validate_config_file(config_path: str = 'config.json') -> bool:
    """
    Название: validate_config_file
    Назначение: Проверка валидности конфигурационного файла
    Описание: Проверяет синтаксис JSON и базовую структуру конфигурационного файла
    Принцип работы: Читает файл, парсит JSON и проверяет обязательные поля
    Входящие параметры: config_path - путь к файлу конфигурации
    Исходящие параметры: bool - True если файл валиден, False если есть ошибки
    """
    try:
        if not os.path.exists(config_path):
            print_status("ERROR", f"Файл конфигурации не найден", config_path)
            return False
        
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if not content.strip():
            print_status("ERROR", f"Файл конфигурации пуст", config_path)
            return False
        
        # Парсим JSON
        config_data = json.loads(content)
        
        # Проверяем обязательные поля
        required_fields = ['host', 'port']
        for field in required_fields:
            if field not in config_data:
                print_status("ERROR", f"Отсутствует обязательное поле", field)
                return False
        
        # Проверяем структуру безопасности
        if 'security' in config_data:
            security = config_data['security']
            if 'allowed_tokens' in security and not security['allowed_tokens']:
                print_status("ERROR", f"Список allowed_tokens не может быть пустым")
                return False
        
        print_status("OK", f"Конфигурационный файл валиден", config_path)
        return True
        
    except json.JSONDecodeError as e:
        print_status("ERROR", f"Ошибка формата JSON", str(e))
        
        # Показываем контекст ошибки
        lines = content.split('\n')
        error_line = e.lineno if hasattr(e, 'lineno') else 0
        error_col = e.colno if hasattr(e, 'colno') else 0
        
        if error_line > 0 and error_line <= len(lines):
            problematic_line = lines[error_line - 1]
            print(f"  Ошибка в строке {error_line}, столбец {error_col}:")
            print(f"  {problematic_line}")
            if error_col > 0:
                print(f"  {' ' * (error_col - 1)}^")
        
        return False
    except Exception as e:
        print_status("ERROR", f"Ошибка проверки конфигурационного файла", str(e))
        return False    


def _log_configuration_changes(old_config, new_config):
    """Логирование изменений конфигурации"""
    changes = []
    
    if old_config.host != new_config.host:
        changes.append(f"Хост: {old_config.host} -> {new_config.host}")
    if old_config.port != new_config.port:
        changes.append(f"Порт: {old_config.port} -> {new_config.port}")
    if old_config.debug != new_config.debug:
        changes.append(f"Режим отладки: {old_config.debug} -> {new_config.debug}")
    if old_config.log_level != new_config.log_level:
        changes.append(f"Уровень логирования: {old_config.log_level} -> {new_config.log_level}")
    if old_config.select_top != new_config.select_top:
        changes.append(f"Лимит выборки: {old_config.select_top} -> {new_config.select_top}")
    if old_config.signature_ttl != new_config.signature_ttl:
        changes.append(f"TTL подписи: {old_config.signature_ttl} -> {new_config.signature_ttl}")
    if old_config.allowed_tokens != new_config.allowed_tokens:
        changes.append(f"Количество токенов: {len(old_config.allowed_tokens)} -> {len(new_config.allowed_tokens)}")
    if old_config.disable_certificates != new_config.disable_certificates:
        changes.append(f"Сертификаты: {'отключены' if old_config.disable_certificates else 'включены'} -> {'отключены' if new_config.disable_certificates else 'включены'}")
    if old_config.disable_token_auth != new_config.disable_token_auth:
        changes.append(f"Аутентификация по токену: {'отключена' if old_config.disable_token_auth else 'включена'} -> {'отключена' if new_config.disable_token_auth else 'включена'}")
    if old_config.disable_signature != new_config.disable_signature:
        changes.append(f"Проверка подписи: {'отключена' if old_config.disable_signature else 'включена'} -> {'отключена' if new_config.disable_signature else 'включена'}")
    if old_config.login_security.get('enabled') != new_config.login_security.get('enabled'):
        changes.append(f"Безопасность входа: {'включена' if new_config.login_security.get('enabled') else 'отключена'}")
    if old_config.login_security.get('max_failed_attempts') != new_config.login_security.get('max_failed_attempts'):
        changes.append(f"Макс. попыток входа: {old_config.login_security.get('max_failed_attempts')} -> {new_config.login_security.get('max_failed_attempts')}")
    if old_config.login_security.get('check_period_minutes') != new_config.login_security.get('check_period_minutes'):
        changes.append(f"Период проверки: {old_config.login_security.get('check_period_minutes')} -> {new_config.login_security.get('check_period_minutes')} мин")
    
    if changes:
        print(f"  Изменения в конфигурации:")
        for change in changes:
            print(f"    - {change}")
    else:
        print(f"  Изменений в конфигурации не обнаружено")


async def _reload_security_keys(old_config, new_config):
    """Перезагрузка ключей безопасности при изменении настроек"""
    key_changed = (old_config.server_private_key_path != new_config.server_private_key_path or
                   old_config.client_public_key_path != new_config.client_public_key_path or
                   old_config.disable_certificates != new_config.disable_certificates)
    
    if key_changed:
        if verbose_mode:
            print_status("INFO", f"Перезагрузка ключей безопасности")
        
        try:
            global private_key, public_key
            if not config.disable_certificates:
                private_key = await load_private_key()
                public_key = await load_public_key()
                if verbose_mode:
                    print_status("OK", f"Ключи безопасности перезагружены")
            else:
                private_key = None
                public_key = None
                if verbose_mode:
                    print_status("INFO", f"Сертификаты отключены, ключи сброшены")
        except Exception as e:
            print_status("ERROR", f"Ошибка перезагрузки ключей безопасности", str(e))

async def start_config_reload_task():
    """
    Название: start_config_reload_task
    Назначение: Запуск периодической задачи перезагрузки конфигурации
    Описание: Создает асинхронную задачу для периодической проверки и перезагрузки конфигурации
    Принцип работы: В бесконечном цикле проверяет необходимость перезагрузки по интервалу
    Входящие параметры: Отсутствуют
    Исходящие параметры: Отсутствуют
    """
    global config_reload_interval, last_config_reload_time
    
    while True:
        if config_reload_interval > 0:
            await asyncio.sleep(60)  # Проверяем каждую минуту
            
            if last_config_reload_time is None:
                # Первая перезагрузка
                await reload_configuration()
            else:
                # Проверяем, прошло ли достаточно времени
                time_since_last_reload = (datetime.now() - last_config_reload_time).total_seconds()
                if time_since_last_reload >= config_reload_interval * 60:
                    await reload_configuration()
        else:
            # Если перезагрузка отключена, ждем дольше
            await asyncio.sleep(300)  # 5 минут


def format_time_remaining(interval_minutes):
    """
    Название: format_time_remaining
    Назначение: Форматирование оставшегося времени до следующей перезагрузки
    Описание: Преобразует интервал в минутах в удобочитаемый формат (дни, часы, минуты)
    Принцип работы: Разбивает общее количество минут на дни, часы и минуты
    Входящие параметры: interval_minutes - интервал в минутах
    Исходящие параметры: str - отформатированная строка времени
    """
    if interval_minutes <= 0:
        return "не применяется"
    
    minutes = interval_minutes
    days = minutes // 1440
    minutes %= 1440
    hours = minutes // 60
    minutes %= 60
    
    parts = []
    if days > 0:
        parts.append(f"{days} {pluralize(days, 'день', 'дня', 'дней')}")
    if hours > 0:
        parts.append(f"{hours} {pluralize(hours, 'час', 'часа', 'часов')}")
    if minutes > 0:
        parts.append(f"{minutes} {pluralize(minutes, 'минуту', 'минуты', 'минут')}")
    
    return ", ".join(parts) if parts else "менее минуты"


def pluralize(number, form1, form2, form5):
    """
    Название: pluralize
    Назначение: Склонение существительных после числительных
    Описание: Выбирает правильную форму слова в зависимости от числа
    Принцип работы: Проверяет остаток от деления числа на 10 и 100 для определения формы
    Входящие параметры: 
        number - число
        form1 - форма для 1
        form2 - форма для 2-4  
        form5 - форма для 5-0
    Исходящие параметры: str - правильная форма слова
    """
    n = abs(number) % 100
    n1 = n % 10
    if 10 < n < 20:
        return form5
    if n1 == 1:
        return form1
    if 1 < n1 < 5:
        return form2
    return form5


async def app_factory() -> web.Application:
    """
    Название: app_factory
    Назначение: Фабрика для создания и настройки веб-приложения с увеличенным лимитом размера запроса
    Описание: Создает экземпляр aiohttp приложения с настройкой client_max_size, 
              регистрирует маршруты и middleware
    Принцип работы: Инициализирует приложение с увеличенным лимитом для загрузки больших файлов,
                    добавляет обработчики маршрутов и цепочку middleware
    Входящие параметры: Отсутствуют
    Исходящие параметры: web.Application - сконфигурированное веб-приложение с увеличенным лимитом
    """
    # РАСЧИТЫВАЕМ МАКСИМАЛЬНЫЙ РАЗМЕР ЗАПРОСА НА ОСНОВЕ КОНФИГУРАЦИИ
    # По умолчанию aiohttp ограничивает до 1 МБ (1024*1024 = 1048576 байт)
    # Мы используем конфигурацию из config.max_upload_size (в МБ)
    max_upload_size_bytes = config.max_upload_size * 1024 * 1024
    client_max_size = int(max_upload_size_bytes * 1.1)  # +10% запаса для заголовков
    
    if verbose_mode:
        print_status("INFO", f"Создание приложения с увеличенным лимитом", 
                    f"client_max_size={client_max_size:,} байт "
                    f"({client_max_size / 1024 / 1024:.1f} МБ)")
    
    # СОЗДАЕМ ПРИЛОЖЕНИЕ С УВЕЛИЧЕННЫМ ЛИМИТОМ РАЗМЕРА ЗАПРОСА
    app = web.Application(
        client_max_size=client_max_size,  # Ключевой параметр!
        middlewares=[cors_middleware, auth_middleware]
    )
    
    # Основные эндпоинты
    app.router.add_get('/health', health_check)
    app.router.add_get('/health/security', health_security)
    app.router.add_get('/health/database', health_database)
    app.router.add_get('/health/logging', health_logging)
    app.router.add_get('/health/network', health_network)
    app.router.add_get('/health/cloud', health_cloud)
    app.router.add_get('/health/stat', health_statistics)    
    app.router.add_get('/help', help_handler)

    app.router.add_post('/user/by-phone', get_user_by_phone)
    app.router.add_post('/user/update', get_user_update) 
    app.router.add_post('/ticket/list', get_tickets)
    app.router.add_post('/payment/set', get_setpayment)
    app.router.add_post('/payment/calculate-distribution', get_payment_calculate_distribution)
    
    app.router.add_post('/user/login', get_login)
    app.router.add_post('/document/load', get_setdocument)
    app.router.add_post('/document/signed', get_documentsigned)
    app.router.add_post('/document/list', get_documentlist)
    app.router.add_post('/user/mailing', get_useremailing)

    # OPTIONS handlers для всех маршрутов
    app.router.add_options('/health', options_handler)
    app.router.add_options('/health/security', options_handler)
    app.router.add_options('/health/database', options_handler)
    app.router.add_options('/health/logging', options_handler)
    app.router.add_options('/health/network', options_handler)
    app.router.add_options('/health/cloud', options_handler)
    app.router.add_options('/help', options_handler)
    app.router.add_options('/user/by-phone', options_handler)
    app.router.add_options('/user/update', options_handler)
    app.router.add_options('/ticket/list', options_handler)
    app.router.add_options('/payment/set', options_handler)
    app.router.add_options('/payment/calculate-distribution', options_handler) 
    app.router.add_options('/user/login', options_handler)
    app.router.add_options('/document/load', options_handler)
    app.router.add_options('/document/signed', options_handler)
    app.router.add_options('/document/list', options_handler)
    app.router.add_options('/user/mailing', options_handler)

    # Обработчик для favicon.ico
    app.router.add_get('/favicon.ico', favicon_handler)
    
    if verbose_mode:
        print_status("OK", f"Веб-приложение создано", 
                    f"клиентский лимит: {client_max_size:,} байт")
    
    return app

async def main():
    """
    Название: main
    Назначение: Основная точка входа и запуска сервера
    Описание: Инициализирует приложение, запускает веб-сервер и обрабатывает сигналы завершения
    Принцип работы: Создает и настраивает AppRunner, запускает TCP сервер, обрабатывает KeyboardInterrupt
    Входящие параметры: Отсутствуют
    Исходящие параметры: Отсутствуют (бесконечный цикл до получения сигнала остановки)
    """
    global start_time
    start_time = time.time()
    
    app = await init_app()
    
    # Увеличиваем максимальный размер тела запроса
    # aiohttp по умолчанию ограничивает до 1 МБ, нам нужно больше
    max_upload_size_bytes = config.max_upload_size * 1024 * 1024
    client_max_size = int(max_upload_size_bytes * 1.1)  # +10% запаса для заголовков
    
    # Устанавливаем новый client_max_size для приложения
    app._client_max_size = client_max_size
    
    if verbose_mode:
        print_status("INFO", f"Установлен максимальный размер запроса", 
                    f"{client_max_size:,} байт ({client_max_size/1024/1024:.1f} МБ)")
    
    runner = web.AppRunner(app)
    
    await runner.setup()
    
    # Создаем TCP сайт с увеличенным буфером
    site = web.TCPSite(
        runner, 
        config.host, 
        config.port
    )
    
    await site.start()
    
    # Проверяем доступность облачного хранилища для отображения статуса
    cloud_available = False
    if config.cloud_enabled:
        cloud_available = await check_cloud_availability()
    
    # Вывод информации о запуске
    print_status("OK", f"Сервер Secure Data Exchange запущен")
    print(f"     Прослушивание на http://{config.host}:{config.port}")
    print(f"     Health check: http://{config.host}:{config.port}/health")
    
    # Информация о режимах работы
    print(f"     Подробный режим: {'ВКЛЮЧЕН' if verbose_mode else 'ВЫКЛЮЧЕН'}")
    print(f"     CORS: {'ВКЛЮЧЕН' if config.cors_enabled else 'ВЫКЛЮЧЕН'}")
    
    if config.cors_enabled:
        origins = config.cors_allowed_origins
        if origins == ['*']:
            print(f"     Разрешены все домены: *")
        else:
            print(f"     Разрешены домены: {', '.join(origins)}")

    # Информация о логировании
    print(f"     Логирование в файл: {'ВКЛЮЧЕНО' if config.is_log_to_file_enabled() else 'ВЫКЛЮЧЕНО'}")
    if config.is_log_to_file_enabled():
        print(f"     Уровни файлового логирования: {', '.join(config.log_to_file)}")

    print(f"     Логирование в БД: {'ВКЛЮЧЕНО' if config.is_log_to_db_enabled() else 'ВЫКЛЮЧЕНО'}")
    if config.is_log_to_db_enabled():
        print(f"     Уровни логирования в БД: {', '.join(config.log_to_db)}")
                    
    # Информация о базе данных
    db_status = "ПОДКЛЮЧЕНА" if db_connection else "НЕ ПОДКЛЮЧЕНА"
    print(f"     База данных: {db_status}")
    
    if not db_connection:
        print(f"     Режим без БД: {'РАЗРЕШЕН' if config.allow_start_without_db else 'ЗАПРЕЩЕН'}")
    
    # Информация о лимитах
    print(f"     Максимальное количество строк в выборке: {config.select_top}")
    
    # Информация о максимальном размере файла
    print(f"     Максимальный размер файла для загрузки: {config.max_upload_size} МБ")
    print(f"     Максимальный размер запроса: {client_max_size/1024/1024:.1f} МБ")
    
    # Информация о безопасности
    security_mode = "ЗАЩИЩЕННЫЙ" if not (config.disable_certificates and config.disable_token_auth and config.disable_signature) else "НЕЗАЩИЩЕННЫЙ"
    print(f"     Режим безопасности: {security_mode}")
    
    if security_mode == "ЗАЩИЩЕННЫЙ":
        print(f"     Сертификаты: {'ВКЛЮЧЕНЫ' if not config.disable_certificates else 'ОТКЛЮЧЕНЫ'}")
        print(f"     Аутентификация по токену: {'ВКЛЮЧЕНА' if not config.disable_token_auth else 'ОТКЛЮЧЕНА'}")
        print(f"     Проверка подписи: {'ВКЛЮЧЕНА' if not config.disable_signature else 'ОТКЛЮЧЕНА'}")
    
    # Информация о облачном хранилище
    if config.cloud_enabled:
        cloud_status = "ДОСТУПНО" if cloud_available else "НЕДОСТУПНО"
        print(f"     Облачное хранилище: {cloud_status}")
        if not cloud_available:
            print(f"     Режим без облака: {'РАЗРЕШЕН' if config.allow_start_without_cloud else 'ЗАПРЕЩЕН'}")
    else:
        print(f"     Облачное хранилище: ОТКЛЮЧЕНО")

    print("     Для остановки нажмите Ctrl+C")
    print("-" * 60)
    
    # Основной цикл ожидания
    await asyncio.Future()

async def shutdown():
    """
    Название: shutdown
    Назначение: Корректное завершение работы сервера
    Описание: Выполняет очистку ресурсов: закрывает подключение к БД, останавливает сервер
    Принцип работы: Закрывает соединение с базой данных и выводит сообщение о завершении
    Входящие параметры: Отсутствуют
    Исходящие параметры: Отсутствуют (побочный эффект - освобождение ресурсов)
    """
    global config_reload_task
    
    # Останавливаем задачу перезагрузки конфигурации если она запущена
    if config_reload_task and not config_reload_task.done():
        config_reload_task.cancel()
        try:
            await config_reload_task
        except asyncio.CancelledError:
            pass
    
    await close_database()
    if verbose_mode:
        print_status("INFO", f"Сервер остановлен")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Остановка сервера...")
        asyncio.run(shutdown())
    except Exception as e:
        print_status("ERROR", f"Критическая ошибка", str(e))
        asyncio.run(shutdown())
