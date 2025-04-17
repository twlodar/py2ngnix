# -*- coding: utf-8 -*-
import paramiko
import os
import sys
import getpass
import google.generativeai as genai
import yaml
from datetime import datetime, timedelta, timezone
import time
import re
from flask import Flask, request, jsonify, render_template # Dodano Flask
from flask_cors import CORS # Dodano CORS
from markupsafe import Markup # Import Markup from jinja2

# --- Konfiguracja ---

SECRETS_FILE = "secrets.yaml"
SECRET_GEMINI_FILE = "secret_gemini.yaml"
#GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
# GEMINI_API_KEY = "Wklej_Tutaj_Swój_Klucz_API_Google_Gemini"
GEMINI_MODEL_NAME = 'models/gemini-1.5-flash-latest'

# --- Odczyt klucza API z pliku secret_gemini.yaml ---
def load_gemini_api_key(filename=SECRET_GEMINI_FILE):
    """Wczytuje klucz API Gemini z pliku YAML."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(script_dir, filename)

    if not os.path.exists(filepath):
        print(f"BŁĄD: Plik z kluczem API '{filename}' nie został znaleziony w katalogu skryptu ({script_dir}).")
        return None

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            if isinstance(config, dict) and 'gemini_api_key' in config:
                return config['gemini_api_key']
            else:
                print(f"BŁĄD: Nieprawidłowa zawartość pliku '{filename}'. Oczekiwano klucza 'gemini_api_key'.")
                return None
    except yaml.YAMLError as e:
        print(f"BŁĄD: Nie można sparsować pliku YAML '{filepath}': {e}")
        return None
    except Exception as e:
        print(f"BŁĄD: Nie można odczytać pliku '{filepath}': {e}")
        return None

# --- Miejsce, gdzie wkleić kod: ---
# Zastąp obecne odczytywanie zmiennej środowiskowej
# GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
# ... lub odkomentowywanie hardcodowanego klucza

# Wczytaj klucz API z pliku secret_gemini.yaml
GEMINI_API_KEY = load_gemini_api_key()

if GEMINI_API_KEY is None:
    print("BŁĄD: Nie można wczytać klucza API Gemini. Sprawdź konfigurację.")
    # Możesz tu dodać kod, który kończy działanie skryptu lub
    # przechodzi do trybu bez API (wyświetlanie surowych logów)
    # sys.exit(1) # Przykładowe zakończenie skryptu
else:
    print("Klucz API Gemini wczytano pomyślnie z pliku.")


# --- Funkcje ---

def load_config(filename=SECRETS_FILE):
    """Wczytuje konfigurację routerów z pliku YAML."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(script_dir, filename)

    if not os.path.exists(filepath):
        print(f"BŁĄD: Plik konfiguracyjny '{filename}' nie został znaleziony w katalogu skryptu ({script_dir}).")
        return None

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"BŁĄD: Nie można sparsować pliku YAML '{filepath}': {e}")
        return None
    except Exception as e:
        print(f"BŁĄD: Nie można odczytać pliku '{filepath}': {e}")
        return None

    if not config or 'routers' not in config or not isinstance(config['routers'], list):
        print(f"BŁĄD: Nieprawidłowa struktura pliku '{filepath}'. Oczekiwano klucza 'routers' z listą routerów.")
        return None

    validated_routers = []
    required_router_count = 4
    names = set()

    for i, router_cfg in enumerate(config['routers']):
        if not isinstance(router_cfg, dict):
            print(f"BŁĄD: Wpis routera nr {i+1} w '{filename}' nie jest słownikiem.")
            continue

        required_keys = ['name', 'role', 'host', 'port', 'user']
        missing_keys = [key for key in required_keys if key not in router_cfg or router_cfg[key] is None]
        if missing_keys:
            print(f"BŁĄD: Brakujące lub puste wymagane klucze dla routera '{router_cfg.get('name', f'pozycja {i+1}')}': {', '.join(missing_keys)}")
            continue

        router_name = router_cfg['name']
        if router_name in names:
             print(f"BŁĄD: Nazwa routera '{router_name}' nie jest unikalna.")
             continue
        names.add(router_name)

        router_cfg['password'] = router_cfg.get('password')
        key_path_relative = router_cfg.get('key_path')
        if key_path_relative:
            if not os.path.isabs(key_path_relative):
                 router_cfg['key_path'] = os.path.join(script_dir, key_path_relative)
            else:
                 router_cfg['key_path'] = key_path_relative
        else:
             router_cfg['key_path'] = None

        if router_cfg['role'] not in ['main', 'subordinate']:
             print(f"BŁĄD: Nieprawidłowa wartość 'role' ('{router_cfg['role']}') dla routera '{router_name}'. Dozwolone: 'main', 'subordinate'.")
             continue

        try:
            router_cfg['port'] = int(router_cfg['port'])
        except (ValueError, TypeError):
            print(f"BŁĄD: Nieprawidłowa wartość 'port' ('{router_cfg.get('port')}') dla routera '{router_name}'. Musi być liczbą.")
            continue

        validated_routers.append(router_cfg)

    if len(validated_routers) != len(config['routers']):
         print("Nie wszystkie wpisy routerów z pliku konfiguracyjnego są poprawne. Przerwano.")
         return None

    if len(validated_routers) != required_router_count:
         print(f"BŁĄD: Oczekiwano konfiguracji dla {required_router_count} routerów (1 main, 3 subordinate). Znaleziono {len(validated_routers)} poprawnych wpisów.")
         return None

    main_routers = [r for r in validated_routers if r['role'] == 'main']
    if len(main_routers) != 1:
        print(f"BŁĄD: W konfiguracji musi znajdować się dokładnie jeden router z rolą 'main'. Znaleziono: {len(main_routers)}.")
        return None

    subordinate_routers = [r for r in validated_routers if r['role'] == 'subordinate']
    if len(subordinate_routers) != 3:
        print(f"BŁĄD: W konfiguracji muszą znajdować się dokładnie trzy routery z rolą 'subordinate'. Znaleziono: {len(subordinate_routers)}.")
        return None

    print(f"Pomyślnie wczytano i zwalidowano konfigurację dla {len(validated_routers)} routerów z '{filename}'.")
    return validated_routers


def get_ssh_connection(hostname, port, username, key_path=None, password=None):
    """Nawiązuje połączenie SSH i zwraca obiekt klienta."""
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"Łączenie z {hostname}:{port} jako {username}...")
        auth_method = "niczego"
        if key_path:
            auth_method = f"klucza ({os.path.basename(key_path)})"
            print(f"Używam klucza: {key_path}")
            if not os.path.isfile(key_path):
                 raise FileNotFoundError(f"Plik klucza prywatnego nie istnieje lub nie jest plikiem: {key_path}")
            key = None
            key_types = [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]
            last_exception = None
            for key_type in key_types:
                 try:
                      key = key_type.from_private_key_file(key_path)
                      print(f"  Pomyślnie wczytano klucz typu: {key_type.__name__}")
                      break
                 except paramiko.PasswordRequiredException:
                      key_password = getpass.getpass(f"Podaj hasło dla klucza SSH {key_path}: ")
                      try:
                            key = key_type.from_private_key_file(key_path, password=key_password)
                            print(f"  Pomyślnie wczytano zaszyfrowany klucz typu: {key_type.__name__}")
                            break
                      except Exception as e_pwd:
                            last_exception = e_pwd
                            print(f"  Nie udało się wczytać klucza {key_type.__name__} z hasłem.")
                 except Exception as e:
                      last_exception = e
            if key is None:
                 print(f"BŁĄD: Nie można wczytać klucza prywatnego {key_path} jako żadnego ze znanych typów.")
                 if last_exception:
                     print(f"  Ostatni błąd: {last_exception}")
                 return None

            ssh_client.connect(hostname=hostname, port=port, username=username, pkey=key, timeout=15)

        elif password:
            auth_method = "hasła"
            print("Używam hasła z konfiguracji.")
            ssh_client.connect(hostname=hostname, port=port, username=username, password=password, timeout=15)
        else:
            auth_method = "hasła (wprowadzonego ręcznie)"
            print(f"W konfiguracji dla {username}@{hostname} nie podano hasła ani ścieżki klucza.")
            password_prompt = getpass.getpass(f"Podaj hasło SSH dla {username}@{hostname}: ")
            ssh_client.connect(hostname=hostname, port=port, username=username, password=password_prompt, timeout=15)

        print(f"Połączono z {hostname} używając {auth_method}")
        return ssh_client

    except paramiko.AuthenticationException:
        print(f"BŁĄD: Uwierzytelnienie nie powiodło się dla {username}@{hostname} przy użyciu {auth_method}.")
    except paramiko.SSHException as sshException:
        print(f"BŁĄD: Nie można ustanowić połączenia SSH z {hostname}: {sshException}")
    except FileNotFoundError as e:
        print(f"BŁĄD: {e}")
    except Exception as e:
        print(f"BŁĄD: Wystąpił nieoczekiwany błąd podczas łączenia z {hostname}: {e}")

    return None

def execute_ssh_command(ssh_client, command):
    """Wykonuje komendę SSH i zwraca stdout, stderr oraz kod wyjścia."""
    if not ssh_client:
        return None, "Klient SSH nie jest połączony.", -1

    try:
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=30)
        exit_status = stdout.channel.recv_exit_status()
        stdout_bytes = stdout.read()
        stderr_bytes = stderr.read()
        stdout_data = stdout_bytes.decode('utf-8', errors='replace').strip()
        stderr_data = stderr_bytes.decode('utf-8', errors='replace').strip()
        return stdout_data, stderr_data, exit_status
    except Exception as e:
        hostname_info = "nieznanego hosta"
        try: hostname_info = ssh_client.get_transport().getpeername()[0]
        except Exception: pass
        print(f"BŁĄD: Błąd podczas wykonywania komendy '{command}' na {hostname_info}: {e}")
        return None, str(e), -1

def filter_dmesg_logs(raw_logs, estimated_boot_time_unix, hours_ago):
    """Filtruje logi dmesg, aby zawierały tylko wpisy z ostatnich X godzin."""
    if hours_ago <= 0:
        print("  Analiza obejmuje wszystkie dostępne logi dmesg (hours_ago <= 0).")
        return raw_logs

    if estimated_boot_time_unix is None:
        print("  OSTRZEŻENIE: Nie można przefiltrować logów dmesg czasowo - brak szacowanego czasu startu.")
        return raw_logs

    print(f"  Filtrowanie logów dmesg dla ostatnich {hours_ago} godzin...")
    filtered_lines = []
    now_utc = datetime.now(timezone.utc)
    cutoff_time_unix = (now_utc - timedelta(hours=hours_ago)).timestamp()

    relative_time_pattern = re.compile(r'^\[\s*(\d+\.\d+)\s*\](.*)')

    lines_processed = 0
    lines_kept = 0
    errors_parsing_time = 0

    for line in raw_logs.splitlines():
        lines_processed += 1
        match = relative_time_pattern.match(line)
        if match:
            try:
                log_seconds = float(match.group(1))
                event_time_unix = estimated_boot_time_unix + log_seconds
                if event_time_unix >= cutoff_time_unix:
                    filtered_lines.append(line)
                    lines_kept += 1
            except ValueError:
                errors_parsing_time += 1
                pass
        else:
            pass

    if errors_parsing_time > 0:
        print(f"  OSTRZEŻENIE: Napotkano {errors_parsing_time} błędów podczas parsowania czasu względnego w logach.")

    print(f"  Filtrowanie zakończone: Zachowano {lines_kept} z {lines_processed} linii.")

    if not filtered_lines:
        print(f"  UWAGA: Po filtrowaniu dla ostatnich {hours_ago} godzin, nie znaleziono pasujących wpisów w dmesg.")
        return ""

    return "\n".join(filtered_lines)


def get_router_data(ssh_client, hours_ago_for_filter):
    """Pobiera logi dmesg (i filtruje je), czas i uptime z połączonego urządzenia."""
    data = {
        'logs': None,
        'raw_log_length': 0,
        'filtered_log_length': 0,
        'current_unix_time': None,
        'uptime_seconds': None,
        'error': None,
        'estimated_boot_time_unix': None
    }
    hostname = "Nieznany host"
    try:
         if ssh_client and ssh_client.get_transport():
              hostname = ssh_client.get_transport().getpeername()[0]
    except Exception: pass

    print(f"Pobieranie czasu systemowego (Unix timestamp) z {hostname}...")
    date_out, date_err, date_status = execute_ssh_command(ssh_client, 'date +%s')
    if date_status == 0 and date_out:
        try:
            data['current_unix_time'] = int(date_out)
            dt_object_utc = datetime.fromtimestamp(data['current_unix_time'], timezone.utc)
            print(f"  Sukces: czas Unix = {data['current_unix_time']} ({dt_object_utc.strftime('%Y-%m-%d %H:%M:%S %Z')})")
        except ValueError:
            err_msg = f"Nie udało się sparsować wyniku 'date +%s' dla {hostname}: '{date_out}'"
            print(f"BŁĄD: {err_msg}")
            if not data['error']: data['error'] = err_msg
    else:
        err_msg = f"Nie można pobrać czasu z {hostname}. Status: {date_status}, Błąd: {date_err}"
        print(f"BŁĄD: {err_msg}")
        if not data['error']: data['error'] = err_msg

    print(f"Pobieranie uptime z {hostname}...")
    uptime_out, uptime_err, uptime_status = execute_ssh_command(ssh_client, 'cat /proc/uptime')
    if uptime_status == 0 and uptime_out:
        try:
            uptime_str = uptime_out.split()[0]
            data['uptime_seconds'] = int(float(uptime_str))
            print(f"  Sukces: uptime = {data['uptime_seconds']} sekund")
        except (ValueError, IndexError):
            err_msg = f"Nie udało się sparsować wyniku '/proc/uptime' dla {hostname}: '{uptime_out}'"
            print(f"BŁĄD: {err_msg}")
            if not data['error']: data['error'] = err_msg
    else:
        print(f"  Nie udało się odczytać /proc/uptime dla {hostname}, sprawdzanie komendy 'uptime'...")
        uptime_cmd_out, uptime_cmd_err, uptime_cmd_status = execute_ssh_command(ssh_client, 'uptime')
        if uptime_cmd_status == 0 and uptime_cmd_out:
             print(f"  Wynik komendy 'uptime' dla {hostname}: {uptime_cmd_out}")
             if not data['error']: data['error'] = "Nie udało się odczytać /proc/uptime, komenda 'uptime' dostępna, ale nie sparsowana."
        else:
             err_msg = f"Nie można pobrać uptime z {hostname} ani z /proc/uptime, ani z komendy 'uptime'. Błąd: {uptime_err} / {uptime_cmd_err}"
             print(f"BŁĄD: {err_msg}")
             if not data['error']: data['error'] = err_msg

    if data['current_unix_time'] and data['uptime_seconds'] is not None:
         data['estimated_boot_time_unix'] = data['current_unix_time'] - data['uptime_seconds']
         est_boot_dt_utc = datetime.fromtimestamp(data['estimated_boot_time_unix'], timezone.utc)
         print(f"  Szacowany czas startu dla {hostname}: {data['estimated_boot_time_unix']} ({est_boot_dt_utc.strftime('%Y-%m-%d %H:%M:%S %Z')})")
    else:
         print(f"  Nie można obliczyć szacowanego czasu startu dla {hostname} (brak czasu i/lub uptime).")

    print(f"Pobieranie logów dmesg z {hostname}...")
    raw_dmesg_logs = None
    logs_std, err_std, status_std = execute_ssh_command(ssh_client, 'dmesg')
    if status_std == 0 and logs_std:
        print("  Sukces: pobrano surowe logi 'dmesg'.")
        raw_dmesg_logs = logs_std
    else:
        print("  Komenda 'dmesg' nie powiodła się, próba 'dmesg -T'...")
        logs_T, err_T, status_T = execute_ssh_command(ssh_client, 'dmesg -T')
        if status_T == 0 and logs_T:
            print("  Sukces: użyto 'dmesg -T' (logi nie będą filtrowane czasowo).")
            raw_dmesg_logs = logs_T
            filter_warn = "Użyto dmesg -T, filtrowanie czasowe niemożliwe."
            data['error'] = f"{data.get('error', '')} {filter_warn}".strip()
        else:
            error_details = f"dmesg (status {status_std}): {err_std}. dmesg -T (status {status_T}): {err_T}"
            err_msg = f"Nie można pobrać logów dmesg z {hostname}. Szczegóły: {error_details}"
            print(f"BŁĄD: {err_msg}")
            if not data['error']: data['error'] = err_msg

    if raw_dmesg_logs and logs_std:
        data['raw_log_length'] = len(raw_dmesg_logs)
        data['logs'] = filter_dmesg_logs(raw_dmesg_logs, data['estimated_boot_time_unix'], hours_ago_for_filter)
        data['filtered_log_length'] = len(data['logs'])
        if not data['logs'] and hours_ago_for_filter > 0 and not data['error']:
            data['error'] = f"Brak wpisów dmesg w ciągu ostatnich {hours_ago_for_filter} godzin."
    elif raw_dmesg_logs and logs_T:
        data['logs'] = raw_dmesg_logs
        data['raw_log_length'] = len(raw_dmesg_logs)
        data['filtered_log_length'] = len(raw_dmesg_logs)
        print("  Logi z 'dmesg -T' nie zostały przefiltrowane czasowo.")

    if data['logs'] and (data['current_unix_time'] is None or data['uptime_seconds'] is None):
        time_err_msg = "Nie udało się pobrać pełnych danych czasowych (czas i/lub uptime)."
        if data['error'] and "Nie można wykonać 'dmesg'" not in data['error']:
             data['error'] += " " + time_err_msg
        elif not data['error']:
             data['error'] = time_err_msg
        print(f"UWAGA: {time_err_msg} dla {hostname}")

    if not data['logs'] and not data['error']:
         data['error'] = "Nie udało się pobrać logów dmesg lub logi są puste."

    print(f"Zakończono pobieranie danych dla {hostname}.")
    return data

def analyze_logs_with_gemini(api_key, router_data, analysis_hours):
    """Wysyła zebrane i przefiltrowane dane do Gemini API i zwraca analizę."""
    if not api_key:
        return "BŁĄD: Klucz API Gemini nie został skonfigurowany. Ustaw zmienną środowiskową GEMINI_API_KEY."

    try:
        genai.configure(api_key=api_key)
    except Exception as e:
        return f"BŁĄD: Nieprawidłowa konfiguracja API Gemini: {e}"

    model_name_to_use = GEMINI_MODEL_NAME
    print(f"\nUżywanie modelu Gemini: {model_name_to_use}")
    try:
        model = genai.GenerativeModel(model_name_to_use)
    except Exception as e:
        return f"BŁĄD: Nie można zainicjować lub połączyć się z modelem '{model_name_to_use}': {e}"

    print("\nPrzygotowywanie promptu dla Gemini...")

    main_router_name = next((name for name, data in router_data.items() if data['config']['role'] == 'main'), "Nieznany")
    current_analysis_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
    analysis_period_str = f"ostatnich {analysis_hours} godzin" if analysis_hours > 0 else "całego dostępnego okresu"

    prompt_parts = [
        f"Jesteś zaawansowanym analitykiem systemów sieciowych, specjalizującym się w diagnozowaniu problemów w małych sieciach opartych o routery Linux (OpenWrt, DD-WRT itp.). Analizujesz dane zebrane {current_analysis_time_str} z 4 routerów (1 główny, 3 podrzędne).",
        f"**WAŻNE:** Dostarczone logi `dmesg` zostały już **przefiltrowane**, aby zawierały tylko wpisy z **{analysis_period_str}** (licząc wstecz od czasu zebrania danych). Jeśli dla któregoś routera logi są puste po filtrowaniu, zostanie to zaznaczone.",
        f"Twoim zadaniem jest analiza tych (potencjalnie przefiltrowanych) logów i danych czasowych.",

        f"\nKLUCZOWE ZADANIE:",
        f"1.  **Identyfikacja Błędów/Ostrzeżeń:** Wyszukaj wszelkie błędy krytyczne (np. kernel panic, oops, I/O errors, filesystem errors), problemy sieciowe (link down/up, błędy sterowników), braki pamięci (OOM), restarty (krótki uptime) itp. w dostarczonych logach.",
        f"2.  **Korelacja Czasowa:** Spróbuj powiązać zdarzenia między routerami, które wystąpiły w zbliżonym czasie (z tolerancją +/- 30 sekund), wykorzystując dostarczone czasy startu i znaczniki w logach dmesg (czas od startu systemu).",
        f"3.  **Ocena Ogólna:** Na podstawie znalezionych problemów (lub ich braku) w analizowanym okresie ({analysis_period_str}), oceń stabilność każdego routera i potencjalne zależności.",
        f"4.  **Jeśli nie ma błędów:** **Jeżeli w przefiltrowanych logach dla danego routera (lub wszystkich) nie znajdziesz żadnych istotnych błędów ani ostrzeżeń, wyraźnie zaznacz w podsumowaniu i analizie indywidualnej, że w analizowanym okresie ({analysis_period_str}) nie wykryto problemów dla tego urządzenia.**",

        f"\nFORMAT ODPOWIEDZI:",
        f"   - **Podsumowanie Ogólne ({analysis_period_str}):** Krótka ocena stanu sieci na podstawie analizy. Czy znaleziono problemy? Czy występują korelacje? (Jeśli nie ma błędów, zaznacz to).",
        f"   - **Analiza Czasu Systemowego:** Czy szacowane czasy startu routerów sugerują problemy z synchronizacją czasu (NTP)?",
        f"   - **Szczegółowa Analiza (per Router):**",
        f"     - **{main_router_name} (Main):**",
        f"       - Wykryte problemy w logach z {analysis_period_str} (lub informacja o ich braku).",
        f"       - Ocena stabilności na podstawie logów i uptime.",
        f"     - **[Nazwa Routera Podrzędnego 1] (Subordinate):**",
        f"       - Wykryte problemy (lub info o braku) w {analysis_period_str}.",
        f"       - Ocena stabilności.",
        f"     - **[Nazwa Routera Podrzędnego 2] (Subordinate):** ...",
        f"     - **[Nazwa Routera Podrzędnego 3] (Subordinate):** ...",
        f"   - **Korelacja Zdarzeń ({analysis_period_str}):** Opis znalezionych powiązań czasowych między routerami (lub stwierdzenie ich braku).",
        f"   - **Prawdopodobne Przyczyny (jeśli wykryto problemy):** Hipotezy.",
        f"   - **Rekomendacje:** Sugestie dalszych kroków.",

        f"\n--- POCZĄTEK DANYCH Z ROUTERÓW (Analiza dla: {analysis_period_str}) ---"
    ]

    if not router_data:
        return "BŁĄD: Brak danych z routerów do analizy."

    sorted_router_names = sorted(router_data.keys(), key=lambda name: (router_data[name]['config']['role'] != 'main', name))

    for name in sorted_router_names:
        data = router_data[name]
        config = data['config']
        prompt_parts.append(f"\n\n=== Dane dla: {name} (Rola: {config['role']}, Host: {config['host']}) ===")

        # Informacje o czasie
        prompt_parts.append("\n--- Informacje o czasie ---")
        time_info_ok = data.get('current_unix_time') and data.get('uptime_seconds') is not None and data.get('estimated_boot_time_unix') is not None
        if time_info_ok:
            current_dt_utc = datetime.fromtimestamp(data['current_unix_time'], timezone.utc)
            uptime_days = data['uptime_seconds'] // (24 * 3600)
            uptime_hms = time.strftime('%H:%M:%S', time.gmtime(data['uptime_seconds'] % (24 * 3600)))
            estimated_boot_dt_utc = datetime.fromtimestamp(data['estimated_boot_time_unix'], timezone.utc)
            prompt_parts.append(f"Aktualny czas systemowy (Unix): {data['current_unix_time']} ({current_dt_utc.strftime('%Y-%m-%d %H:%M:%S %Z')})")
            prompt_parts.append(f"Czas działania (Uptime): {data['uptime_seconds']} sekund (około {uptime_days} dni {uptime_hms})")
            prompt_parts.append(f"Szacowany czas startu (Unix): {data['estimated_boot_time_unix']} ({estimated_boot_dt_utc.strftime('%Y-%m-%d %H:%M:%S %Z')})")
        else:
            prompt_parts.append("Niekompletne informacje o czasie.")
            if data.get('current_unix_time'):
                 current_dt_utc = datetime.fromtimestamp(data['current_unix_time'], timezone.utc)
                 prompt_parts.append(f"  - Aktualny czas Unix: {data['current_unix_time']} ({current_dt_utc.strftime('%Y-%m-%d %H:%M:%S %Z')})")
            if data.get('uptime_seconds') is not None:
                 prompt_parts.append(f"  - Uptime: {data['uptime_seconds']} sekund")
            if data.get('error') and ("czas" in data['error'].lower() or "date" in data['error'].lower() or "uptime" in data['error'].lower()):
                 prompt_parts.append(f"  - Komunikat błędu dotyczący czasu: {data['error']}")

        # Logi dmesg (już przefiltrowane)
        prompt_parts.append(f"\n--- Logi dmesg (Filtrowane dla: {analysis_period_str}) ---")
        if data.get('logs') is not None:
            if data['logs']:
                MAX_LOG_CHARS = 25000
                log_content = data['logs']
                if len(log_content) > MAX_LOG_CHARS:
                     print(f"UWAGA: Przefiltrowane logi dla {name} są nadal długie ({len(log_content)} znaków), zostaną przycięte do {MAX_LOG_CHARS} znaków dla analizy LLM (zachowano koniec logu).")
                     log_content = log_content[-MAX_LOG_CHARS:]
                prompt_parts.append(log_content)
                filter_info = f"(Rozmiar przed filtrowaniem: {data.get('raw_log_length','N/A')} B, po filtrowaniu: {data.get('filtered_log_length','N/A')} B)"
                prompt_parts.append(f"\n[Informacja o filtrowaniu: {filter_info}]")
            else:
                prompt_parts.append(f"**BRAK WPISÓW W LOGACH DMESG** w analizowanym okresie ({analysis_period_str}).")
                if data.get('error') and "Brak wpisów dmesg" in data['error']:
                     prompt_parts.append(f"(Komunikat błędu: {data['error']})")
        else:
             log_error_msg = f"**BŁĄD POBIERANIA LUB PRZETWARZANIA LOGÓW DMESG.**"
             if data.get('error'):
                  log_error_msg += f"\n(Komunikat błędu: {data['error']})"
             prompt_parts.append(log_error_msg)

        prompt_parts.append(f"\n=== Koniec danych dla: {name} ===")

    prompt_parts.append(f"\n\n--- KONIEC DANYCH Z ROUTERÓW ---")
    prompt_parts.append(f"\nProszę o przeprowadzenie szczegółowej analizy zgodnie z powyższymi wytycznymi, pamiętając, że logi dotyczą tylko okresu: {analysis_period_str} i wyraźnie wskazując brak błędów, jeśli takowy wystąpił.")

    final_prompt = "".join(prompt_parts)

    # Debug: Zapisz prompt do pliku (opcjonalne)
    # try:
    #     with open("gemini_prompt.txt", "w", encoding='utf-8') as f: f.write(final_prompt)
    #     print("DEBUG: Prompt zapisany do pliku gemini_prompt.txt")
    # except Exception as e: print(f"DEBUG: Nie udało się zapisać promptu do pliku: {e}")

    print(f"\nWysyłanie zapytania do Gemini API (model: {model_name_to_use})... To może potrwać kilka minut.")

    try:
        generation_config = genai.types.GenerationConfig(
            # temperature=0.7,
            # max_output_tokens=8192
        )
        response = model.generate_content(
            final_prompt,
            generation_config=generation_config,
            request_options={'timeout': 480} # 8 minut
        )
        print("Otrzymano odpowiedź z Gemini.")

        if not response.parts:
             reason = "Nieznana przyczyna"
             block_reason = "Nie podano"
             safety_ratings_str = "Brak"
             try:
                  candidate = response.candidates[0]
                  reason = candidate.finish_reason.name if candidate.finish_reason else "Nieznana"
                  if candidate.safety_ratings:
                       safety_ratings_str = ", ".join([f"{r.category.name}: {r.probability.name}" for r in candidate.safety_ratings])
                  if response.prompt_feedback and response.prompt_feedback.block_reason:
                      block_reason = response.prompt_feedback.block_reason.name
             except (IndexError, AttributeError, Exception) as e_resp:
                  print(f"  Ostrzeżenie: Nie można w pełni przeanalizować pustej odpowiedzi Gemini: {e_resp}")

             error_msg = f"BŁĄD: Otrzymano pustą odpowiedź z Gemini API."
             error_msg += f"\n  Powód zakończenia: {reason}"
             error_msg += f"\n  Powód blokady (Prompt Feedback): {block_reason}"
             error_msg += f"\n  Oceny bezpieczeństwa (kandydata): {safety_ratings_str}"
             print(error_msg)
             try:
                 error_text = response.text
                 if error_text: return error_msg + f"\n  Tekst z odpowiedzi (jeśli jest): {error_text}"
             except ValueError: pass
             return error_msg

        return response.text

    except Exception as e:
        print(f"BŁĄD KRYTYCZNY: Wystąpił błąd podczas komunikacji z Gemini API: {e}")
        error_details = getattr(e, 'message', str(e))
        try: # Spróbuj uzyskać więcej szczegółów, jeśli to Google API error
            if hasattr(e, 'response') and hasattr(e.response, 'text'): error_details += f"\nSzczegóły odpowiedzi API: {e.response.text}"
            elif hasattr(e, 'args'): error_details += f"\nArgumenty błędu: {e.args}"
        except Exception: pass
        error_type = type(e).__name__
        return f"BŁĄD KRYTYCZNY ({error_type}): Nie udało się uzyskać analizy z Gemini. Powód: {error_details}"


# --- Główna część skryptu ---

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# --- Define the nl2br filter ---
def nl2br(value):
    """Jinja filter to convert newlines to <br> tags."""
    _paragraph_re = re.compile(r'(?:\r\n|\r(?!\n)|\n){2,}')
    paragraphs = _paragraph_re.split(value)  # Correct: .split(value)
    result = '\n\n'.join(
        Markup(p).unescape() for p in paragraphs
    )
    return Markup(result.replace('\n', '<br>\n'))

--- Register the nl2br filter with Jinja2 ---

app.jinja_env.filters['nl2br'] = nl2br


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    analysis_hours = -1
    try:
        analysis_hours = int(request.form['analysis_hours'])
        if analysis_hours < 0:
            return render_template('index.html', error="Liczba godzin nie może być ujemna.")
    except ValueError:
        return render_template('index.html', error="Nieprawidłowa wartość godzin. Proszę podać liczbę całkowitą.")

    router_configs = load_config(SECRETS_FILE)
    if not router_configs:
        return render_template('index.html', error="Błąd konfiguracji routerów.")

    all_router_data = {}
    connections = {}
    analysis_summary_text = ""
    raw_data_text = ""

    for i, config in enumerate(router_configs):
        name = config['name']
        role = config['role']
        print(f"\n--- Przetwarzanie routera {i+1}/{len(router_configs)}: {name} ({role}) ---")
        ssh = None
        router_info = {'config': config, 'logs': None, 'raw_log_length': 0, 'filtered_log_length': 0, 'current_unix_time': None, 'uptime_seconds': None, 'estimated_boot_time_unix': None, 'error': None}
        try:
            ssh = get_ssh_connection(
                config['host'],
                config['port'],
                config['user'],
                config.get('key_path'),
                config.get('password')
            )
            if ssh:
                connections[name] = ssh
                router_specific_data = get_router_data(ssh, analysis_hours)
                router_info.update(router_specific_data)
            else:
                router_info['error'] = "Nie udało się nawiązać połączenia SSH."

        except Exception as e:
            error_msg = f"Nieoczekiwany błąd krytyczny podczas przetwarzania {name}: {e}"
            print(f"KRYTYCZNY BŁĄD: {error_msg}")
            router_info['error'] = error_msg
        finally:
             all_router_data[name] = router_info

    print("\n--- Zamykanie połączeń SSH ---")
    for name, ssh_client in connections.items():
        if ssh_client:
            try:
                ssh_client.close()
                print(f"Zamknięto połączenie z {name}")
            except Exception as e:
                print(f"Błąd podczas zamykania połączenia z {name}: {e}")

    print("\n--- Podsumowanie Pobierania Danych ---")
    logs_collected_count = 0
    filtered_logs_present = 0
    data_collected_count = 0
    time_data_collected_count = 0

    sorted_names_report = sorted(all_router_data.keys(), key=lambda name: (all_router_data[name]['config']['role'] != 'main', name))

    for name in sorted_names_report:
        data = all_router_data[name]
        status = "[OK]" if not data.get('error') or "Brak wpisów dmesg" in data.get('error','') else "[BŁĄD]"
        log_status = "Pobrano" if data.get('logs') is not None else "Brak/Błąd"
        filtered_status = "Obecne" if data.get('logs') else "Puste/Brak"
        time_status = "Pełne" if data.get('current_unix_time') and data.get('uptime_seconds') is not None and data.get('estimated_boot_time_unix') is not None else "Niepełne/Brak"
        error_msg = f" Info/Błąd: {data['error']}" if data.get('error') else ""

        analysis_summary_text += f"{status:<7} {name} ({data['config']['role']}): Logi: {log_status} (filtrowane: {filtered_status}), Dane czasowe: {time_status}.{error_msg}\n"

        if not data.get('error') or "Brak wpisów dmesg" in data.get('error',''):
            data_collected_count += 1
        if data.get('logs') is not None:
             logs_collected_count += 1
        if data.get('logs'):
             filtered_logs_present += 1
        if time_status == "Pełne":
             time_data_collected_count +=1

        raw_data_text += f"\n\n=== SUROWE DANE DLA: {name} (Rola: {data['config']['role']}) ===\n"
        if data.get('error'): raw_data_text += f"BŁĄD/INFO PODCZAS POBIERANIA: {data['error']}\n"
        if data.get('current_unix_time'):
             ctime_str = datetime.fromtimestamp(data['current_unix_time'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
             raw_data_text += f"Czas systemowy (Unix): {data['current_unix_time']} ({ctime_str})\n"
        if data.get('uptime_seconds') is not None: raw_data_text += f"Uptime (sekundy): {data['uptime_seconds']}\n"
        if data.get('estimated_boot_time_unix') is not None:
             est_boot_str = datetime.fromtimestamp(data['estimated_boot_time_unix'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
             raw_data_text += f"Szacowany czas startu (Unix): {data['estimated_boot_time_unix']} ({est_boot_str})\n"

        raw_data_text += f"\n--- Logi dmesg (Filtrowane dla {analysis_hours}h) ---\n"
        if data.get('logs') is not None:
             if data['logs']:
                  raw_data_text += data['logs']
                  raw_data_text += f"\n[INFO: Rozmiar przed filtrowaniem: {data.get('raw_log_length','N/A')} B, po filtrowaniu: {data.get('filtered_log_length','N/A')} B]\n"
             else: raw_data_text += f"[BRAK WPISÓW w ostatnich {analysis_hours}h lub błąd]\n"
        else: raw_data_text += "[BŁĄD POBIERANIA LOGÓW]\n"
        raw_data_text += f"--- Koniec danych dla: {name} ---\n"


    gemini_analysis = ""
    if GEMINI_API_KEY:
        if logs_collected_count == 0:
            gemini_analysis = "KRYTYCZNE: Nie udało się pobrać logów dmesg z żadnego routera. Analiza LLM nie jest możliwa."
        elif filtered_logs_present == 0 and analysis_hours > 0:
            gemini_analysis = f"INFORMACJA: Nie znaleziono żadnych wpisów w logach dmesg we wszystkich routerach w ciągu ostatnich {analysis_hours} godzin. Analiza LLM zostanie przeprowadzona, ale może nie zawierać istotnych informacji."
        elif data_collected_count < len(router_configs):
            gemini_analysis = f"UWAGA: Udało się pobrać dane bez krytycznych błędów tylko z {data_collected_count} z {len(router_configs)} routerów."
        elif logs_collected_count < len(router_configs):
            gemini_analysis = f"UWAGA: Logi dmesg (przed filtrowaniem) pobrano tylko z {logs_collected_count} z {len(router_configs)} routerów."
        elif time_data_collected_count < len(router_configs):
            gemini_analysis = f"UWAGA: Pełne dane czasowe pobrano tylko z {time_data_collected_count} z {len(router_configs)} routerów. Korelacja czasowa może być utrudniona."
        else:
            gemini_analysis = "" # No initial warnings

        gemini_result = analyze_logs_with_gemini(GEMINI_API_KEY, all_router_data, analysis_hours)
        gemini_analysis += "\n" + "="*20 + f" Wynik Analizy Gemini ({analysis_hours}h) " + "="*20 + "\n" + gemini_result
        gemini_analysis += "\n" + "="* (44 + len(f" Wynik Analizy Gemini ({analysis_hours}h) ")) # Dopasuj długość linii
    else:
        gemini_analysis = "\nUWAGA: Klucz API Gemini nie został znaleziony. Nie można przeprowadzić automatycznej analizy LLM.\n" + raw_data_text


    return render_template('results.html', analysis_hours=analysis_hours, analysis_summary=analysis_summary_text, gemini_analysis=gemini_analysis, raw_data=raw_data_text, gemini_api_key_available=bool(GEMINI_API_KEY))


if __name__ == "__main__":
    print(f"--- Analizator Logów Routera z Gemini ({GEMINI_MODEL_NAME}) ---")
    print("Uruchamianie serwera Flask...")
    app.run(debug=True, host='0.0.0.0', port=5000) # Uruchomienie serwera Flask
