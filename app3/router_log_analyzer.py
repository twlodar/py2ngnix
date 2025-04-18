#--- START OF FILE dmesgAIgoogle_raw_git.py ---
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
import subprocess
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
        print(f"Łączenie z {hostname}:{port} jako {username}...") # LOGGING
        print(f"  Host: {hostname}, Port: {port}, User: {username}, Key Path: {key_path}, Password Provided: {bool(password)}") # LOGGING
        auth_method = "niczego"
        if key_path:
            auth_method = f"klucza ({os.path.basename(key_path)})"
            print(f"Używam klucza: {key_path}") # LOGGING
            if not os.path.isfile(key_path):
                 raise FileNotFoundError(f"Plik klucza prywatnego nie istnieje lub nie jest plikiem: {key_path}")
            key = None
            key_types = [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]
            last_exception = None
            for key_type in key_types:
                 try:
                      key = key_type.from_private_key_file(key_path)
                      print(f"  Pomyślnie wczytano klucz typu: {key_type.__name__}") # LOGGING
                      break
                 except paramiko.PasswordRequiredException:
                      key_password = getpass.getpass(f"Podaj hasło dla klucza SSH {key_path}: ")
                      try:
                            key = key_type.from_private_key_file(key_path, password=key_password)
                            print(f"  Pomyślnie wczytano zaszyfrowany klucz typu: {key_type.__name__}") # LOGGING
                            break
                      except Exception as e_pwd:
                            last_exception = e_pwd
                            print(f"  Nie udało się wczytać klucza {key_type.__name__} z hasłem.") # LOGGING
                 except Exception as e:
                      last_exception = e
            if key is None:
                 print(f"BŁĄD: Nie można wczytać klucza prywatnego {key_path} jako żadnego ze znanych typów.") # LOGGING
                 if last_exception:
                     print(f"  Ostatni błąd: {last_exception}") # LOGGING
                 return None

            print(f"Próba połączenia SSH z kluczem: {auth_method}") # LOGGING
            ssh_client.connect(hostname=hostname, port=port, username=username, pkey=key, timeout=15) # LOGGING - Keep timeout
            print(f"Połączono z {hostname} używając {auth_method}") # LOGGING

        elif password:
            auth_method = "hasła"
            print("Używam hasła z konfiguracji.") # LOGGING
            print(f"Próba połączenia SSH z hasłem: {auth_method}") # LOGGING
            ssh_client.connect(hostname=hostname, port=port, username=username, password=password, timeout=15) # LOGGING - Keep timeout
            print(f"Połączono z {hostname} używając {auth_method}") # LOGGING
        else:
            auth_method = "hasła (wprowadzonego ręcznie)"
            print(f"W konfiguracji dla {username}@{hostname} nie podano hasła ani ścieżki klucza.") # LOGGING
            print(f"Próba połączenia SSH z hasłem: {auth_method}") # LOGGING
            password_prompt = getpass.getpass(f"Podaj hasło SSH dla {username}@{hostname}: ")
            ssh_client.connect(hostname=hostname, port=port, username=username, password=password_prompt, timeout=15) # LOGGING - Keep timeout
            print(f"Połączono z {hostname} używając {auth_method}") # LOGGING

        print(f"Połączono z {hostname} używając {auth_method}") # LOGGING - Redundant line, already present above in each auth block
        return ssh_client

    except paramiko.AuthenticationException as auth_e: # LOGGING - Specific exception
        print(f"BŁĄD: Uwierzytelnienie nie powiodło się dla {username}@{hostname} przy użyciu {auth_method}.") # LOGGING
        print(f"  Szczegóły błędu uwierzytelnienia: {auth_e}") # LOGGING
    except paramiko.SSHException as sshException: # LOGGING - Specific exception
        print(f"BŁĄD: Nie można ustanowić połączenia SSH z {hostname}: {sshException}") # LOGGING
    except FileNotFoundError as e: # LOGGING - Specific exception
        print(f"BŁĄD: {e}") # LOGGING
    except Exception as e: # LOGGING - Catch-all exception
        print(f"BŁĄD: Wystąpił nieoczekiwany błąd podczas łączenia z {hostname}: {e}") # LOGGING

    return None

def execute_ssh_command(ssh_client, command):
       """Wykonuje komendę SSH i zwraca stdout, stderr oraz kod wyjścia."""
    if not ssh_client:
        return None, "Klient SSH nie jest połączony.", -1

    try:
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=30)
        exit_status = stdout.channel.recv_exit_status()
        stdout_data = stdout.read().decode('utf-8', errors='replace').strip()
        stderr_data = stderr.read().decode('utf-8', errors='replace').strip()
        return stdout_data, stderr_data, exit_status
    except Exception as e:
        print(f"BŁĄD: Błąd podczas wykonywania komendy '{command}': {e}")
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


def get_router_data(ssh_client, router_config):
    """Pobiera logi dmesg i inne dane z routera."""
    data = {
        'name': router_config['name'],
        'role': router_config['role'],
        'host': router_config['host'],
        'port': router_config['port'],
        'user': router_config['user'],
        'ssh_logs': "",
        'dmesg_logs': "",
        'uptime': "",
        'error': None,
    }

    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=router_config['host'], port=router_config['port'], username=router_config['user'], pkey=paramiko.RSAKey.from_private_key_file(router_config['key_path']), timeout=15)
        
        # Pobierz logi dmesg
        dmesg_output, _, _ = execute_ssh_command(ssh_client, "dmesg")
        data['dmesg_logs'] = dmesg_output
        
        # Pobierz uptime
        uptime_output, _, _ = execute_ssh_command(ssh_client, "uptime")
        data['uptime'] = uptime_output
        
        data['ssh_logs'] = "Połączenie pomyślne."
        ssh_client.close()
    except Exception as e:
        data['ssh_logs'] = f"Błąd połączenia: {e}"
        data['error'] = str(e)
        
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
    paragraphs = _paragraph_re.split(value)  # Use .split() to split into paragraphs
    result = '\n\n'.join(
        Markup(p).unescape() for p in paragraphs # Iterate over paragraphs
    )
    return Markup(result.replace('\n', '<br>\n'))

# --- Register the nl2br filter with Jinja2 ---
app.jinja_env.filters['nl2br'] = nl2br


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    analysis_hours = int(request.form['analysis_hours'])
    router_configs = load_config()

    if not router_configs:
        return render_template('error.html', error="Błąd konfiguracji routerów.")

    router_data = []
    for config in router_configs:
        router_data.append(get_router_data(None, config))  # Pass None to get_router_data

    # Perform Gemini analysis
    gemini_analysis = analyze_logs_with_gemini(router_data)

    return render_template('results.html', router_data=router_data, analysis_hours=analysis_hours, gemini_analysis=gemini_analysis)

if __name__ == "__main__":
    print(f"--- Analizator Logów Routera z Gemini ({GEMINI_MODEL_NAME}) ---")
    print("Uruchamianie serwera Flask...")
    app.run(debug=True, host='0.0.0.0', port=5000) # Uruchomienie serwera Flask
