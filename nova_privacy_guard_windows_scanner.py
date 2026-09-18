#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
 NOVA Privacy Guard v3.1  ::  UI 'Obsidian'  -  Auditoría forense local
===============================================================================
 POLÍTICA DE FUNCIONAMIENTO: SOLO LECTURA ("Zero Damage")
   * El Registro se abre EXCLUSIVAMENTE con winreg.KEY_READ.
   * Los archivos se abren en modo 'rb' (lectura binaria).
   * No se terminan procesos ni se cierran conexiones.
   * Cero telemetría: 100% local en tu equipo.

 Módulos:
   1. Registro (Startup)   - Claves Run / RunOnce (HKCU y HKLM).
   2. Procesos (Memoria)   - tasklist vs. lista negra de malware.
   3. Hardware (Cam/Mic)   - CapabilityAccessManager\\ConsentStore.
   4. Fugas de PII         - Tarjetas sin cifrar en Documentos (.txt/.csv).
   5. Red (Conexiones)     - netstat -ano: puertos sospechosos de RATs / C2.
   6. Integridad DNS       - Archivo hosts: redirecciones y sabotaje.
   7. Estado de Defensas   - Windows Defender, firewall y UAC saboteados.
===============================================================================
"""

import os
import sys
import time
import threading
import subprocess
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import font as tkfont

# winreg solo existe en Windows.
try:
    import winreg
except ImportError:
    winreg = None

APP_NAME = "NOVA Privacy Guard"
APP_VERSION = "3.1.0 Obsidian"

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

POLL_MS = 80
MAX_CONSOLE_LINES = 6000
MAX_PII_FILE_SIZE = 20 * 1024 * 1024
PII_EXTENSIONS = (".txt", ".csv")

MODULE_INFO = (
    ("Registro (Startup)",  "Claves Run / RunOnce en HKCU y HKLM"),
    ("Procesos (Memoria)",  "tasklist vs. lista negra de malware"),
    ("Hardware (Cam/Mic)",  "ConsentStore: acceso activo a cámara y micro"),
    ("Fugas de PII",        "Tarjetas sin cifrar en Documentos (.txt/.csv)"),
    ("Red (Conexiones)",    "netstat -ano: puertos de RAT y canales C2"),
    ("Integridad DNS",      "Archivo hosts: redirecciones y sabotaje"),
    ("Estado de Defensas",  "Defender, firewall y UAC desactivados"),
)
MODULE_COUNT = len(MODULE_INFO)

RISK_WEIGHT_ALERT = 12
RISK_WEIGHT_WARN = 4

RUN_SUBKEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)

STARTUP_HEURISTICS = (
    (re.compile(r"\\(?:temp|tmp)\\"), "Se ejecuta desde una carpeta temporal (Temp)", "ALERT"),
    (re.compile(r"\.(?:vbs|vbe|js|jse|wsf|wsh|hta)\b"), "Invoca un script de Windows Script Host (.vbs/.js/.wsf/.hta)", "ALERT"),
    (re.compile(r"\b(?:wscript|cscript|mshta)(?:\.exe)?\b"), "Usa un intérprete de scripts (wscript/cscript/mshta)", "ALERT"),
    (re.compile(r"powershell(?:\.exe)?.*?(?:\s-e(?:nc(?:odedcommand)?)?\s|-w(?:indowstyle)?\s+hidden|downloadstring|invoke-expression|\biex\b)"), "PowerShell oculto u ofuscado", "ALERT"),
    (re.compile(r"https?://"), "El comando de inicio contiene una URL remota", "ALERT"),
    (re.compile(r"\\users\\public\\"), "Ejecutable en la carpeta pública de usuarios", "ALERT"),
    (re.compile(r"\brundll32(?:\.exe)?\s+[^,]*\\(?:appdata|users\\public|programdata)\\"), "rundll32 cargando una DLL desde una ruta de usuario", "ALERT"),
    (re.compile(r"\.(?:bat|cmd|ps1|scr|pif)\b"), "Script por lotes / PowerShell / salvapantallas en el arranque", "WARN"),
    (re.compile(r"\\downloads\\"), "Se ejecuta desde la carpeta Descargas", "WARN"),
    (re.compile(r"\\appdata\\roaming\\[^\\]+\.exe"), "Ejecutable suelto en la raíz de AppData\\Roaming", "WARN"),
)

PROCESS_BLACKLIST = {
    "nc.exe": "Netcat - shell inversa / puerta trasera",
    "nc64.exe": "Netcat 64-bit - shell inversa / puerta trasera",
    "ncat.exe": "Ncat - shell inversa / puerta trasera",
    "netcat.exe": "Netcat - shell inversa / puerta trasera",
    "keylogger.exe": "Keylogger genérico (firma de prueba)",
    "mimikatz.exe": "Mimikatz - volcado de credenciales",
    "njrat.exe": "njRAT - troyano de acceso remoto",
    "darkcomet.exe": "DarkComet - troyano de acceso remoto",
    "quasar.exe": "Quasar RAT - troyano de acceso remoto",
    "remcos.exe": "Remcos RAT - troyano de acceso remoto",
    "asyncrat.exe": "AsyncRAT - troyano de acceso remoto",
}

PROCESS_TYPOSQUATS = {
    "svch0st.exe": "svchost.exe", "scvhost.exe": "svchost.exe",
    "svhost.exe": "svchost.exe",  "lsas.exe": "lsass.exe",
    "lsasss.exe": "lsass.exe",    "csrs.exe": "csrss.exe",
    "expl0rer.exe": "explorer.exe", "winlogin.exe": "winlogon.exe",
    "rundl32.exe": "rundll32.exe",  "taskhostw32.exe": "taskhostw.exe",
}

TASKLIST_RX = re.compile(r'^"([^"]+)","(\d+)"')
CONSENT_BASE = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
CAPABILITIES = (("webcam", "Cámara web"), ("microphone", "Micrófono"))
FILETIME_EPOCH_DIFF = 116444736000000000
FILETIME_PER_SECOND = 10_000_000

CARD_CANDIDATE_RX = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?!-?\d)")
CARD_BRANDS = (
    ("Visa", re.compile(r"^4\d{12}(?:\d{3}){0,2}$")),
    ("Mastercard", re.compile(r"^(?:5[1-5]\d{14}|(?:222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)\d{12})$")),
    ("AmEx", re.compile(r"^3[47]\d{13}$")),
    ("Discover", re.compile(r"^6(?:011|5\d{2}|4[4-9]\d)\d{12,15}$")),
    ("Diners", re.compile(r"^3(?:0[0-5]|[68]\d)\d{11,16}$")),
    ("JCB", re.compile(r"^35(?:2[89]|[3-8]\d)\d{12,15}$")),
)
MAX_CARD_HITS_PER_FILE = 1000

SUSPICIOUS_PORTS = {
    666: "Backdoor clásico (Doly / Attack FTP)",
    1337: "Puerto 'leet', habitual en backdoors caseros",
    1604: "Protocolo abusado por RATs de escritorio remoto",
    3127: "Gusano MyDoom",
    4444: "Metasploit Meterpreter (payload por defecto)",
    4445: "Metasploit / variantes de payload",
    5555: "ADB remoto / RATs multiplataforma",
    6666: "Bot IRC / backdoor",
    6667: "IRC - canal de control de botnets",
    6697: "IRC sobre TLS - canal de control de botnets",
    9001: "Tor ORPort / canal C2 encubierto",
    12345: "NetBus",
    12346: "NetBus (canal secundario)",
    20034: "NetBus 2 Pro",
    27374: "SubSeven",
    31337: "Back Orifice ('eleet')",
    54321: "Back Orifice 2000 / SchoolBus",
}

ESTABLISHED_STATES = {
    "ESTABLISHED", "ESTABLECIDO", "ESTABLECIDA", "ESTABELECIDO",
    "ETABLI", "HERGESTELLT", "STABILITO", "VERBUNDEN",
}
LISTENING_STATES = {
    "LISTENING", "ESCUCHAR", "ESCUCHANDO", "A LA ESCUCHA",
    "OUVIR", "ABHOREN", "ABHÖREN", "IN ATTESA",
}

DEFAULT_HOSTS_DIR = r"%SystemRoot%\System32\drivers\etc"
TCPIP_PARAMS_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
LOCAL_HOST_NAMES = {"localhost", "localhost.localdomain", "local",
                    "ip6-localhost", "ip6-loopback", "broadcasthost"}

SECURITY_DOMAIN_KEYWORDS = (
    "windowsupdate", "update.microsoft", "defender", "msftncsi", "msftconnecttest",
    "avast", "avg", "avira", "bitdefender", "eset", "nod32", "kaspersky", "mcafee",
    "norton", "symantec", "malwarebytes", "sophos", "trendmicro", "virustotal",
    "clamav", "drweb", "f-secure", "panda", "securelist", "spybot", "sucuri",
)

FINANCIAL_DOMAIN_KEYWORDS = (
    "bank", "banco", "banca", "paypal", "santander", "bbva", "caixa", "bancolombia",
    "chase", "wellsfargo", "citibank", "hsbc", "binance", "coinbase", "kraken",
    "metamask", "blockchain", "mercadopago", "westernunion",
)
BLOCKING_IPS = ("0.0.0.0", "::", "0::0")

DEFENDER_POLICY_ROOT = r"SOFTWARE\Policies\Microsoft\Windows Defender"
DEFENDER_RTP_ROOT = DEFENDER_POLICY_ROOT + r"\Real-Time Protection"

DEFENDER_CHECKS = (
    (DEFENDER_POLICY_ROOT, "DisableAntiSpyware", "Windows Defender (antispyware) DESACTIVADO por directiva", "ALERT"),
    (DEFENDER_POLICY_ROOT, "DisableAntiVirus", "Motor antivirus DESACTIVADO por directiva", "ALERT"),
    (DEFENDER_POLICY_ROOT, "DisableRoutinelyTakingAction", "Defender NO actúa automáticamente sobre las amenazas", "WARN"),
    (DEFENDER_RTP_ROOT, "DisableRealtimeMonitoring", "Protección en TIEMPO REAL desactivada", "ALERT"),
    (DEFENDER_RTP_ROOT, "DisableBehaviorMonitoring", "Análisis de comportamiento desactivado", "ALERT"),
    (DEFENDER_RTP_ROOT, "DisableOnAccessProtection", "Protección al acceder a archivos desactivada", "ALERT"),
    (DEFENDER_RTP_ROOT, "DisableIOAVProtection", "Análisis de descargas y adjuntos desactivado", "ALERT"),
    (DEFENDER_RTP_ROOT, "DisableScanOnRealtimeEnable", "Análisis al reactivar la protección desactivado", "WARN"),
)

DEFENDER_EXCLUSION_KEYS = (
    (r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", "ruta"),
    (r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions", "extension"),
    (r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes", "proceso"),
)
EXCLUSION_HIGH_RISK_RX = re.compile(
    r"^(?:c:\\?$|c:\\windows\\temp|.*\\appdata\\|.*\\temp\\|.*\\downloads\\|c:\\users\\public)", re.I)

FIREWALL_PROFILES = (("DomainProfile", "Dominio"), ("StandardProfile", "Privado"), ("PublicProfile", "Público"))
FIREWALL_ROOT = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
UAC_POLICY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

SECURITY_SERVICES = (
    ("WinDefend", "Antivirus de Microsoft Defender", "ALERT"),
    ("WdNisSvc", "Inspección de red de Defender", "ALERT"),
    ("Sense", "Defender for Endpoint (EDR)", "WARN"),
    ("SecurityHealthService", "Centro de seguridad de Windows", "ALERT"),
    ("MpsSvc", "Servicio de Firewall de Windows", "ALERT"),
    ("wscsvc", "Centro de seguridad (WSC)", "ALERT"),
    ("wuauserv", "Windows Update", "WARN"),
    ("EventLog", "Registro de eventos de Windows", "ALERT"),
)
SERVICES_ROOT = r"SYSTEM\CurrentControlSet\Services"

def hive_name(hive):
    if winreg is None:
        return "HK??"
    return {winreg.HKEY_CURRENT_USER: "HKCU", winreg.HKEY_LOCAL_MACHINE: "HKLM"}.get(hive, "HK??")

def reg_enum_values(hive, subkey, view_flag=0):
    values = []
    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
        index = 0
        while True:
            try:
                name, data, vtype = winreg.EnumValue(key, index)
            except OSError:
                break
            values.append((name, data, vtype))
            index += 1
    return values

def reg_enum_subkeys(hive, subkey, view_flag=0):
    names = []
    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
        index = 0
        while True:
            try:
                names.append(winreg.EnumKey(key, index))
            except OSError:
                break
            index += 1
    return names

def reg_query_int(key, value_name):
    try:
        data, _ = winreg.QueryValueEx(key, value_name)
        return int(data)
    except (OSError, ValueError, TypeError):
        return None

def reg_read_dword(hive, subkey, value_name):
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            value = reg_query_int(key, value_name)
            return (value, None) if value is not None else (None, "missing")
    except FileNotFoundError:
        return None, "missing"
    except (PermissionError, OSError):
        return None, "denied"

def extract_executable_path(command):
    cmd = command.strip()
    if not cmd:
        return None
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 1 else None
    match = re.match(r"^(.+?\.(?:exe|com|bat|cmd|vbs|js|ps1|scr|hta))\b", cmd, re.I)
    if match:
        return match.group(1)
    return cmd.split(" ")[0]

def analyze_startup_command(command):
    reasons, severity = [], "OK"
    expanded = os.path.expandvars(command)
    lowered = expanded.lower()

    for regex, reason, level in STARTUP_HEURISTICS:
        if regex.search(lowered):
            reasons.append(reason)
            if level == "ALERT":
                severity = "ALERT"
            elif severity == "OK":
                severity = "WARN"

    exe = extract_executable_path(expanded)
    try:
        if exe and os.path.isabs(exe) and not os.path.exists(exe):
            reasons.append("El ejecutable referenciado no existe (entrada huérfana)")
            if severity == "OK":
                severity = "WARN"
    except (OSError, ValueError):
        pass
    return severity, reasons

def decode_console_output(raw):
    for encoding in ("oem", "mbcs", "utf-8"):
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("latin-1", errors="replace")

def run_console_command(arguments, timeout=60):
    try:
        result = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except FileNotFoundError:
        return None, f"No se encontró '{arguments[0]}' en el sistema."
    except subprocess.TimeoutExpired:
        return None, f"'{arguments[0]}' excedió el tiempo límite ({timeout} s)."
    except OSError as exc:
        return None, f"No se pudo ejecutar '{arguments[0]}': {exc}"

    if result.returncode != 0:
        detail = decode_console_output(result.stderr).strip()
        return None, f"'{arguments[0]}' devolvió código {result.returncode}: {detail}"
    return decode_console_output(result.stdout), None

def filetime_to_str(filetime):
    try:
        if not filetime:
            return "-"
        epoch = (filetime - FILETIME_EPOCH_DIFF) / FILETIME_PER_SECOND
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))
    except (OSError, OverflowError, ValueError):
        return "fecha inválida"

def luhn_is_valid(digits):
    total = 0
    for position, char in enumerate(reversed(digits)):
        digit = ord(char) - 48
        if position % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0

def detect_card_brand(digits):
    for brand, regex in CARD_BRANDS:
        if regex.match(digits):
            return brand
    return None

def find_card_numbers(text):
    brands = []
    for match in CARD_CANDIDATE_RX.finditer(text):
        digits = re.sub(r"[ -]", "", match.group(0))
        if not 13 <= len(digits) <= 19:
            continue
        if len(set(digits)) == 1:
            continue
        if not luhn_is_valid(digits):
            continue
        brand = detect_card_brand(digits)
        if brand:
            brands.append(brand)
            if len(brands) >= MAX_CARD_HITS_PER_FILE:
                break
    return brands

def get_documents_folder():
    if winreg is not None:
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
                0, winreg.KEY_READ,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "Personal")
                path = os.path.expandvars(value)
                if os.path.isdir(path):
                    return path
        except OSError:
            pass
    return os.path.join(os.path.expanduser("~"), "Documents")

def is_link_or_junction(path):
    try:
        if os.path.islink(path):
            return True
        isjunction = getattr(os.path, "isjunction", None)
        return bool(isjunction and isjunction(path))
    except OSError:
        return True

def read_text_readonly(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="ignore")
    return raw.decode("utf-8", errors="ignore")

def split_endpoint(endpoint):
    if ":" not in endpoint:
        return endpoint, None
    address, _, port = endpoint.rpartition(":")
    try:
        return address, int(port)
    except ValueError:
        return endpoint, None

def is_loopback_address(address):
    clean = address.strip("[]").lower()
    return (clean.startswith("127.") or clean in ("::1", "0.0.0.0", "::", "*") or clean == "localhost")

def parse_netstat(text):
    connections = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].upper() not in ("TCP", "UDP"):
            continue
        if not parts[-1].isdigit():
            continue
        protocol = parts[0].upper()
        pid = int(parts[-1])
        local_ip, local_port = split_endpoint(parts[1])
        remote_ip, remote_port = split_endpoint(parts[2])
        state = " ".join(parts[3:-1]).strip().upper()
        connections.append({
            "protocol": protocol, "pid": pid, "state": state,
            "local_ip": local_ip, "local_port": local_port,
            "remote_ip": remote_ip, "remote_port": remote_port,
        })
    return connections

def is_established(state):
    if state in ESTABLISHED_STATES:
        return True
    normalized = state.replace("É", "E").replace("Ó", "O").replace("Ö", "O")
    return normalized in ESTABLISHED_STATES

def is_listening(state):
    return state in LISTENING_STATES or state.startswith("LISTEN")

def get_hosts_file_path():
    default_dir = os.path.expandvars(DEFAULT_HOSTS_DIR)
    if winreg is not None:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMS_KEY, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "DataBasePath")
                path = os.path.expandvars(value)
                if os.path.isdir(path):
                    return os.path.join(path, "hosts"), default_dir
        except OSError:
            pass
    return os.path.join(default_dir, "hosts"), default_dir

def parse_hosts_file(text):
    entries = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        entries.append((number, parts[0], parts[1:]))
    return entries

def is_blocking_ip(address):
    clean = address.strip("[]").lower()
    return clean.startswith("127.") or clean in ("::1", *BLOCKING_IPS)

def matches_keyword(hostname, keywords):
    lowered = hostname.lower()
    return any(keyword in lowered for keyword in keywords)

def compute_risk_score(alerts, warns):
    return min(100, alerts * RISK_WEIGHT_ALERT + warns * RISK_WEIGHT_WARN)

def risk_verdict(score):
    if score == 0:
        return "SISTEMA LIMPIO"
    if score < 25:
        return "RIESGO BAJO"
    if score < 60:
        return "RIESGO MEDIO"
    if score < 85:
        return "RIESGO ALTO"
    return "RIESGO CRÍTICO"

def has_admin_rights():
    try:
        os.listdir(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "config"))
        return True
    except OSError:
        return False

class ScanEngine:
    def __init__(self, emit, stop_event, enabled_modules):
        self.emit = emit
        self.stop_event = stop_event
        self.enabled = list(enabled_modules)
        self.findings = []
        self._current = 0
        self._completed = 0
        self._total = max(1, sum(1 for flag in self.enabled if flag))
        self._processes = None
        self._process_map = {}
        self._tasklist_failed = False

    def log(self, level, message):
        self.emit(("log", level, message))

    def add_finding(self, severity, detail):
        self.findings.append((self._current, severity, detail))
        self.log(severity, detail)
        self.emit(("finding", severity, self._current, detail))

    def progress(self, fraction, text=""):
        fraction = min(max(fraction, 0.0), 1.0)
        percent = (self._completed + fraction) / self._total * 100.0
        self.emit(("progress", percent, text))

    def stopped(self):
        return self.stop_event.is_set()

    def _load_processes(self):
        if self._processes is not None or self._tasklist_failed:
            return self._processes
        text, error = run_console_command(["tasklist", "/FO", "CSV", "/NH"])
        if error:
            self._tasklist_failed = True
            self.log("ERROR", error)
            return None
        processes = []
        for line in text.splitlines():
            match = TASKLIST_RX.match(line.strip())
            if match:
                processes.append((match.group(1), int(match.group(2))))
        self._processes = processes
        self._process_map = {pid: name for name, pid in processes}
        return processes

    def process_name(self, pid):
        self._load_processes()
        return self._process_map.get(pid, "proceso desconocido")

    def run(self):
        started = time.time()
        cancelled = False
        steps = (
            self.scan_registry_startup, self.scan_processes,
            self.scan_hardware_privacy, self.scan_pii_leaks,
            self.scan_network_connections, self.scan_hosts_integrity,
            self.scan_security_defenses
        )
        try:
            self.log("SYS", "Motor iniciado en hilo secundario - modo SOLO LECTURA activo.")
            if not has_admin_rights():
                self.log("WARN", "Ejecutando SIN privilegios de administrador: algunas claves "
                                  "de HKLM (exclusiones de Defender, servicios) pueden devolver "
                                  "'acceso denegado'.")
            for index, step in enumerate(steps):
                if not self.enabled[index]:
                    self.emit(("module", index, "SKIPPED", 0, 0))
                    continue
                if self.stopped():
                    cancelled = True
                    break

                self._current = index
                self.emit(("module", index, "RUNNING", 0, 0))
                self.log("HEAD", f"==== MÓDULO {index + 1}/{MODULE_COUNT} :: {MODULE_INFO[index][0].upper()} ====")
                before = len(self.findings)
                module_started = time.time()
                try:
                    step()
                    new = self.findings[before:]
                    alerts = sum(1 for f in new if f[1] == "ALERT")
                    warns = sum(1 for f in new if f[1] == "WARN")
                    state = "CANCELLED" if self.stopped() else "DONE"
                    self.emit(("module", index, state, alerts, warns))
                    self.log("SYS", f"Módulo {index + 1} finalizado en {time.time() - module_started:.2f} s.")
                except Exception as exc:
                    self.log("ERROR", f"Fallo inesperado en el módulo: {exc!r}")
                    self.emit(("module", index, "ERROR", 0, 0))
                self._completed += 1
                self.progress(0.0, "")
            cancelled = cancelled or self.stopped()
        except Exception as exc:
            self.log("ERROR", f"Error crítico del motor: {exc!r}")
        finally:
            alerts = sum(1 for f in self.findings if f[1] == "ALERT")
            warns = sum(1 for f in self.findings if f[1] == "WARN")
            score = compute_risk_score(alerts, warns)
            elapsed = time.time() - started
            self.log("HEAD", "==== RESUMEN DE LA AUDITORÍA ====")
            if cancelled:
                self.log("WARN", "Escaneo cancelado por el usuario: resultados parciales.")
            self.log("INFO", f"Duración: {elapsed:.1f} s | Alertas: {alerts} | Avisos: {warns}")
            self.log("INFO", f"Índice de riesgo: {score}/100 -> {risk_verdict(score)}")
            if alerts == 0 and warns == 0 and not cancelled:
                self.log("OK", "No se detectaron amenazas en los módulos ejecutados.")
            elif alerts:
                self.log("ALERT", "Revise manualmente cada ALERTA. NOVA no modifica el sistema.")
            self.emit(("done", {"alerts": alerts, "warns": warns, "score": score,
                                "elapsed": elapsed, "cancelled": cancelled}))

    def scan_registry_startup(self):
        targets = []
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for subkey in RUN_SUBKEYS:
                if hive == winreg.HKEY_LOCAL_MACHINE:
                    targets.append((hive, subkey, winreg.KEY_WOW64_64KEY, "x64"))
                    targets.append((hive, subkey, winreg.KEY_WOW64_32KEY, "x86"))
                else:
                    targets.append((hive, subkey, 0, ""))

        seen = set()
        total_entries = 0
        for number, (hive, subkey, view_flag, view) in enumerate(targets):
            if self.stopped():
                return
            short = subkey.rsplit("\\", 1)[-1]
            location = f"{hive_name(hive)}\\...\\{short}" + (f" ({view})" if view else "")
            self.progress(number / len(targets), f"Leyendo {location}")

            try:
                values = reg_enum_values(hive, subkey, view_flag)
            except FileNotFoundError:
                continue
            except PermissionError:
                self.log("WARN", f"{location}: acceso denegado (ejecute como administrador).")
                continue
            except OSError as exc:
                self.log("ERROR", f"{location}: no se pudo leer ({exc}).")
                continue

            for name, data, _vtype in values:
                command = data if isinstance(data, str) else str(data)
                signature = (hive, subkey.lower(), name.lower(), command.lower())
                if signature in seen:
                    continue
                seen.add(signature)
                total_entries += 1

                severity, reasons = analyze_startup_command(command)
                label = name or "(Predeterminado)"
                if severity == "OK":
                    self.log("OK", f"[{location}] '{label}' -> {command}")
                else:
                    self.add_finding(severity, f"[{location}] '{label}' -> {command} | Motivo: {'; '.join(reasons)}")
        self.log("INFO", f"Entradas de arranque analizadas: {total_entries}")
        self.progress(1.0, "Registro auditado")

    def scan_processes(self):
        self.progress(0.1, "Ejecutando tasklist...")
        processes = self._load_processes()
        if processes is None:
            return

        unique = len({name.lower() for name, _ in processes})
        self.log("INFO", f"Procesos en memoria: {len(processes)} ({unique} imágenes distintas).")

        hits = 0
        total = max(1, len(processes))
        for index, (name, pid) in enumerate(processes):
            if self.stopped():
                return
            if index % 25 == 0:
                self.progress(0.2 + 0.8 * index / total, f"Comparando procesos ({index}/{total})")
            lowered = name.lower()
            if lowered in PROCESS_BLACKLIST:
                hits += 1
                self.add_finding("ALERT", f"Proceso en lista negra: {name} (PID {pid}) -> {PROCESS_BLACKLIST[lowered]}")
            elif lowered in PROCESS_TYPOSQUATS:
                hits += 1
                self.add_finding("ALERT", f"Proceso suplantador: {name} (PID {pid}) imita a '{PROCESS_TYPOSQUATS[lowered]}'")
        if hits == 0:
            self.log("OK", "Ningún proceso activo coincide con la lista negra.")
        self.progress(1.0, "Procesos auditados")

    def scan_hardware_privacy(self):
        now_filetime = int(time.time() * FILETIME_PER_SECOND) + FILETIME_EPOCH_DIFF
        day = 24 * 3600 * FILETIME_PER_SECOND

        for number, (capability, label) in enumerate(CAPABILITIES):
            if self.stopped():
                return
            self.progress(number / len(CAPABILITIES), f"Consultando ConsentStore: {label}")
            cap_path = f"{CONSENT_BASE}\\{capability}"

            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(hive, cap_path, 0, winreg.KEY_READ) as key:
                        policy, _ = winreg.QueryValueEx(key, "Value")
                        self.log("INFO", f"{label} - política {hive_name(hive)}: {policy}")
                except OSError:
                    pass

            entries = self._collect_consent_entries(winreg.HKEY_CURRENT_USER, cap_path, label)
            active = [e for e in entries if e["active"]]
            if active:
                for entry in active:
                    self.add_finding("ALERT", f"{label} EN USO AHORA por: {entry['app']} (desde {filetime_to_str(entry['start'])})")
            else:
                self.log("OK", f"{label}: ninguna aplicación la está usando en este momento.")

            recent = sorted((e for e in entries if not e["active"] and e["stop"] and now_filetime - e["stop"] < day),
                            key=lambda e: e["stop"], reverse=True)
            for entry in recent[:5]:
                self.log("INFO", f"{label} - uso reciente: {entry['app']} (fin {filetime_to_str(entry['stop'])})")
            self.log("INFO", f"{label}: {len(entries)} aplicaciones con historial de acceso.")
        self.progress(1.0, "Hardware auditado")

    def _collect_consent_entries(self, hive, cap_path, label):
        entries = []
        try:
            subkeys = reg_enum_subkeys(hive, cap_path)
        except (FileNotFoundError, OSError):
            return entries

        for subkey in subkeys:
            if self.stopped():
                break
            if subkey.lower() == "nonpackaged":
                np_path = f"{cap_path}\\{subkey}"
                try:
                    apps = reg_enum_subkeys(hive, np_path)
                except OSError:
                    apps = []
                for app in apps:
                    entry = self._read_usage(hive, f"{np_path}\\{app}", app.replace("#", "\\"))
                    if entry:
                        entries.append(entry)
            else:
                entry = self._read_usage(hive, f"{cap_path}\\{subkey}", subkey)
                if entry:
                    entries.append(entry)
        return entries

    @staticmethod
    def _read_usage(hive, path, display_name):
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                start = reg_query_int(key, "LastUsedTimeStart")
                stop = reg_query_int(key, "LastUsedTimeStop") or 0
        except OSError:
            return None
        if not start:
            return None
        return {"app": display_name, "start": start, "stop": stop, "active": stop == 0 or stop < start}

    def scan_pii_leaks(self):
        documents = get_documents_folder()
        self.log("INFO", f"Carpeta objetivo: {documents}")
        if not os.path.isdir(documents):
            self.log("ERROR", "La carpeta Documentos no existe o no es accesible.")
            return

        self.progress(0.02, "Indexando archivos...")
        candidates = []

        for root, dirs, files in os.walk(documents, onerror=lambda e: None, followlinks=False):
            if self.stopped():
                return
            dirs[:] = [d for d in dirs if not is_link_or_junction(os.path.join(root, d))]
            for filename in files:
                if filename.lower().endswith(PII_EXTENSIONS):
                    candidates.append(os.path.join(root, filename))

        total = len(candidates)
        self.log("INFO", f"Archivos .txt/.csv a analizar: {total}")
        if total == 0:
            self.log("OK", "No hay archivos de texto que analizar.")
            return

        exposed = 0
        for index, path in enumerate(candidates):
            if self.stopped():
                return
            if index % 5 == 0:
                self.progress(0.05 + 0.95 * index / total, f"Analizando ({index + 1}/{total}): {os.path.basename(path)}")
            try:
                if os.path.getsize(path) > MAX_PII_FILE_SIZE:
                    continue
                text = read_text_readonly(path)
            except OSError:
                continue

            brands = find_card_numbers(text)
            del text
            if brands:
                exposed += 1
                summary = ", ".join(sorted(set(brands)))
                self.add_finding("ALERT", f"PII expuesta en: {os.path.relpath(path, documents)} | {len(brands)} posible(s) tarjeta(s) sin cifrar [{summary}] | Datos: ****-****-****-**** (ENMASCARADO)")
        if exposed == 0:
            self.log("OK", "No se encontraron números de tarjeta sin cifrar.")
        else:
            self.log("INFO", f"Archivos con PII expuesta: {exposed} de {total}.")
        self.progress(1.0, "PII auditada")

    def scan_network_connections(self):
        self.progress(0.1, "Ejecutando netstat -ano...")
        text, error = run_console_command(["netstat", "-ano"], timeout=90)
        if error:
            self.log("ERROR", error)
            return

        connections = parse_netstat(text)
        if not connections:
            self.log("WARN", "netstat no devolvió conexiones interpretables.")
            return

        self.progress(0.35, "Correlacionando PIDs con procesos...")
        self._load_processes()

        established = [c for c in connections if is_established(c["state"])]
        listening = [c for c in connections if is_listening(c["state"])]
        external = [c for c in established if not is_loopback_address(c["remote_ip"])]
        remote_hosts = {c["remote_ip"] for c in external}

        self.log("INFO", f"Sockets totales: {len(connections)} | Establecidas: {len(established)} | A la escucha: {len(listening)}")
        self.log("INFO", f"Conexiones hacia Internet: {len(external)} ({len(remote_hosts)} equipos remotos distintos).")

        hits = 0
        total = max(1, len(connections))
        for index, conn in enumerate(connections):
            if self.stopped():
                return
            if index % 50 == 0:
                self.progress(0.4 + 0.6 * index / total, f"Analizando conexiones ({index}/{total})")

            process = self.process_name(conn["pid"])
            local = f"{conn['local_ip']}:{conn['local_port']}"
            remote = f"{conn['remote_ip']}:{conn['remote_port']}"

            if is_established(conn["state"]):
                for port, side in ((conn["remote_port"], "remoto"), (conn["local_port"], "local")):
                    if port in SUSPICIOUS_PORTS:
                        hits += 1
                        loopback = is_loopback_address(conn["remote_ip"]) and is_loopback_address(conn["local_ip"])
                        severity = "WARN" if loopback else "ALERT"
                        note = " [tráfico local: posible falso positivo]" if loopback else ""
                        self.add_finding(
                            severity,
                            f"Conexión ESTABLECIDA en puerto {side} {port} ({SUSPICIOUS_PORTS[port]}) | {local} <-> {remote} | PID {conn['pid']} ({process}){note}"
                        )
                        break

            elif is_listening(conn["state"]) and conn["local_port"] in SUSPICIOUS_PORTS:
                hits += 1
                port = conn["local_port"]
                self.add_finding(
                    "ALERT",
                    f"Puerto {port} A LA ESCUCHA ({SUSPICIOUS_PORTS[port]}) | {local} | PID {conn['pid']} ({process}) -> posible puerta trasera esperando conexión"
                )

        if hits == 0:
            self.log("OK", "Ninguna conexión usa puertos asociados a RATs o C2 conocidos.")
        self.progress(1.0, "Red auditada")

    def scan_hosts_integrity(self):
        hosts_path, default_dir = get_hosts_file_path()
        self.log("INFO", f"Archivo hosts: {hosts_path}")
        self.progress(0.1, "Leyendo archivo hosts...")

        if os.path.normcase(os.path.dirname(hosts_path)) != os.path.normcase(default_dir):
            self.add_finding("WARN", f"La ruta del archivo hosts fue modificada en el Registro a: {os.path.dirname(hosts_path)}")

        try:
            text = read_text_readonly(hosts_path)
        except FileNotFoundError:
            self.log("INFO", "No existe el archivo hosts (situación limpia).")
            return
        except PermissionError:
            self.log("WARN", "Acceso denegado al archivo hosts (ejecute como administrador).")
            return
        except OSError as exc:
            self.log("ERROR", f"No se pudo leer el archivo hosts: {exc}")
            return

        entries = parse_hosts_file(text)
        computer = os.environ.get("COMPUTERNAME", "").lower()
        local_names = set(LOCAL_HOST_NAMES) | {computer} if computer else set(LOCAL_HOST_NAMES)

        self.progress(0.4, "Analizando entradas del archivo hosts...")
        self.log("INFO", f"Entradas activas: {len(entries)}")

        redirections = 0
        blocked = []
        total = max(1, len(entries))
        for index, (line_number, ip, hostnames) in enumerate(entries):
            if self.stopped():
                return
            if index % 200 == 0:
                self.progress(0.4 + 0.6 * index / total, f"Entradas hosts ({index}/{total})")

            for hostname in hostnames:
                name = hostname.lower().rstrip(".")
                blocking = is_blocking_ip(ip)

                if blocking and (name in local_names or name.endswith(".localhost")):
                    continue

                if blocking:
                    if matches_keyword(name, SECURITY_DOMAIN_KEYWORDS):
                        self.add_finding("ALERT", f"Línea {line_number}: '{hostname}' BLOQUEADO hacia {ip} -> sabotaje del antivirus")
                    else:
                        blocked.append(hostname)
                    continue

                redirections += 1
                if matches_keyword(name, FINANCIAL_DOMAIN_KEYWORDS):
                    self.add_finding("ALERT", f"Línea {line_number}: Dominio FINANCIERO '{hostname}' redirigido a {ip} -> troyano bancario / phishing.")
                elif matches_keyword(name, SECURITY_DOMAIN_KEYWORDS):
                    self.add_finding("ALERT", f"Línea {line_number}: Dominio de seguridad '{hostname}' redirigido a {ip} -> suplantación de antivirus.")
                else:
                    self.add_finding("ALERT", f"Línea {line_number}: '{hostname}' redirigido a IP externa {ip} -> secuestro de DNS local.")

        if blocked:
            examples = ", ".join(blocked[:3])
            self.log("INFO", f"{len(blocked)} dominios anulados hacia loopback (listas anti-publicidad). Ej: {examples}")
        if redirections == 0:
            self.log("OK", "El archivo hosts no contiene redirecciones a IPs externas.")
        self.progress(1.0, "Archivo hosts auditado")

    def scan_security_defenses(self):
        hklm = winreg.HKEY_LOCAL_MACHINE
        self.progress(0.05, "Comprobando directivas de Windows Defender...")
        sabotaged = 0
        for subkey, value_name, description, severity in DEFENDER_CHECKS:
            if self.stopped():
                return
            value, error = reg_read_dword(hklm, subkey, value_name)
            if error == "denied":
                continue
            if error == "missing":
                continue
            if value == 1:
                sabotaged += 1
                self.add_finding(severity, f"DEFENSA SABOTEADA: {description} [{value_name}=1 en HKLM\\{subkey}]")
            else:
                self.log("OK", f"{value_name}={value} (sin sabotaje).")

        if sabotaged == 0:
            self.log("OK", "Ninguna directiva desactiva Windows Defender.")

        self.progress(0.35, "Revisando exclusiones de Defender...")
        for subkey, kind in DEFENDER_EXCLUSION_KEYS:
            if self.stopped():
                return
            try:
                values = reg_enum_values(hklm, subkey)
            except (FileNotFoundError, PermissionError, OSError):
                continue

            for name, _data, _vtype in values:
                if EXCLUSION_HIGH_RISK_RX.match(name.strip()):
                    self.add_finding("ALERT", f"Exclusión de Defender de ALTO RIESGO ({kind}): '{name}'")
                else:
                    self.add_finding("WARN", f"Exclusión de Defender ({kind}): '{name}'")

        self.progress(0.6, "Comprobando el Firewall de Windows...")
        for profile_key, profile_label in FIREWALL_PROFILES:
            if self.stopped():
                return
            value, error = reg_read_dword(hklm, f"{FIREWALL_ROOT}\\{profile_key}", "EnableFirewall")
            if value == 0:
                self.add_finding("ALERT", f"Firewall de Windows DESACTIVADO en {profile_label} (EnableFirewall=0).")
            elif error is None:
                self.log("OK", f"Firewall ({profile_label}): activado.")

        self.progress(0.78, "Comprobando el Control de Cuentas (UAC)...")
        value, error = reg_read_dword(hklm, UAC_POLICY_KEY, "EnableLUA")
        if error is None and value == 0:
            self.add_finding("ALERT", "UAC DESACTIVADO (EnableLUA=0): programas pueden elevarse sin confirmar.")
        elif error is None:
            self.log("OK", "UAC activado (EnableLUA=1).")

        self.progress(0.9, "Comprobando servicios de seguridad...")
        for service, description, severity in SECURITY_SERVICES:
            if self.stopped():
                return
            value, error = reg_read_dword(hklm, f"{SERVICES_ROOT}\\{service}", "Start")
            if value == 4:
                self.add_finding(severity, f"Servicio DESHABILITADO: {service} ({description}) -> Start=4 en Registro.")
            elif error is None:
                self.log("OK", f"Servicio {service}: habilitado (tipo {value}).")
        self.progress(1.0, "Defensas auditadas")

C_BG = "#0B0F19"
C_PANEL = "#111827"
C_PANEL_ALT = "#161F32"
C_PANEL_HI = "#1B2639"
C_BORDER = "#1F2A3D"
C_BORDER_HI = "#2F3E58"
C_TEXT = "#E5E7EB"
C_TEXT_DIM = "#9AA7B8"
C_MUTED = "#64748B"
C_CONSOLE = "#080C14"

C_CYAN = "#22D3EE"
C_EMERALD = "#34D399"
C_AMBER = "#FBBF24"
C_CRIMSON = "#F43F5E"
C_VIOLET = "#A78BFA"
C_BLUE = "#60A5FA"
C_ORANGE = "#FB923C"

MODULE_ACCENTS = (C_CYAN, C_VIOLET, C_EMERALD, C_AMBER, C_BLUE, C_CYAN, C_VIOLET)

UI_FAMILY = "Segoe UI"
MONO_FAMILY = "Consolas"

FONT_BRAND = (UI_FAMILY, 21, "bold")
FONT_H1 = (UI_FAMILY, 12, "bold")
FONT_H2 = (UI_FAMILY, 10, "bold")
FONT_BODY = (UI_FAMILY, 9)
FONT_SMALL = (UI_FAMILY, 8)
FONT_BTN = (UI_FAMILY, 9, "bold")
FONT_STAT = (UI_FAMILY, 19, "bold")
FONT_SCORE = (UI_FAMILY, 34, "bold")
FONT_LABEL = (MONO_FAMILY, 8, "bold")
FONT_MONO = (MONO_FAMILY, 10)
FONT_MONO_BOLD = (MONO_FAMILY, 10, "bold")

LEVEL_STYLES = {
    "INFO":  ("INFO", C_CYAN),
    "OK":    ("OK", C_EMERALD),
    "WARN":  ("AVISO", C_AMBER),
    "ALERT": ("ALERTA", C_CRIMSON),
    "ERROR": ("ERROR", C_ORANGE),
    "SYS":   ("SYS", C_MUTED),
    "HEAD":  ("", C_EMERALD),
}
FILTERED_LEVELS = ("INFO", "OK", "SYS")

_BANNER_LETTERS = {
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "V": ["██╗   ██╗", "██║   ██║", "██║   ██║", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚═══╝  "],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
}
BANNER = "\n".join("  " + " ".join(_BANNER_LETTERS[c][row] for c in "NOVA") for row in range(6))

def blend(color_a, color_b, ratio):
    ratio = min(max(ratio, 0.0), 1.0)
    a = [int(color_a[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(color_b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * ratio) for i in range(3))

def rounded_points(x1, y1, x2, y2, radius):
    radius = min(radius, abs(x2 - x1) / 2, abs(y2 - y1) / 2)
    return [
        x1 + radius, y1, x2 - radius, y1, x2, y1, x2, y1 + radius,
        x2, y2 - radius, x2, y2, x2 - radius, y2, x1 + radius, y2,
        x1, y2, x1, y2 - radius, x1, y1 + radius, x1, y1,
    ]

def score_color(score):
    if score == 0:
        return C_EMERALD
    if score < 25:
        return C_EMERALD
    if score < 60:
        return C_AMBER
    return C_CRIMSON

class NeoButton(tk.Canvas):
    HOVER_STEP = 0.22
    FRAME_MS = 16

    def __init__(self, parent, text, command=None, kind="ghost", accent=C_CYAN,
                 height=38, radius=9, font=FONT_BTN, surface=None, padding=22):
        surface = surface or parent["bg"]
        super().__init__(parent, height=height, bg=surface, highlightthickness=0, bd=0, takefocus=0)
        self.text = text
        self.command = command
        self.kind = kind
        self.accent = accent
        self.radius = radius
        self.font = font
        self.surface = surface
        self._hover = 0.0
        self._target = 0.0
        self._pressed = False
        self._enabled = True
        self._active = False
        self._animation = None

        self.configure(width=tkfont.Font(font=font).measure(text) + padding * 2, cursor="hand2")
        self.bind("<Configure>", lambda _e: self._draw())
        self.bind("<Enter>", lambda _e: self._animate_to(1.0))
        self.bind("<Leave>", lambda _e: self._on_leave())
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _on_leave(self):
        self._pressed = False
        self._animate_to(0.0)

    def _on_press(self, _event):
        if self._enabled:
            self._pressed = True
            self._draw()

    def _on_release(self, _event):
        was_pressed = self._pressed
        self._pressed = False
        self._draw()
        if was_pressed and self._enabled and self.command is not None:
            self.command()

    def _animate_to(self, target):
        if not self._enabled:
            return
        self._target = target
        if self._animation is None:
            self._step()

    def _step(self):
        delta = self._target - self._hover
        if abs(delta) < 0.02:
            self._hover = self._target
            self._animation = None
            self._draw()
            return
        self._hover += delta * self.HOVER_STEP if abs(delta) > 0.05 else delta
        self._draw()
        try:
            self._animation = self.after(self.FRAME_MS, self._step)
        except tk.TclError:
            self._animation = None

    def set_enabled(self, enabled):
        self._enabled = bool(enabled)
        self._hover = self._target = 0.0
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw()

    def set_active(self, active):
        self._active = bool(active)
        self._draw()

    def set_text(self, text):
        self.text = text
        self._draw()

    def _palette(self):
        if not self._enabled:
            return C_PANEL, C_BORDER, C_MUTED
        if self.kind == "primary":
            fill = blend(self.accent, "#FFFFFF", 0.12 * self._hover)
            if self._pressed:
                fill = blend(fill, C_BG, 0.2)
            return fill, fill, C_BG
        if self.kind == "toggle" and self._active:
            fill = blend(C_PANEL_ALT, self.accent, 0.22 + 0.10 * self._hover)
            return fill, self.accent, self.accent
        fill = blend(C_PANEL_ALT, self.accent, 0.16 * self._hover)
        if self._pressed:
            fill = blend(fill, C_BG, 0.25)
        outline = blend(C_BORDER, self.accent, self._hover)
        text_color = blend(C_TEXT_DIM, self.accent, max(self._hover, 0.55))
        return fill, outline, text_color

    def _draw(self):
        width, height = self.winfo_width(), self.winfo_height()
        if width <= 1 or height <= 1:
            return
        fill, outline, text_color = self._palette()
        self.delete("all")
        self.create_polygon(rounded_points(1, 1, width - 1, height - 1, self.radius),
                            smooth=True, splinesteps=16, fill=fill, outline=outline)
        self.create_text(width / 2, height / 2 + 1, text=self.text,
                         fill=text_color, font=self.font)

class NeoProgress(tk.Canvas):
    def __init__(self, parent, height=8, surface=None, accent=C_CYAN):
        surface = surface or parent["bg"]
        super().__init__(parent, height=height, bg=surface, highlightthickness=0, bd=0)
        self.accent = accent
        self.value = 0.0
        self.bind("<Configure>", lambda _e: self._draw())

    def set_value(self, percent):
        self.value = min(max(percent, 0.0), 100.0)
        self._draw()

    def set_accent(self, color):
        self.accent = color
        self._draw()

    def _draw(self):
        width, height = self.winfo_width(), self.winfo_height()
        if width <= 1:
            return
        self.delete("all")
        radius = height / 2
        self.create_polygon(rounded_points(0, 0, width, height, radius),
                            smooth=True, splinesteps=12, fill=C_PANEL_HI, outline=C_PANEL_HI)
        filled = width * self.value / 100.0
        if filled > 2:
            self.create_polygon(rounded_points(0, 0, max(filled, height), height, radius),
                                smooth=True, splinesteps=12, fill=self.accent, outline=self.accent)

class RiskGauge(tk.Canvas):
    SWEEP = 240
    START = 210

    def __init__(self, parent, size=196, thickness=13, surface=C_PANEL):
        super().__init__(parent, width=size, height=int(size * 0.66), bg=surface, highlightthickness=0, bd=0)
        self.size = size
        self.thickness = thickness
        self.surface = surface
        self.value = 0.0
        self.target = 0.0
        self._animation = None
        self.bind("<Configure>", lambda _e: self._draw())

    def set_score(self, score, animate=True):
        self.target = float(min(max(score, 0), 100))
        if not animate:
            self.value = self.target
            self._draw()
        elif self._animation is None:
            self._step()

    def _step(self):
        delta = self.target - self.value
        if abs(delta) < 0.5:
            self.value = self.target
            self._animation = None
            self._draw()
            return
        self.value += delta * 0.2
        self._draw()
        try:
            self._animation = self.after(16, self._step)
        except tk.TclError:
            self._animation = None

    def _draw(self):
        width = self.winfo_width() or self.size
        height = self.winfo_height() or int(self.size * 0.66)
        if width <= 1:
            return
        self.delete("all")
        margin = self.thickness / 2 + 4
        diameter = min(width - margin * 2, (height - margin) * 4 / 3)
        if diameter < 40:
            return
        x1 = (width - diameter) / 2
        y1 = margin
        box = (x1, y1, x1 + diameter, y1 + diameter)

        self.create_arc(box, start=self.START, extent=-self.SWEEP, style="arc",
                        width=self.thickness, outline=C_PANEL_HI)
        color = score_color(self.value)
        extent = -self.SWEEP * self.value / 100.0
        if abs(extent) > 0.8:
            self.create_arc(box, start=self.START, extent=extent, style="arc",
                            width=self.thickness, outline=color)

        center_x = x1 + diameter / 2
        center_y = y1 + diameter / 2
        score_size = max(16, min(34, int(diameter * 0.23)))
        self.create_text(center_x, center_y - score_size * 0.12,
                         text=f"{int(round(self.value))}", fill=color,
                         font=(UI_FAMILY, score_size, "bold"))
        if diameter > 110:
            self.create_text(center_x, center_y + score_size * 0.85, text="ÍNDICE / 100",
                             fill=C_MUTED, font=FONT_LABEL)

class ModuleCard(tk.Frame):
    STATUS_TEXT = {
        "PENDING":   ("EN ESPERA", C_MUTED),
        "RUNNING":   ("ANALIZANDO", C_CYAN),
        "SKIPPED":   ("OMITIDO", C_MUTED),
        "CANCELLED": ("CANCELADO", C_ORANGE),
        "ERROR":     ("ERROR", C_ORANGE),
        "CLEAN":     ("LIMPIO", C_EMERALD),
    }

    def __init__(self, parent, index, title, description, accent, on_toggle):
        super().__init__(parent, bg=C_PANEL, highlightbackground=C_BORDER,
                         highlightcolor=C_BORDER, highlightthickness=1)
        self.index = index
        self.accent = accent
        self.on_toggle = on_toggle
        self.var = tk.BooleanVar(value=True)
        self._hovered = False

        self.stripe = tk.Frame(self, bg=accent, height=3)
        self.stripe.pack(fill="x")

        header = tk.Frame(self, bg=C_PANEL)
        header.pack(fill="x", padx=14, pady=(12, 0))
        self.chip = tk.Label(header, text=f"{index + 1:02d}", font=FONT_LABEL,
                             fg=accent, bg=blend(C_PANEL, accent, 0.14), padx=6, pady=2)
        self.chip.pack(side="left")
        self.switch = tk.Label(header, text="●", font=(UI_FAMILY, 11), fg=accent, bg=C_PANEL)
        self.switch.pack(side="right")

        self.title = tk.Label(self, text=title, font=FONT_H2, fg=C_TEXT, bg=C_PANEL,
                              anchor="w", justify="left", wraplength=180)
        self.title.pack(fill="x", padx=14, pady=(8, 0))
        self.description = tk.Label(self, text=description, font=FONT_SMALL, fg=C_MUTED,
                                    bg=C_PANEL, anchor="nw", justify="left", wraplength=190, height=2)
        self.description.pack(fill="x", padx=14, pady=(2, 0))
        self.status = tk.Label(self, text="● EN ESPERA", font=FONT_LABEL, fg=C_MUTED, bg=C_PANEL, anchor="w")
        self.status.pack(fill="x", padx=14, pady=(8, 12))

        self._surfaces = [self, header, self.chip, self.switch, self.title, self.description, self.status]
        for widget in self._surfaces:
            widget.bind("<Button-1>", self._toggle)
            widget.bind("<Enter>", self._on_enter)
            widget.bind("<Leave>", self._on_leave)
            widget.configure(cursor="hand2")

    def _toggle(self, _event=None):
        self.var.set(not self.var.get())
        self._refresh_enabled()
        if self.on_toggle:
            self.on_toggle()

    def _on_enter(self, _event=None):
        self._hovered = True
        self._paint(C_PANEL_ALT)
        self.configure(highlightbackground=C_BORDER_HI, highlightcolor=C_BORDER_HI)

    def _on_leave(self, _event=None):
        self._hovered = False
        self._paint(C_PANEL)
        self.configure(highlightbackground=C_BORDER, highlightcolor=C_BORDER)

    def _paint(self, surface):
        for widget in self._surfaces:
            if widget is not self.chip:
                widget.configure(bg=surface)
        self.chip.configure(bg=blend(surface, self.accent, 0.14))

    def _refresh_enabled(self):
        enabled = self.var.get()
        self.switch.configure(text="●" if enabled else "○", fg=self.accent if enabled else C_MUTED)
        self.title.configure(fg=C_TEXT if enabled else C_MUTED)
        self.chip.configure(fg=self.accent if enabled else C_MUTED)
        self.stripe.configure(bg=blend(C_PANEL, self.accent, 0.5) if enabled else C_BORDER)
        if not enabled:
            self.status.configure(text="○ DESACTIVADO", fg=C_MUTED)
        else:
            self.status.configure(text="● EN ESPERA", fg=C_MUTED)

    def reset(self):
        self._refresh_enabled()

    def set_status(self, state, alerts=0, warns=0):
        if state == "DONE":
            if alerts:
                text = f"{alerts} ALERTA(S)" + (f" · {warns} AVISO(S)" if warns else "")
                color = C_CRIMSON
            elif warns:
                text, color = f"{warns} AVISO(S)", C_AMBER
            else:
                text, color = self.STATUS_TEXT["CLEAN"]
        else:
            text, color = self.STATUS_TEXT.get(state, self.STATUS_TEXT["PENDING"])
        symbol = "◉" if state == "RUNNING" else "●"
        self.status.configure(text=f"{symbol} {text}", fg=color)
        self.stripe.configure(bg=color if state != "SKIPPED" else C_BORDER)

class NovaPrivacyGuardApp:
    def __init__(self, root):
        self.root = root
        self.stop_event = threading.Event()
        self.worker = None
        self._events = []
        self._events_lock = threading.Lock()
        self._closing = False
        self.log_lines = []
        self.findings = []
        self.counters = {"ALERT": 0, "WARN": 0}
        self.scan_started = None
        self.elapsed = 0.0

        self._configure_window()
        self._configure_styles()
        self._build_ui()
        self._bind_shortcuts()
        self._print_banner()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(POLL_MS, self._poll_events)

    def _configure_window(self):
        self.root.title(f"{APP_NAME} v{APP_VERSION}  ·  Modo SOLO LECTURA")
        self.root.configure(bg=C_BG)
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        width = min(1320, screen_w - 80)
        height = min(900, screen_h - 120)
        self.root.geometry(f"{width}x{height}+{(screen_w - width) // 2}+{max((screen_h - height) // 2 - 20, 0)}")
        self.root.minsize(1120, 620)

    def _configure_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Nova.Vertical.TScrollbar", troughcolor=C_CONSOLE,
                        background=C_PANEL_ALT, darkcolor=C_PANEL_ALT,
                        lightcolor=C_PANEL_ALT, bordercolor=C_CONSOLE,
                        arrowcolor=C_MUTED, borderwidth=0, arrowsize=12)
        style.map("Nova.Vertical.TScrollbar", background=[("active", C_BORDER_HI)])

    def _build_ui(self):
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self._build_appbar()

        body = tk.Frame(self.root, bg=C_BG)
        body.grid(row=1, column=0, sticky="nsew", padx=24, pady=(0, 14))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)

        self._build_sidebar(body)
        self._build_workspace(body)
        self._build_statusbar()

    def _build_appbar(self):
        bar = tk.Frame(self.root, bg=C_BG)
        bar.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 16))

        brand = tk.Frame(bar, bg=C_BG)
        brand.pack(side="left")
        line = tk.Frame(brand, bg=C_BG)
        line.pack(anchor="w")
        tk.Label(line, text="NOVA", font=FONT_BRAND, fg=C_EMERALD, bg=C_BG).pack(side="left")
        tk.Label(line, text="PRIVACY GUARD", font=FONT_BRAND, fg=C_TEXT, bg=C_BG).pack(side="left", padx=(8, 0))
        tk.Label(brand, text="Auditoría forense local  ·  7 módulos  ·  sin agentes ni telemetría",
                 font=FONT_BODY, fg=C_MUTED, bg=C_BG).pack(anchor="w", pady=(2, 0))

        badges = tk.Frame(bar, bg=C_BG)
        badges.pack(side="right")
        self._badge(badges, "■  READ-ONLY · ZERO DAMAGE", C_EMERALD).pack(side="right")
        host = f"{os.environ.get('COMPUTERNAME', '?')} / {os.environ.get('USERNAME', '?')}"
        tk.Label(badges, text=host, font=FONT_SMALL, fg=C_MUTED, bg=C_BG).pack(side="right", padx=(0, 14))

        tk.Frame(self.root, bg=C_BORDER, height=1).grid(row=0, column=0, sticky="sew", padx=24)

    def _badge(self, parent, text, accent):
        width = tkfont.Font(font=FONT_LABEL).measure(text) + 26
        canvas = tk.Canvas(parent, width=width, height=26, bg=C_BG, highlightthickness=0, bd=0)
        canvas.create_polygon(rounded_points(1, 1, width - 1, 25, 12), smooth=True, splinesteps=16,
                              fill=blend(C_BG, accent, 0.16), outline=blend(C_BG, accent, 0.45))
        canvas.create_text(width / 2, 13, text=text, fill=accent, font=FONT_LABEL)
        return canvas

    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=C_BG, width=300, height=600)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        sidebar.grid_propagate(False)

        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(0, weight=1, minsize=150)

        gauge_card = tk.Frame(sidebar, bg=C_PANEL, highlightbackground=C_BORDER, highlightthickness=1)
        gauge_card.grid(row=0, column=0, sticky="nsew")
        tk.Label(gauge_card, text="ÍNDICE DE RIESGO", font=FONT_LABEL, fg=C_MUTED, bg=C_PANEL).pack(anchor="w", padx=16, pady=(12, 0))
        self.lbl_verdict = tk.Label(gauge_card, text="SIN ANALIZAR", font=FONT_H1, fg=C_MUTED, bg=C_PANEL)
        self.lbl_verdict.pack(side="bottom", pady=(0, 12))
        self.gauge = RiskGauge(gauge_card, size=214, thickness=13)
        self.gauge.pack(padx=16, pady=(4, 0), fill="both", expand=True)

        stats = tk.Frame(sidebar, bg=C_BG)
        stats.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        stats.grid_columnconfigure(0, weight=1, uniform="stat")
        stats.grid_columnconfigure(1, weight=1, uniform="stat")
        self.stat_alerts = self._stat_tile(stats, "ALERTAS", C_CRIMSON, 0, 0)
        self.stat_warns = self._stat_tile(stats, "AVISOS", C_AMBER, 0, 1)

        actions = tk.Frame(sidebar, bg=C_BG)
        actions.grid(row=2, column=0, sticky="ew", pady=(14, 0))
        self._build_actions(actions)

        tk.Label(sidebar, text=f"v{APP_VERSION}  ·  F5 escanear · Esc detener · Ctrl+S · Ctrl+E",
                 font=FONT_SMALL, fg=C_MUTED, bg=C_BG, justify="left").grid(row=3, column=0, sticky="w", pady=(12, 0))

    def _build_actions(self, actions):
        tk.Label(actions, text="CONTROL DE ESCANEO", font=FONT_LABEL, fg=C_MUTED, bg=C_BG).pack(anchor="w", pady=(0, 8))
        self.btn_start = NeoButton(actions, "INICIAR ESCANEO", self.start_scan, kind="primary", accent=C_EMERALD, height=42)
        self.btn_start.pack(fill="x")
        self.btn_stop = NeoButton(actions, "DETENER", self.stop_scan, accent=C_CRIMSON, height=34)
        self.btn_stop.pack(fill="x", pady=(8, 0))
        self.btn_stop.set_enabled(False)

        grid = tk.Frame(actions, bg=C_BG)
        grid.pack(fill="x", pady=(12, 0))
        grid.grid_columnconfigure(0, weight=1, uniform="act")
        grid.grid_columnconfigure(1, weight=1, uniform="act")
        self.btn_clear = NeoButton(grid, "LIMPIAR", self.clear_console, accent=C_CYAN, height=31, font=FONT_SMALL, padding=10)
        self.btn_copy = NeoButton(grid, "COPIAR", self.copy_log, accent=C_CYAN, height=31, font=FONT_SMALL, padding=10)
        self.btn_export = NeoButton(grid, "INFORME TXT", self.export_report, accent=C_AMBER, height=31, font=FONT_SMALL, padding=10)
        self.btn_csv = NeoButton(grid, "HALLAZGOS CSV", self.export_findings_csv, accent=C_AMBER, height=31, font=FONT_SMALL, padding=10)
        self.btn_clear.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self.btn_copy.grid(row=0, column=1, sticky="ew", padx=(4, 0))
        self.btn_export.grid(row=1, column=0, sticky="ew", padx=(0, 4), pady=(8, 0))
        self.btn_csv.grid(row=1, column=1, sticky="ew", padx=(4, 0), pady=(8, 0))

    def _stat_tile(self, parent, label, accent, row, column, value="0"):
        tile = tk.Frame(parent, bg=C_PANEL, highlightbackground=C_BORDER, highlightthickness=1)
        tile.grid(row=row, column=column, sticky="nsew", padx=(0, 5) if column == 0 else (5, 0), pady=(0, 0) if row == 0 else (10, 0))
        value_label = tk.Label(tile, text=value, font=FONT_STAT, fg=accent, bg=C_PANEL)
        value_label.pack(anchor="w", padx=14, pady=(8, 0))
        tk.Label(tile, text=label, font=FONT_LABEL, fg=C_MUTED, bg=C_PANEL).pack(anchor="w", padx=14, pady=(0, 8))
        return value_label

    def _build_workspace(self, parent):
        workspace = tk.Frame(parent, bg=C_BG)
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.grid_rowconfigure(2, weight=1, minsize=150)
        workspace.grid_columnconfigure(0, weight=1)

        cards = tk.Frame(workspace, bg=C_BG)
        cards.grid(row=0, column=0, sticky="ew")
        for column in range(4):
            cards.grid_columnconfigure(column, weight=1, uniform="cards")

        self.cards = []
        for index, (title, description) in enumerate(MODULE_INFO):
            row, column = divmod(index, 4)
            card = ModuleCard(cards, index, title, description, MODULE_ACCENTS[index % len(MODULE_ACCENTS)], self._on_module_toggle)
            card.grid(row=row, column=column, sticky="nsew", padx=(0 if column == 0 else 10, 0), pady=(0 if row == 0 else 10, 0))
            self.cards.append(card)
        self.module_vars = [card.var for card in self.cards]

        row, column = divmod(MODULE_COUNT, 4)
        selector = tk.Frame(cards, bg=C_PANEL, highlightbackground=C_BORDER, highlightthickness=1)
        selector.grid(row=row, column=column, sticky="nsew", padx=(0 if column == 0 else 10, 0), pady=(10, 0))
        tk.Label(selector, text="SELECCIÓN", font=FONT_LABEL, fg=C_MUTED, bg=C_PANEL).pack(anchor="w", padx=14, pady=(14, 0))
        tk.Label(selector, text="Haz clic en una tarjeta\npara activarla o no", font=FONT_SMALL, fg=C_MUTED, bg=C_PANEL, justify="left", anchor="w").pack(fill="x", padx=14, pady=(4, 8))
        buttons = tk.Frame(selector, bg=C_PANEL)
        buttons.pack(fill="x", padx=14, pady=(0, 14))
        NeoButton(buttons, "TODOS", lambda: self._select_modules(True), accent=C_EMERALD, height=30, font=FONT_SMALL, surface=C_PANEL, padding=12).pack(side="left", expand=True, fill="x", padx=(0, 4))
        NeoButton(buttons, "NINGUNO", lambda: self._select_modules(False), accent=C_MUTED, height=30, font=FONT_SMALL, surface=C_PANEL, padding=12).pack(side="left", expand=True, fill="x", padx=(4, 0))

        progress_card = tk.Frame(workspace, bg=C_PANEL, highlightbackground=C_BORDER, highlightthickness=1)
        progress_card.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        head = tk.Frame(progress_card, bg=C_PANEL)
        head.pack(fill="x", padx=18, pady=(14, 0))
        self.lbl_task = tk.Label(head, text="Listo. Selecciona los módulos y pulsa INICIAR ESCANEO (F5).", font=FONT_BODY, fg=C_TEXT_DIM, bg=C_PANEL, anchor="w")
        self.lbl_task.pack(side="left")
        self.lbl_percent = tk.Label(head, text="0%", font=FONT_H1, fg=C_EMERALD, bg=C_PANEL)
        self.lbl_percent.pack(side="right")
        self.progress = NeoProgress(progress_card, height=8, surface=C_PANEL, accent=C_EMERALD)
        self.progress.pack(fill="x", padx=18, pady=(10, 16))

        console_card = tk.Frame(workspace, bg=C_CONSOLE, highlightbackground=C_BORDER, highlightthickness=1)
        console_card.grid(row=2, column=0, sticky="nsew", pady=(16, 0))
        console_card.grid_rowconfigure(1, weight=1)
        console_card.grid_columnconfigure(0, weight=1)

        titlebar = tk.Frame(console_card, bg=C_PANEL)
        titlebar.grid(row=0, column=0, sticky="ew")
        dots = tk.Canvas(titlebar, width=52, height=26, bg=C_PANEL, highlightthickness=0, bd=0)
        for position, color in enumerate((C_CRIMSON, C_AMBER, C_EMERALD)):
            x = 16 + position * 13
            dots.create_oval(x - 4, 9, x + 4, 17, fill=blend(C_PANEL, color, 0.75), outline="")
        dots.pack(side="left")
        tk.Label(titlebar, text="nova@guard  ~  registro en vivo", font=(MONO_FAMILY, 9), fg=C_MUTED, bg=C_PANEL).pack(side="left", pady=5)
        self.filter_var = tk.BooleanVar(value=False)
        self.btn_filter = NeoButton(titlebar, "SOLO ALERTAS", self._toggle_filter, kind="toggle", accent=C_AMBER, height=24, radius=7, font=FONT_SMALL, surface=C_PANEL, padding=12)
        self.btn_filter.pack(side="right", padx=10, pady=4)

        self.console = tk.Text(console_card, bg=C_CONSOLE, fg=C_TEXT_DIM, insertbackground=C_EMERALD, selectbackground="#1D3A5C",
                               font=FONT_MONO, relief="flat", bd=0, padx=18, pady=14, wrap="word", state="disabled", spacing1=2, spacing3=3, cursor="arrow")
        self.console.grid(row=1, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(console_card, orient="vertical", command=self.console.yview, style="Nova.Vertical.TScrollbar")
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.console.configure(yscrollcommand=scrollbar.set)

        self.console.tag_configure("ts", foreground=C_MUTED)
        self.console.tag_configure("msg", foreground=C_TEXT_DIM)
        self.console.tag_configure("msg_ALERT", foreground="#FFC2CD")
        self.console.tag_configure("msg_WARN", foreground="#FFE3A3")
        self.console.tag_configure("msg_OK", foreground="#A7F3D0")
        self.console.tag_configure("head", foreground=C_EMERALD, font=FONT_MONO_BOLD, spacing1=10, spacing3=6)
        self.console.tag_configure("banner", foreground=C_EMERALD)
        self.console.tag_configure("subtitle", foreground=C_MUTED)
        for level, (_label, color) in LEVEL_STYLES.items():
            self.console.tag_configure(f"chip_{level}", foreground=C_BG, background=color, font=(MONO_FAMILY, 9, "bold"))
            self.console.tag_configure(f"line_{level}")

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=C_PANEL, height=30)
        bar.grid(row=2, column=0, sticky="ew")
        self.state_dot = tk.Label(bar, text="●", font=(UI_FAMILY, 10), fg=C_MUTED, bg=C_PANEL)
        self.state_dot.pack(side="left", padx=(24, 6))
        self.lbl_state = tk.Label(bar, text="INACTIVO", font=FONT_LABEL, fg=C_MUTED, bg=C_PANEL)
        self.lbl_state.pack(side="left", pady=7)
        tk.Label(bar, text="Registro: KEY_READ  ·  Archivos: modo 'rb'  ·  Procesos: solo lectura",
                 font=FONT_SMALL, fg=C_MUTED, bg=C_PANEL).pack(side="right", padx=(0, 24))
        tk.Label(bar, text="│", font=FONT_SMALL, fg=C_BORDER_HI, bg=C_PANEL).pack(side="right", padx=14)
        self.stat_time = tk.Label(bar, text="TIEMPO 00:00", font=FONT_LABEL, fg=C_CYAN, bg=C_PANEL)
        self.stat_time.pack(side="right")
        self.stat_modules = tk.Label(bar, text=f"MÓDULOS {MODULE_COUNT}/{MODULE_COUNT}", font=FONT_LABEL, fg=C_EMERALD, bg=C_PANEL)
        self.stat_modules.pack(side="right", padx=(0, 16))

    def _bind_shortcuts(self):
        self.root.bind("<F5>", lambda _e: self.start_scan())
        self.root.bind("<Escape>", lambda _e: self.stop_scan())
        self.root.bind("<Control-s>", lambda _e: self.export_report())
        self.root.bind("<Control-e>", lambda _e: self.export_findings_csv())
        self.root.bind("<Control-l>", lambda _e: self.clear_console())

    def _print_banner(self):
        self.console.configure(state="normal")
        self.console.insert("end", BANNER + "\n", "banner")
        self.console.insert("end", f"  PRIVACY GUARD v{APP_VERSION}   ::   auditor forense de solo lectura   ::   7 módulos\n\n", "subtitle")
        self.console.configure(state="disabled")
        try:
            winver = sys.getwindowsversion()
            os_text = f"Windows {winver.major}.{winver.minor} build {winver.build}"
        except AttributeError:
            os_text = sys.platform
        self._append_log("SYS", f"Equipo: {os.environ.get('COMPUTERNAME', '?')} | Usuario: {os.environ.get('USERNAME', '?')} | {os_text} | Python {sys.version.split()[0]}")
        self._append_log("SYS", "Política Zero Damage: Registro con KEY_READ, archivos en modo 'rb', sin terminar procesos ni cerrar conexiones.")
        self._append_log("SYS", "Atajos: F5 escanear · Esc detener · Ctrl+S informe · Ctrl+E CSV · Ctrl+L limpiar.")
        if not IS_WINDOWS or winreg is None:
            self._append_log("ERROR", "Este sistema no es Windows: el escaneo está deshabilitado.")

    def emit(self, event):
        with self._events_lock:
            self._events.append(event)

    def _poll_events(self):
        if self._closing:
            return
        with self._events_lock:
            events, self._events = self._events, []
        for event in events:
            self._handle_event(event)
        if self.scan_started is not None:
            self.elapsed = time.time() - self.scan_started
        self._refresh_counters()
        try:
            self.root.after(POLL_MS, self._poll_events)
        except tk.TclError:
            pass

    def _handle_event(self, event):
        kind = event[0]
        if kind == "log":
            self._append_log(event[1], event[2])
        elif kind == "finding":
            severity, module_index, detail = event[1], event[2], event[3]
            self.counters[severity] = self.counters.get(severity, 0) + 1
            self.findings.append((time.strftime("%Y-%m-%d %H:%M:%S"), MODULE_INFO[module_index][0], severity, detail))
            if severity == "ALERT":
                self.progress.set_accent(C_CRIMSON)
                self.lbl_percent.configure(fg=C_CRIMSON)
        elif kind == "progress":
            percent = event[1]
            self.progress.set_value(percent)
            self.lbl_percent.configure(text=f"{percent:.0f}%")
            if event[2]:
                text = event[2]
                self.lbl_task.configure(text=text if len(text) <= 110 else text[:107] + "...")
        elif kind == "module":
            self.cards[event[1]].set_status(event[2], event[3], event[4])
        elif kind == "done":
            self._on_scan_finished(event[1])

    def _append_log(self, level, message):
        timestamp = time.strftime("%H:%M:%S")
        label, _color = LEVEL_STYLES.get(level, LEVEL_STYLES["INFO"])
        line_tag = f"line_{level}"
        self.console.configure(state="normal")
        if level == "HEAD":
            self.console.insert("end", f"{message}\n", ("head", line_tag))
            plain = f"\n[{timestamp}] {message}"
        else:
            body_tag = f"msg_{level}" if level in ("ALERT", "WARN", "OK") else "msg"
            self.console.insert("end", f"{timestamp}  ", ("ts", line_tag))
            self.console.insert("end", f" {label} ", (f"chip_{level}", line_tag))
            self.console.insert("end", "  " + message + "\n", (body_tag, line_tag))
            plain = f"[{timestamp}] [{label}] {message}"

        line_count = int(self.console.index("end-1c").split(".")[0])
        if line_count > MAX_CONSOLE_LINES:
            self.console.delete("1.0", f"{line_count - MAX_CONSOLE_LINES}.0")
        self.console.configure(state="disabled")
        self.console.see("end")
        self.log_lines.append(plain)

    def _toggle_filter(self):
        self.filter_var.set(not self.filter_var.get())
        self.btn_filter.set_active(self.filter_var.get())
        self._apply_filter()

    def _apply_filter(self):
        hide = self.filter_var.get()
        for level in FILTERED_LEVELS:
            self.console.tag_configure(f"line_{level}", elide=hide)
        self.console.see("end")

    def _refresh_counters(self):
        minutes, seconds = divmod(int(self.elapsed), 60)
        self.stat_alerts.configure(text=str(self.counters["ALERT"]))
        self.stat_warns.configure(text=str(self.counters["WARN"]))
        self.stat_time.configure(text=f"TIEMPO {minutes:02d}:{seconds:02d}")
        score = compute_risk_score(self.counters["ALERT"], self.counters["WARN"])
        self.gauge.set_score(score)
        if self.scan_started is not None or score:
            self.lbl_verdict.configure(text=risk_verdict(score), fg=score_color(score))

    def _on_module_toggle(self):
        active = sum(1 for var in self.module_vars if var.get())
        self.stat_modules.configure(text=f"MÓDULOS {active}/{MODULE_COUNT}", fg=C_EMERALD if active else C_MUTED)

    def _select_modules(self, value):
        for card in self.cards:
            card.var.set(value)
            card.reset()
        self._on_module_toggle()

    def _set_state_pill(self, text, color):
        self.lbl_state.configure(text=text, fg=color)
        self.state_dot.configure(fg=color)

    def start_scan(self):
        if self.worker is not None and self.worker.is_alive():
            return
        if not IS_WINDOWS or winreg is None:
            messagebox.showerror(APP_NAME, "NOVA Privacy Guard solo puede ejecutarse en Windows.")
            return
        enabled = [var.get() for var in self.module_vars]
        if not any(enabled):
            messagebox.showwarning(APP_NAME, "Selecciona al menos un módulo de auditoría.")
            return

        self.counters = {"ALERT": 0, "WARN": 0}
        self.findings = []
        self.elapsed = 0.0
        self.progress.set_value(0)
        self.progress.set_accent(C_EMERALD)
        self.lbl_percent.configure(text="0%", fg=C_EMERALD)
        self.gauge.set_score(0, animate=False)
        for card in self.cards:
            card.reset()

        self.btn_start.set_enabled(False)
        self.btn_stop.set_enabled(True)
        self.btn_export.set_enabled(False)
        self.btn_csv.set_enabled(False)
        self._set_state_pill("ESCANEANDO", C_CYAN)
        self._append_log("HEAD", "#### NUEVA AUDITORÍA INICIADA ####")

        self.stop_event.clear()
        engine = ScanEngine(self.emit, self.stop_event, enabled)
        self.worker = threading.Thread(target=engine.run, name="NovaScanWorker", daemon=True)
        self.scan_started = time.time()
        self.worker.start()

    def stop_scan(self):
        if self.worker is not None and self.worker.is_alive():
            self.stop_event.set()
            self.btn_stop.set_enabled(False)
            self._set_state_pill("DETENIENDO", C_ORANGE)
            self._append_log("SYS", "Cancelación solicitada. Esperando a que el módulo actual se detenga...")

    def _on_scan_finished(self, summary):
        self.scan_started = None
        self.elapsed = summary["elapsed"]
        self.btn_start.set_enabled(True)
        self.btn_stop.set_enabled(False)
        self.btn_export.set_enabled(True)
        self.btn_csv.set_enabled(True)

        if summary["cancelled"]:
            self._set_state_pill("CANCELADO · RESULTADOS PARCIALES", C_ORANGE)
            self.lbl_task.configure(text="Escaneo cancelado por el usuario.")
        else:
            self.progress.set_value(100)
            self.lbl_percent.configure(text="100%")
            self.lbl_task.configure(text=f"Auditoría finalizada en {summary['elapsed']:.1f} s.")
            if summary["alerts"]:
                self._set_state_pill(f"COMPLETADO · {summary['alerts']} ALERTA(S) POR REVISAR", C_CRIMSON)
            elif summary["warns"]:
                self._set_state_pill("COMPLETADO · SOLO AVISOS MENORES", C_AMBER)
            else:
                self._set_state_pill("COMPLETADO · SISTEMA LIMPIO", C_EMERALD)
        self.gauge.set_score(summary["score"])
        self.lbl_verdict.configure(text=risk_verdict(summary["score"]), fg=score_color(summary["score"]))

    def clear_console(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
        self.log_lines.clear()

    def copy_log(self):
        if not self.log_lines:
            messagebox.showinfo(APP_NAME, "No hay registros que copiar.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(self.log_lines))
        self._append_log("SYS", f"{len(self.log_lines)} líneas copiadas al portapapeles.")

    def export_report(self):
        if not self.log_lines:
            messagebox.showinfo(APP_NAME, "No hay registros que exportar.")
            return
        path = filedialog.asksaveasfilename(
            title="Exportar informe de auditoría",
            defaultextension=".txt",
            initialfile=time.strftime("NOVA_informe_%Y%m%d_%H%M%S.txt"),
            filetypes=[("Informe de texto", "*.txt"), ("Todos los archivos", "*.*")],
        )
        if not path:
            return
        score = compute_risk_score(self.counters["ALERT"], self.counters["WARN"])
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f"{APP_NAME} v{APP_VERSION} - Informe de auditoría\n")
                handle.write(f"Generado: {time.strftime('%Y-%m-%d %H:%M:%S')} | Equipo: {os.environ.get('COMPUTERNAME', '?')}\n")
                handle.write(f"Alertas: {self.counters['ALERT']} | Avisos: {self.counters['WARN']} | Índice de riesgo: {score}/100 ({risk_verdict(score)})\n")
                handle.write("=" * 79 + "\n")
                handle.write("\n".join(self.log_lines) + "\n")
            self._append_log("SYS", f"Informe exportado a: {path}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"No se pudo guardar el informe:\n{exc}")

    def export_findings_csv(self):
        if not self.findings:
            messagebox.showinfo(APP_NAME, "No hay hallazgos que exportar. Ejecuta un escaneo primero.")
            return
        path = filedialog.asksaveasfilename(
            title="Exportar hallazgos en CSV",
            defaultextension=".csv",
            initialfile=time.strftime("NOVA_hallazgos_%Y%m%d_%H%M%S.csv"),
            filetypes=[("CSV", "*.csv"), ("Todos los archivos", "*.*")],
        )
        if not path:
            return

        def quote(value):
            return '"' + str(value).replace('"', '""') + '"'
         
        try:
            with open(path, "w", encoding="utf-8-sig") as handle:
                handle.write("Fecha;Modulo;Severidad;Detalle\n")
                for row in self.findings:
                    handle.write(";".join(quote(field) for field in row) + "\n")
            self._append_log("SYS", f"{len(self.findings)} hallazgos exportados a: {path}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"No se pudo guardar el CSV:\n{exc}")

    def _on_close(self):
        if self.worker is not None and self.worker.is_alive():
            if not messagebox.askyesno(APP_NAME, "Hay un escaneo en curso. ¿Deseas cancelarlo y salir?"):
                return
            self.stop_event.set()
        self._closing = True
        self.root.destroy()

def main():
    root = tk.Tk()
    NovaPrivacyGuardApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
