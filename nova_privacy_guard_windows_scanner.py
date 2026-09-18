#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
 NOVA Privacy Guard v3.0  -  Auditoria forense local de privacidad (Windows)
===============================================================================
 POLITICA DE FUNCIONAMIENTO: SOLO LECTURA ("Zero Damage")
   * El Registro se abre EXCLUSIVAMENTE con winreg.KEY_READ
     (nunca KEY_WRITE, KEY_SET_VALUE ni KEY_ALL_ACCESS).
   * Los archivos (Documentos del usuario, archivo hosts) se abren en modo
     'rb' (lectura binaria). Nunca se modifican, mueven, renombran ni borran.
   * No se terminan procesos ni se cierran conexiones: 'tasklist' y 'netstat'
     se invocan solo para LEER el estado del sistema.
   * Las UNICAS escrituras posibles son "Exportar informe" (TXT) y "Exportar
     hallazgos" (CSV), iniciadas manualmente por el usuario y guardadas en la
     ruta que el propio usuario elija.

 Arquitectura:
   * Hilo principal  -> interfaz tkinter (nunca ejecuta trabajo pesado).
   * Hilo secundario -> ScanEngine (los 7 modulos de auditoria).
   * Comunicacion    -> lista de eventos protegida con threading.Lock que la
                        GUI consume con root.after() (tkinter NO es thread-safe:
                        el hilo de escaneo jamas toca un widget).

 Modulos:
   1. Registro (Startup)   - claves Run / RunOnce (HKCU + HKLM, vistas 32/64).
   2. Procesos (Memoria)   - tasklist contra lista negra y typosquatting.
   3. Hardware (Cam/Mic)   - CapabilityAccessManager\\ConsentStore.
   4. Fugas de PII         - tarjetas sin cifrar en Documentos (regex + Luhn).
   5. Red (Conexiones)     - netstat -ano: puertos de RAT / C2.           [v3.0]
   6. Integridad DNS       - archivo hosts: redirecciones y sabotaje.     [v3.0]
   7. Estado de Defensas   - Defender, firewall y UAC saboteados.         [v3.0]

 Dependencias: solo biblioteca estandar (Python 3.8+).
 Compilacion sugerida:
   pyinstaller --onefile --noconsole --name "NOVA_Privacy_Guard" nova_privacy_guard.py
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

# winreg solo existe en Windows. Se importa de forma protegida para que el
# archivo pueda abrirse (y mostrar un error claro) en otros sistemas.
try:
    import winreg
except ImportError:  # pragma: no cover
    winreg = None


# =============================================================================
# CONFIGURACION GENERAL
# =============================================================================
APP_NAME = "NOVA Privacy Guard"
APP_VERSION = "3.0.0"

IS_WINDOWS = sys.platform.startswith("win")

# Flag de CreateProcess para que 'tasklist'/'netstat' no abran una ventana de
# consola (importante cuando se compila con --noconsole).
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

POLL_MS = 80                         # Frecuencia de refresco de la GUI (ms)
MAX_CONSOLE_LINES = 6000             # Lineas maximas visibles en la consola
MAX_PII_FILE_SIZE = 20 * 1024 * 1024 # Archivos > 20 MB se omiten en modulo 4
PII_EXTENSIONS = (".txt", ".csv")

# Nombre y descripcion de los modulos (compartido por motor y GUI)
MODULE_INFO = (
    ("Registro (Startup)",  "Claves Run / RunOnce en HKCU y HKLM"),
    ("Procesos (Memoria)",  "tasklist vs. lista negra de malware"),
    ("Hardware (Cam/Mic)",  "ConsentStore: acceso activo a camara y micro"),
    ("Fugas de PII",        "Tarjetas sin cifrar en Documentos (.txt/.csv)"),
    ("Red (Conexiones)",    "netstat -ano: puertos de RAT y canales C2"),
    ("Integridad DNS",      "Archivo hosts: redirecciones y sabotaje"),
    ("Estado de Defensas",  "Defender, firewall y UAC desactivados"),
)
MODULE_COUNT = len(MODULE_INFO)

# Ponderacion del indice de riesgo (0-100)
RISK_WEIGHT_ALERT = 12
RISK_WEIGHT_WARN = 4

# --- Modulo 1: rutas del Registro a auditar --------------------------------
RUN_SUBKEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)

# Heuristicas para comandos de arranque: (regex, motivo, severidad).
# Se aplican sobre el comando en minusculas y con variables expandidas.
STARTUP_HEURISTICS = (
    (re.compile(r"\\(?:temp|tmp)\\"),
     "Se ejecuta desde una carpeta temporal (Temp)", "ALERT"),
    (re.compile(r"\.(?:vbs|vbe|js|jse|wsf|wsh|hta)\b"),
     "Invoca un script de Windows Script Host (.vbs/.js/.wsf/.hta)", "ALERT"),
    (re.compile(r"\b(?:wscript|cscript|mshta)(?:\.exe)?\b"),
     "Usa un interprete de scripts (wscript/cscript/mshta)", "ALERT"),
    (re.compile(r"powershell(?:\.exe)?.*?(?:\s-e(?:nc(?:odedcommand)?)?\s|"
                r"-w(?:indowstyle)?\s+hidden|downloadstring|invoke-expression|\biex\b)"),
     "PowerShell oculto u ofuscado", "ALERT"),
    (re.compile(r"https?://"),
     "El comando de inicio contiene una URL remota", "ALERT"),
    (re.compile(r"\\users\\public\\"),
     "Ejecutable en la carpeta publica de usuarios", "ALERT"),
    (re.compile(r"\brundll32(?:\.exe)?\s+[^,]*\\(?:appdata|users\\public|programdata)\\"),
     "rundll32 cargando una DLL desde una ruta de usuario", "ALERT"),
    (re.compile(r"\.(?:bat|cmd|ps1|scr|pif)\b"),
     "Script por lotes / PowerShell / salvapantallas en el arranque", "WARN"),
    (re.compile(r"\\downloads\\"),
     "Se ejecuta desde la carpeta Descargas", "WARN"),
    (re.compile(r"\\appdata\\roaming\\[^\\]+\.exe"),
     "Ejecutable suelto en la raiz de AppData\\Roaming", "WARN"),
)

# --- Modulo 2: lista negra de PRUEBA ----------------------------------------
PROCESS_BLACKLIST = {
    "nc.exe":         "Netcat - shell inversa / puerta trasera",
    "nc64.exe":       "Netcat 64-bit - shell inversa / puerta trasera",
    "ncat.exe":       "Ncat - shell inversa / puerta trasera",
    "netcat.exe":     "Netcat - shell inversa / puerta trasera",
    "keylogger.exe":  "Keylogger generico (firma de prueba)",
    "mimikatz.exe":   "Mimikatz - volcado de credenciales",
    "njrat.exe":      "njRAT - troyano de acceso remoto",
    "darkcomet.exe":  "DarkComet - troyano de acceso remoto",
    "quasar.exe":     "Quasar RAT - troyano de acceso remoto",
    "remcos.exe":     "Remcos RAT - troyano de acceso remoto",
    "asyncrat.exe":   "AsyncRAT - troyano de acceso remoto",
}

# Nombres que imitan procesos legitimos de Windows (typosquatting)
PROCESS_TYPOSQUATS = {
    "svch0st.exe": "svchost.exe", "scvhost.exe": "svchost.exe",
    "svhost.exe": "svchost.exe",  "lsas.exe": "lsass.exe",
    "lsasss.exe": "lsass.exe",    "csrs.exe": "csrss.exe",
    "expl0rer.exe": "explorer.exe", "winlogin.exe": "winlogon.exe",
    "rundl32.exe": "rundll32.exe",  "taskhostw32.exe": "taskhostw.exe",
}

# Formato CSV de 'tasklist /FO CSV /NH':  "imagen.exe","PID","Sesion",...
TASKLIST_RX = re.compile(r'^"([^"]+)","(\d+)"')

# --- Modulo 3: ConsentStore -------------------------------------------------
CONSENT_BASE = (r"Software\Microsoft\Windows\CurrentVersion"
                r"\CapabilityAccessManager\ConsentStore")
CAPABILITIES = (("webcam", "Camara web"), ("microphone", "Microfono"))
FILETIME_EPOCH_DIFF = 116444736000000000   # 100-ns entre 1601-01-01 y 1970-01-01
FILETIME_PER_SECOND = 10_000_000

# --- Modulo 4: deteccion de tarjetas ----------------------------------------
# Secuencia de 13-19 digitos, admitiendo espacios o guiones como separadores.
CARD_CANDIDATE_RX = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?!-?\d)")
CARD_BRANDS = (
    ("Visa",       re.compile(r"^4\d{12}(?:\d{3}){0,2}$")),
    ("Mastercard", re.compile(r"^(?:5[1-5]\d{14}|(?:222[1-9]|22[3-9]\d|2[3-6]\d{2}"
                              r"|27[01]\d|2720)\d{12})$")),
    ("AmEx",       re.compile(r"^3[47]\d{13}$")),
    ("Discover",   re.compile(r"^6(?:011|5\d{2}|4[4-9]\d)\d{12,15}$")),
    ("Diners",     re.compile(r"^3(?:0[0-5]|[68]\d)\d{11,16}$")),
    ("JCB",        re.compile(r"^35(?:2[89]|[3-8]\d)\d{12,15}$")),
)
MAX_CARD_HITS_PER_FILE = 1000

# --- Modulo 5: puertos y estados de red -------------------------------------
# Puertos historicamente asociados a puertas traseras, RATs y canales C2.
SUSPICIOUS_PORTS = {
    666:   "Backdoor clasico (Doly / Attack FTP)",
    1337:  "Puerto 'leet', habitual en backdoors caseros",
    1604:  "Protocolo abusado por RATs de escritorio remoto",
    3127:  "Gusano MyDoom",
    4444:  "Metasploit Meterpreter (payload por defecto)",
    4445:  "Metasploit / variantes de payload",
    5555:  "ADB remoto / RATs multiplataforma",
    6666:  "Bot IRC / backdoor",
    6667:  "IRC - canal de control de botnets",
    6697:  "IRC sobre TLS - canal de control de botnets",
    9001:  "Tor ORPort / canal C2 encubierto",
    12345: "NetBus",
    12346: "NetBus (canal secundario)",
    20034: "NetBus 2 Pro",
    27374: "SubSeven",
    31337: "Back Orifice ('eleet')",
    54321: "Back Orifice 2000 / SchoolBus",
}

# 'netstat' traduce los estados segun el idioma de Windows.
ESTABLISHED_STATES = {
    "ESTABLISHED", "ESTABLECIDO", "ESTABLECIDA", "ESTABELECIDO",
    "ETABLI", "HERGESTELLT", "STABILITO", "VERBUNDEN",
}
LISTENING_STATES = {
    "LISTENING", "ESCUCHAR", "ESCUCHANDO", "A LA ESCUCHA",
    "OUVIR", "ABHOREN", "ABHÖREN", "IN ATTESA",
}

# --- Modulo 6: archivo hosts ------------------------------------------------
DEFAULT_HOSTS_DIR = r"%SystemRoot%\System32\drivers\etc"
TCPIP_PARAMS_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
LOCAL_HOST_NAMES = {"localhost", "localhost.localdomain", "local",
                    "ip6-localhost", "ip6-loopback", "broadcasthost"}
# Bloquear estos dominios apunta a sabotaje del antivirus / actualizaciones.
SECURITY_DOMAIN_KEYWORDS = (
    "windowsupdate", "update.microsoft", "defender", "msftncsi", "msftconnecttest",
    "avast", "avg", "avira", "bitdefender", "eset", "nod32", "kaspersky", "mcafee",
    "norton", "symantec", "malwarebytes", "sophos", "trendmicro", "virustotal",
    "clamav", "drweb", "f-secure", "panda", "securelist", "spybot", "sucuri",
)
# Redirigir estos dominios es tipico de troyanos bancarios / phishing.
FINANCIAL_DOMAIN_KEYWORDS = (
    "bank", "banco", "banca", "paypal", "santander", "bbva", "caixa", "bancolombia",
    "chase", "wellsfargo", "citibank", "hsbc", "binance", "coinbase", "kraken",
    "metamask", "blockchain", "mercadopago", "westernunion",
)
BLOCKING_IPS = ("0.0.0.0", "::", "0::0")

# --- Modulo 7: defensas del sistema ----------------------------------------
DEFENDER_POLICY_ROOT = r"SOFTWARE\Policies\Microsoft\Windows Defender"
DEFENDER_RTP_ROOT = DEFENDER_POLICY_ROOT + r"\Real-Time Protection"

# (subclave, valor, descripcion, severidad si vale 1)
DEFENDER_CHECKS = (
    (DEFENDER_POLICY_ROOT, "DisableAntiSpyware",
     "Windows Defender (antispyware) DESACTIVADO por directiva", "ALERT"),
    (DEFENDER_POLICY_ROOT, "DisableAntiVirus",
     "Motor antivirus DESACTIVADO por directiva", "ALERT"),
    (DEFENDER_POLICY_ROOT, "DisableRoutinelyTakingAction",
     "Defender NO actua automaticamente sobre las amenazas detectadas", "WARN"),
    (DEFENDER_RTP_ROOT, "DisableRealtimeMonitoring",
     "Proteccion en TIEMPO REAL desactivada", "ALERT"),
    (DEFENDER_RTP_ROOT, "DisableBehaviorMonitoring",
     "Analisis de comportamiento desactivado", "ALERT"),
    (DEFENDER_RTP_ROOT, "DisableOnAccessProtection",
     "Proteccion al acceder a archivos desactivada", "ALERT"),
    (DEFENDER_RTP_ROOT, "DisableIOAVProtection",
     "Analisis de descargas y adjuntos desactivado", "ALERT"),
    (DEFENDER_RTP_ROOT, "DisableScanOnRealtimeEnable",
     "Analisis al reactivar la proteccion desactivado", "WARN"),
)

# Exclusiones de Defender (ruta protegida por Tamper Protection)
DEFENDER_EXCLUSION_KEYS = (
    (r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", "ruta"),
    (r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions", "extension"),
    (r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes", "proceso"),
)
EXCLUSION_HIGH_RISK_RX = re.compile(
    r"^(?:c:\\?$|c:\\windows\\temp|.*\\appdata\\|.*\\temp\\|.*\\downloads\\|"
    r"c:\\users\\public)", re.I)

FIREWALL_PROFILES = (("DomainProfile", "Dominio"), ("StandardProfile", "Privado"),
                     ("PublicProfile", "Publico"))
FIREWALL_ROOT = (r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
                 r"\FirewallPolicy")
UAC_POLICY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Servicios de seguridad cuyo tipo de inicio 4 (=deshabilitado) es sabotaje
SECURITY_SERVICES = (
    ("WinDefend", "Antivirus de Microsoft Defender", "ALERT"),
    ("WdNisSvc", "Inspeccion de red de Defender", "ALERT"),
    ("Sense", "Defender for Endpoint (EDR)", "WARN"),
    ("SecurityHealthService", "Centro de seguridad de Windows", "ALERT"),
    ("MpsSvc", "Servicio de Firewall de Windows", "ALERT"),
    ("wscsvc", "Centro de seguridad (WSC)", "ALERT"),
    ("wuauserv", "Windows Update", "WARN"),
    ("EventLog", "Registro de eventos de Windows", "ALERT"),
)
SERVICES_ROOT = r"SYSTEM\CurrentControlSet\Services"


# =============================================================================
# FUNCIONES AUXILIARES (sin estado, faciles de auditar y probar)
# =============================================================================
def hive_name(hive):
    """Devuelve el nombre corto de una colmena del Registro."""
    if winreg is None:
        return "HK??"
    return {winreg.HKEY_CURRENT_USER: "HKCU",
            winreg.HKEY_LOCAL_MACHINE: "HKLM"}.get(hive, "HK??")


def reg_enum_values(hive, subkey, view_flag=0):
    """
    Enumera todos los valores de una clave del Registro.
    SOLO LECTURA: se abre con KEY_READ. Lanza OSError (FileNotFoundError,
    PermissionError...) para que el llamador decida como registrarlo.
    """
    values = []
    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
        index = 0
        while True:
            try:
                name, data, vtype = winreg.EnumValue(key, index)
            except OSError:          # ERROR_NO_MORE_ITEMS -> fin de la lista
                break
            values.append((name, data, vtype))
            index += 1
    return values


def reg_enum_subkeys(hive, subkey, view_flag=0):
    """Enumera las subclaves de una clave del Registro (SOLO LECTURA)."""
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
    """Lee un valor numerico (p.ej. REG_QWORD). Devuelve None si no existe."""
    try:
        data, _ = winreg.QueryValueEx(key, value_name)
        return int(data)
    except (OSError, ValueError, TypeError):
        return None


def reg_read_dword(hive, subkey, value_name):
    """
    Lee un DWORD de una clave concreta (SOLO LECTURA).
    Devuelve (valor, error) donde error es None, "missing" o "denied".
    """
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            value = reg_query_int(key, value_name)
            return (value, None) if value is not None else (None, "missing")
    except FileNotFoundError:
        return None, "missing"
    except PermissionError:
        return None, "denied"
    except OSError:
        return None, "denied"


def extract_executable_path(command):
    """Extrae la ruta del ejecutable de una linea de comandos de arranque."""
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
    """
    Aplica las heuristicas a un comando de arranque.
    Devuelve (severidad, [motivos]) donde severidad es OK, WARN o ALERT.
    """
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

    # Entrada huerfana: apunta a un ejecutable que ya no existe en disco
    exe = extract_executable_path(expanded)
    try:
        if exe and os.path.isabs(exe) and not os.path.exists(exe):
            reasons.append("El ejecutable referenciado no existe (entrada huerfana)")
            if severity == "OK":
                severity = "WARN"
    except (OSError, ValueError):
        pass
    return severity, reasons


def decode_console_output(raw):
    """Decodifica la salida de comandos de consola de Windows (codepage OEM)."""
    for encoding in ("oem", "mbcs", "utf-8"):
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("latin-1", errors="replace")


def run_console_command(arguments, timeout=60):
    """
    Ejecuta una utilidad de consola de Windows en modo lectura y devuelve
    (texto, error). 'error' es None si todo fue bien.
    No abre ventana de consola (CREATE_NO_WINDOW) y cierra stdin para poder
    funcionar dentro de un .exe compilado con --noconsole.
    """
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
        return None, f"No se encontro '{arguments[0]}' en el sistema."
    except subprocess.TimeoutExpired:
        return None, f"'{arguments[0]}' excedio el tiempo limite ({timeout} s)."
    except OSError as exc:
        return None, f"No se pudo ejecutar '{arguments[0]}': {exc}"

    if result.returncode != 0:
        detail = decode_console_output(result.stderr).strip()
        return None, f"'{arguments[0]}' devolvio codigo {result.returncode}: {detail}"
    return decode_console_output(result.stdout), None


def filetime_to_str(filetime):
    """Convierte un FILETIME de Windows (100-ns desde 1601) a texto local."""
    try:
        if not filetime:
            return "-"
        epoch = (filetime - FILETIME_EPOCH_DIFF) / FILETIME_PER_SECOND
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))
    except (OSError, OverflowError, ValueError):
        return "fecha invalida"


def luhn_is_valid(digits):
    """Algoritmo de Luhn (mod 10) para descartar falsos positivos."""
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
    """Devuelve la marca de tarjeta segun el prefijo IIN, o None."""
    for brand, regex in CARD_BRANDS:
        if regex.match(digits):
            return brand
    return None


def find_card_numbers(text):
    """
    Busca posibles PAN (numeros de tarjeta) en un texto.
    PRIVACIDAD: NUNCA devuelve los numeros; solo la marca detectada de cada
    coincidencia valida, de modo que ningun dato sensible llega a la GUI,
    a los logs ni al informe exportado.
    """
    brands = []
    for match in CARD_CANDIDATE_RX.finditer(text):
        digits = re.sub(r"[ -]", "", match.group(0))
        if not 13 <= len(digits) <= 19:
            continue
        if len(set(digits)) == 1:            # 0000..., 1111... -> descartar
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
    """
    Obtiene la carpeta Documentos real del usuario (puede estar redirigida,
    p.ej. a OneDrive) leyendo 'User Shell Folders' en modo solo lectura.
    """
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
    """True si la ruta es un enlace simbolico o una union NTFS (no se sigue)."""
    try:
        if os.path.islink(path):
            return True
        isjunction = getattr(os.path, "isjunction", None)   # Python 3.12+
        return bool(isjunction and isjunction(path))
    except OSError:
        return True


def read_text_readonly(path):
    """
    Lee un archivo de texto en modo 'rb' (SOLO LECTURA) y lo decodifica.
    Soporta UTF-16 con BOM (habitual en exportaciones de Excel/Bloc de notas).
    """
    with open(path, "rb") as handle:
        raw = handle.read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


# --- Auxiliares de red (modulo 5) -------------------------------------------
def split_endpoint(endpoint):
    """
    Separa 'IP:puerto' admitiendo IPv6 ('[::1]:443').
    Devuelve (ip, puerto_int) o (endpoint, None) si no se puede interpretar.
    """
    if ":" not in endpoint:
        return endpoint, None
    address, _, port = endpoint.rpartition(":")
    try:
        return address, int(port)
    except ValueError:
        return endpoint, None


def is_loopback_address(address):
    """True si la direccion es local (127.x.x.x, ::1 o comodin)."""
    clean = address.strip("[]").lower()
    return (clean.startswith("127.") or clean in ("::1", "0.0.0.0", "::", "*")
            or clean == "localhost")


def parse_netstat(text):
    """
    Interpreta la salida de 'netstat -ano'.
    Se parsea por POSICION (proto, local, remoto, [estado], PID) porque los
    encabezados y algunos estados estan traducidos segun el idioma de Windows.
    Devuelve una lista de dicts.
    """
    connections = []
    for line in text.splitlines():
        parts = line.split()
        # UDP tiene 4 columnas (sin estado); TCP tiene 5.
        if len(parts) < 4 or parts[0].upper() not in ("TCP", "UDP"):
            continue
        if not parts[-1].isdigit():
            continue
        protocol = parts[0].upper()
        pid = int(parts[-1])
        local_ip, local_port = split_endpoint(parts[1])
        remote_ip, remote_port = split_endpoint(parts[2])
        # El estado puede contener espacios en algunos idiomas
        state = " ".join(parts[3:-1]).strip().upper()
        connections.append({
            "protocol": protocol, "pid": pid, "state": state,
            "local_ip": local_ip, "local_port": local_port,
            "remote_ip": remote_ip, "remote_port": remote_port,
        })
    return connections


def is_established(state):
    """True si el estado indica conexion establecida (en cualquier idioma)."""
    if state in ESTABLISHED_STATES:
        return True
    normalized = state.replace("É", "E").replace("Ó", "O").replace("Ö", "O")
    return normalized in ESTABLISHED_STATES


def is_listening(state):
    """True si el estado indica socket a la escucha (en cualquier idioma)."""
    return state in LISTENING_STATES or state.startswith("LISTEN")


# --- Auxiliares del archivo hosts (modulo 6) --------------------------------
def get_hosts_file_path():
    """
    Ruta real del archivo hosts. Windows permite reubicarlo con el valor
    'DataBasePath' del Registro, asi que se consulta (SOLO LECTURA) en lugar
    de asumir la ruta por defecto.
    """
    default_dir = os.path.expandvars(DEFAULT_HOSTS_DIR)
    if winreg is not None:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TCPIP_PARAMS_KEY,
                                0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "DataBasePath")
                path = os.path.expandvars(value)
                if os.path.isdir(path):
                    return os.path.join(path, "hosts"), default_dir
        except OSError:
            pass
    return os.path.join(default_dir, "hosts"), default_dir


def parse_hosts_file(text):
    """
    Devuelve [(num_linea, ip, [nombres])] ignorando comentarios ('#') y
    lineas vacias o mal formadas.
    """
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
    """True si la IP se usa para anular un dominio (loopback o 0.0.0.0)."""
    clean = address.strip("[]").lower()
    return clean.startswith("127.") or clean in ("::1", *BLOCKING_IPS)


def matches_keyword(hostname, keywords):
    """True si el dominio contiene alguna de las palabras clave indicadas."""
    lowered = hostname.lower()
    return any(keyword in lowered for keyword in keywords)


# --- Indice de riesgo --------------------------------------------------------
def compute_risk_score(alerts, warns):
    """Indice de riesgo 0-100 a partir de los hallazgos (misma formula en
    motor y GUI para que el numero mostrado y el del informe coincidan)."""
    return min(100, alerts * RISK_WEIGHT_ALERT + warns * RISK_WEIGHT_WARN)


def risk_verdict(score):
    """Traduce el indice de riesgo a un veredicto legible."""
    if score == 0:
        return "SISTEMA LIMPIO"
    if score < 25:
        return "RIESGO BAJO"
    if score < 60:
        return "RIESGO MEDIO"
    if score < 85:
        return "RIESGO ALTO"
    return "RIESGO CRITICO"


def has_admin_rights():
    """
    Heuristica SIN ctypes: la carpeta %SystemRoot%\\System32\\config solo es
    legible con privilegios elevados. Sirve para avisar al usuario de que
    ciertas claves de HKLM pueden devolver 'acceso denegado'.
    """
    try:
        os.listdir(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                "System32", "config"))
        return True
    except OSError:
        return False


# =============================================================================
# MOTOR DE ESCANEO (se ejecuta en un hilo secundario)
# =============================================================================
class ScanEngine:
    """
    Ejecuta los modulos de auditoria. No interactua con tkinter: todo se
    comunica a la GUI mediante 'emit(evento)', que es thread-safe.

    Eventos emitidos:
        ("log", nivel, mensaje)
        ("finding", severidad, indice_modulo, detalle)
        ("progress", porcentaje, texto)
        ("module", indice, estado, n_alertas, n_avisos)
        ("done", resumen_dict)
    """

    def __init__(self, emit, stop_event, enabled_modules):
        self.emit = emit
        self.stop_event = stop_event
        self.enabled = list(enabled_modules)
        self.findings = []              # (indice_modulo, severidad, detalle)
        self._current = 0
        self._completed = 0
        self._total = max(1, sum(1 for flag in self.enabled if flag))
        # Cache de procesos: modulos 2 y 5 comparten una sola llamada a tasklist
        self._processes = None
        self._process_map = {}
        self._tasklist_failed = False

    # ---------------------------------------------------------- utilidades
    def log(self, level, message):
        self.emit(("log", level, message))

    def add_finding(self, severity, detail):
        """Registra un hallazgo (ALERT o WARN) y lo notifica a la GUI."""
        self.findings.append((self._current, severity, detail))
        self.log(severity, detail)
        self.emit(("finding", severity, self._current, detail))

    def progress(self, fraction, text=""):
        """Progreso global calculado a partir del progreso del modulo actual."""
        fraction = min(max(fraction, 0.0), 1.0)
        percent = (self._completed + fraction) / self._total * 100.0
        self.emit(("progress", percent, text))

    def stopped(self):
        return self.stop_event.is_set()

    def _load_processes(self):
        """
        Ejecuta 'tasklist' UNA sola vez por escaneo y cachea el resultado.
        Devuelve [(nombre, pid)] o None si la utilidad fallo.
        """
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
        """Nombre del proceso dueno de un PID (para los hallazgos de red)."""
        self._load_processes()
        return self._process_map.get(pid, "proceso desconocido")

    # --------------------------------------------------------- orquestador
    def run(self):
        started = time.time()
        cancelled = False
        steps = (self.scan_registry_startup, self.scan_processes,
                 self.scan_hardware_privacy, self.scan_pii_leaks,
                 self.scan_network_connections, self.scan_hosts_integrity,
                 self.scan_security_defenses)
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
                self.log("HEAD", f"==== MODULO {index + 1}/{MODULE_COUNT} :: "
                                 f"{MODULE_INFO[index][0].upper()} ====")
                before = len(self.findings)
                module_started = time.time()
                try:
                    step()
                    new = self.findings[before:]
                    alerts = sum(1 for f in new if f[1] == "ALERT")
                    warns = sum(1 for f in new if f[1] == "WARN")
                    state = "CANCELLED" if self.stopped() else "DONE"
                    self.emit(("module", index, state, alerts, warns))
                    self.log("SYS", f"Modulo {index + 1} finalizado en "
                                    f"{time.time() - module_started:.2f} s.")
                except Exception as exc:  # aislamiento: un modulo no tumba al resto
                    self.log("ERROR", f"Fallo inesperado en el modulo: {exc!r}")
                    self.emit(("module", index, "ERROR", 0, 0))
                self._completed += 1
                self.progress(0.0, "")
            cancelled = cancelled or self.stopped()
        except Exception as exc:  # red de seguridad final del hilo
            self.log("ERROR", f"Error critico del motor: {exc!r}")
        finally:
            alerts = sum(1 for f in self.findings if f[1] == "ALERT")
            warns = sum(1 for f in self.findings if f[1] == "WARN")
            score = compute_risk_score(alerts, warns)
            elapsed = time.time() - started
            self.log("HEAD", "==== RESUMEN DE LA AUDITORIA ====")
            if cancelled:
                self.log("WARN", "Escaneo cancelado por el usuario: resultados parciales.")
            self.log("INFO", f"Duracion: {elapsed:.1f} s | Alertas: {alerts} | Avisos: {warns}")
            self.log("INFO", f"Indice de riesgo: {score}/100 -> {risk_verdict(score)}")
            if alerts == 0 and warns == 0 and not cancelled:
                self.log("OK", "No se detectaron amenazas a la privacidad en los modulos ejecutados.")
            elif alerts:
                self.log("ALERT", "Revise manualmente cada ALERTA. NOVA no modifica el sistema: "
                                  "la remediacion debe realizarla un analista.")
            self.emit(("done", {"alerts": alerts, "warns": warns, "score": score,
                                "elapsed": elapsed, "cancelled": cancelled}))

    # =====================================================================
    # MODULO 1 - Auditoria de Registro (Startup)
    # =====================================================================
    def scan_registry_startup(self):
        targets = []
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for subkey in RUN_SUBKEYS:
                if hive == winreg.HKEY_LOCAL_MACHINE:
                    # En Windows x64 HKLM\Software tiene vista 64 y 32 bits
                    # (WOW6432Node). Se auditan ambas.
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
                self.log("INFO", f"{location}: la clave no existe (normal).")
                continue
            except PermissionError:
                self.log("WARN", f"{location}: acceso denegado (ejecute como administrador).")
                continue
            except OSError as exc:
                self.log("ERROR", f"{location}: no se pudo leer ({exc}).")
                continue

            if not values:
                self.log("INFO", f"{location}: sin entradas.")
                continue

            for name, data, _vtype in values:
                command = data if isinstance(data, str) else str(data)
                signature = (hive, subkey.lower(), name.lower(), command.lower())
                if signature in seen:        # evita duplicados entre vistas
                    continue
                seen.add(signature)
                total_entries += 1

                severity, reasons = analyze_startup_command(command)
                label = name or "(Predeterminado)"
                if severity == "OK":
                    self.log("OK", f"[{location}] '{label}' -> {command}")
                else:
                    self.add_finding(severity, f"[{location}] '{label}' -> {command} "
                                               f"| Motivo: {'; '.join(reasons)}")
        self.log("INFO", f"Entradas de arranque analizadas: {total_entries}")
        self.progress(1.0, "Registro auditado")

    # =====================================================================
    # MODULO 2 - Auditoria de Procesos (Memoria)
    # =====================================================================
    def scan_processes(self):
        self.progress(0.1, "Ejecutando tasklist...")
        processes = self._load_processes()
        if processes is None:
            return

        unique = len({name.lower() for name, _ in processes})
        self.log("INFO", f"Procesos en memoria: {len(processes)} ({unique} imagenes distintas).")

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
                self.add_finding("ALERT", f"Proceso en lista negra: {name} (PID {pid}) "
                                          f"-> {PROCESS_BLACKLIST[lowered]}")
            elif lowered in PROCESS_TYPOSQUATS:
                hits += 1
                self.add_finding("ALERT", f"Proceso suplantador: {name} (PID {pid}) imita a "
                                          f"'{PROCESS_TYPOSQUATS[lowered]}'")
        if hits == 0:
            self.log("OK", "Ningun proceso activo coincide con la lista negra.")
        self.progress(1.0, "Procesos auditados")

    # =====================================================================
    # MODULO 3 - Monitor de Privacidad de Hardware (Camara / Microfono)
    # =====================================================================
    def scan_hardware_privacy(self):
        now_filetime = int(time.time() * FILETIME_PER_SECOND) + FILETIME_EPOCH_DIFF
        day = 24 * 3600 * FILETIME_PER_SECOND

        for number, (capability, label) in enumerate(CAPABILITIES):
            if self.stopped():
                return
            self.progress(number / len(CAPABILITIES), f"Consultando ConsentStore: {label}")
            cap_path = f"{CONSENT_BASE}\\{capability}"

            # 1) Politica global de permisos (Allow / Deny)
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(hive, cap_path, 0, winreg.KEY_READ) as key:
                        policy, _ = winreg.QueryValueEx(key, "Value")
                        self.log("INFO", f"{label} - politica {hive_name(hive)}: {policy}")
                except OSError:
                    pass  # la politica puede no estar definida en esa colmena

            # 2) Uso por aplicacion (el uso se registra en HKCU)
            entries = self._collect_consent_entries(winreg.HKEY_CURRENT_USER, cap_path, label)
            active = [e for e in entries if e["active"]]
            if active:
                for entry in active:
                    self.add_finding("ALERT", f"{label} EN USO AHORA por: {entry['app']} "
                                              f"(desde {filetime_to_str(entry['start'])})")
            else:
                self.log("OK", f"{label}: ninguna aplicacion la esta usando en este momento.")

            # 3) Contexto: uso reciente (ultimas 24 h) ya finalizado
            recent = sorted((e for e in entries
                             if not e["active"] and e["stop"] and now_filetime - e["stop"] < day),
                            key=lambda e: e["stop"], reverse=True)
            for entry in recent[:5]:
                self.log("INFO", f"{label} - uso reciente: {entry['app']} "
                                 f"(fin {filetime_to_str(entry['stop'])})")
            self.log("INFO", f"{label}: {len(entries)} aplicaciones con historial de acceso.")
        self.progress(1.0, "Hardware auditado")

    def _collect_consent_entries(self, hive, cap_path, label):
        """Recorre apps empaquetadas (UWP) y no empaquetadas (Win32)."""
        entries = []
        try:
            subkeys = reg_enum_subkeys(hive, cap_path)
        except FileNotFoundError:
            self.log("INFO", f"{label}: no existe ConsentStore (Windows anterior a 1903?).")
            return entries
        except OSError as exc:
            self.log("WARN", f"{label}: no se pudo leer ConsentStore ({exc}).")
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
                    # Las rutas Win32 se guardan con '#' en lugar de '\'
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
        """
        Lee LastUsedTimeStart / LastUsedTimeStop (FILETIME).
        Dispositivo EN USO si Start > 0 y (Stop == 0 o Stop < Start).
        """
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                start = reg_query_int(key, "LastUsedTimeStart")
                stop = reg_query_int(key, "LastUsedTimeStop") or 0
        except OSError:
            return None
        if not start:
            return None
        return {"app": display_name, "start": start, "stop": stop,
                "active": stop == 0 or stop < start}

    # =====================================================================
    # MODULO 4 - Prevencion de Fugas de PII (tarjetas de credito)
    # =====================================================================
    def scan_pii_leaks(self):
        documents = get_documents_folder()
        self.log("INFO", f"Carpeta objetivo: {documents}")
        if not os.path.isdir(documents):
            self.log("ERROR", "La carpeta Documentos no existe o no es accesible.")
            return

        # Fase 1: indexar candidatos (.txt / .csv)
        self.progress(0.02, "Indexando archivos...")
        candidates = []

        def on_walk_error(error):
            self.log("WARN", f"Sin acceso a: {getattr(error, 'filename', error)}")

        for root, dirs, files in os.walk(documents, onerror=on_walk_error, followlinks=False):
            if self.stopped():
                return
            # No se siguen uniones NTFS ('Mi musica', etc.) ni symlinks
            dirs[:] = [d for d in dirs if not is_link_or_junction(os.path.join(root, d))]
            for filename in files:
                if filename.lower().endswith(PII_EXTENSIONS):
                    candidates.append(os.path.join(root, filename))

        total = len(candidates)
        self.log("INFO", f"Archivos .txt/.csv a analizar: {total}")
        if total == 0:
            self.log("OK", "No hay archivos de texto que analizar.")
            return

        # Fase 2: analisis con regex + Luhn + IIN
        exposed = 0
        for index, path in enumerate(candidates):
            if self.stopped():
                return
            if index % 5 == 0:
                self.progress(0.05 + 0.95 * index / total,
                              f"Analizando ({index + 1}/{total}): {os.path.basename(path)}")
            try:
                if os.path.getsize(path) > MAX_PII_FILE_SIZE:
                    self.log("INFO", f"Omitido por tamano (>20 MB): {os.path.basename(path)}")
                    continue
                text = read_text_readonly(path)
            except OSError as exc:
                self.log("WARN", f"No se pudo leer {os.path.basename(path)}: "
                                 f"{exc.strerror or exc}")
                continue

            brands = find_card_numbers(text)
            del text  # liberar la referencia al contenido lo antes posible
            if brands:
                exposed += 1
                summary = ", ".join(sorted(set(brands)))
                # Solo nombre de archivo + recuento. Los numeros NUNCA se muestran.
                self.add_finding("ALERT",
                                 f"PII expuesta en: {os.path.relpath(path, documents)} | "
                                 f"{len(brands)} posible(s) tarjeta(s) sin cifrar [{summary}] | "
                                 f"Datos: ****-****-****-**** (ENMASCARADO)")
        if exposed == 0:
            self.log("OK", "No se encontraron numeros de tarjeta sin cifrar.")
        else:
            self.log("INFO", f"Archivos con PII expuesta: {exposed} de {total}.")
        self.progress(1.0, "PII auditada")

    # =====================================================================
    # MODULO 5 - Auditoria de Red (conexiones activas)          [NUEVO v3.0]
    # =====================================================================
    def scan_network_connections(self):
        """
        Ejecuta 'netstat -ano' (solo lectura) y busca:
          * Conexiones ESTABLECIDAS hacia/desde puertos tipicos de RAT y C2.
          * Sockets A LA ESCUCHA en esos mismos puertos (backdoor esperando).
        Cada hallazgo se enriquece con el nombre del proceso dueno del PID,
        reutilizando la cache de 'tasklist' del modulo 2.
        """
        self.progress(0.1, "Ejecutando netstat -ano...")
        text, error = run_console_command(["netstat", "-ano"], timeout=90)
        if error:
            self.log("ERROR", error)
            return

        connections = parse_netstat(text)
        if not connections:
            self.log("WARN", "netstat no devolvio conexiones interpretables.")
            return

        self.progress(0.35, "Correlacionando PIDs con procesos...")
        self._load_processes()   # cache compartida (no relanza tasklist)

        established = [c for c in connections if is_established(c["state"])]
        listening = [c for c in connections if is_listening(c["state"])]
        external = [c for c in established if not is_loopback_address(c["remote_ip"])]
        remote_hosts = {c["remote_ip"] for c in external}

        self.log("INFO", f"Sockets totales: {len(connections)} | Establecidas: "
                         f"{len(established)} | A la escucha: {len(listening)}")
        self.log("INFO", f"Conexiones hacia Internet: {len(external)} "
                         f"({len(remote_hosts)} equipos remotos distintos).")

        hits = 0
        total = max(1, len(connections))
        for index, conn in enumerate(connections):
            if self.stopped():
                return
            if index % 50 == 0:
                self.progress(0.4 + 0.6 * index / total,
                              f"Analizando conexiones ({index}/{total})")

            process = self.process_name(conn["pid"])
            local = f"{conn['local_ip']}:{conn['local_port']}"
            remote = f"{conn['remote_ip']}:{conn['remote_port']}"

            # 1) Conexion ESTABLECIDA contra un puerto sospechoso
            if is_established(conn["state"]):
                for port, side in ((conn["remote_port"], "remoto"),
                                   (conn["local_port"], "local")):
                    if port in SUSPICIOUS_PORTS:
                        hits += 1
                        # El trafico puramente local (127.0.0.1) suele ser de
                        # herramientas de desarrollo: se degrada a AVISO.
                        loopback = (is_loopback_address(conn["remote_ip"])
                                    and is_loopback_address(conn["local_ip"]))
                        severity = "WARN" if loopback else "ALERT"
                        note = " [trafico local: posible falso positivo]" if loopback else ""
                        self.add_finding(
                            severity,
                            f"Conexion ESTABLECIDA en puerto {side} {port} "
                            f"({SUSPICIOUS_PORTS[port]}) | {local} <-> {remote} | "
                            f"PID {conn['pid']} ({process}){note}")
                        break

            # 2) Socket A LA ESCUCHA en un puerto de backdoor conocido
            elif is_listening(conn["state"]) and conn["local_port"] in SUSPICIOUS_PORTS:
                hits += 1
                port = conn["local_port"]
                self.add_finding(
                    "ALERT",
                    f"Puerto {port} A LA ESCUCHA ({SUSPICIOUS_PORTS[port]}) | "
                    f"{local} | PID {conn['pid']} ({process}) "
                    f"-> posible puerta trasera esperando conexion")

        # Contexto: procesos con mas conexiones salientes (util para triaje)
        if external:
            per_process = {}
            for conn in external:
                per_process[conn["pid"]] = per_process.get(conn["pid"], 0) + 1
            top = sorted(per_process.items(), key=lambda item: item[1], reverse=True)[:5]
            for pid, count in top:
                self.log("INFO", f"Conexiones salientes: {count:3d} | PID {pid} "
                                 f"({self.process_name(pid)})")

        if hits == 0:
            self.log("OK", "Ninguna conexion usa puertos asociados a RATs o C2 conocidos.")
        self.progress(1.0, "Red auditada")

    # =====================================================================
    # MODULO 6 - Integridad de DNS (archivo hosts)              [NUEVO v3.0]
    # =====================================================================
    def scan_hosts_integrity(self):
        """
        Lee el archivo hosts (modo 'rb') y clasifica cada entrada:
          * Loopback + nombre local           -> normal, se ignora.
          * IP externa + dominio              -> ALERTA (secuestro DNS local).
          * Loopback/0.0.0.0 + dominio de AV  -> ALERTA (sabotaje de defensas).
          * Loopback/0.0.0.0 + otro dominio   -> bloqueo (listas anti-anuncios).
        """
        hosts_path, default_dir = get_hosts_file_path()
        self.log("INFO", f"Archivo hosts: {hosts_path}")
        self.progress(0.1, "Leyendo archivo hosts...")

        # Si 'DataBasePath' fue modificado, el hosts real no es el que edita
        # el usuario: tecnica de ocultacion conocida.
        if os.path.normcase(os.path.dirname(hosts_path)) != os.path.normcase(default_dir):
            self.add_finding("WARN", f"La ruta del archivo hosts fue modificada en el Registro "
                                     f"(DataBasePath) a: {os.path.dirname(hosts_path)}")

        try:
            text = read_text_readonly(hosts_path)
        except FileNotFoundError:
            self.log("INFO", "No existe el archivo hosts (situacion valida y limpia).")
            return
        except PermissionError:
            self.log("WARN", "Acceso denegado al archivo hosts (ejecute como administrador).")
            return
        except OSError as exc:
            self.log("ERROR", f"No se pudo leer el archivo hosts: {exc.strerror or exc}")
            return

        entries = parse_hosts_file(text)
        computer = os.environ.get("COMPUTERNAME", "").lower()
        local_names = set(LOCAL_HOST_NAMES) | {computer} if computer else set(LOCAL_HOST_NAMES)

        self.progress(0.4, "Analizando entradas del archivo hosts...")
        self.log("INFO", f"Entradas activas (sin comentarios): {len(entries)}")

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

                # Entradas legitimas por defecto: localhost -> 127.0.0.1 / ::1
                if blocking and (name in local_names or name.endswith(".localhost")):
                    continue

                if blocking:
                    # Bloqueo de dominios de seguridad = sabotaje del antivirus
                    if matches_keyword(name, SECURITY_DOMAIN_KEYWORDS):
                        self.add_finding(
                            "ALERT",
                            f"Linea {line_number}: el dominio de seguridad '{hostname}' esta "
                            f"BLOQUEADO hacia {ip} -> tipico de malware que corta las "
                            f"actualizaciones del antivirus")
                    else:
                        blocked.append(hostname)
                    continue

                # IP externa: secuestro de resolucion de nombres
                redirections += 1
                if matches_keyword(name, FINANCIAL_DOMAIN_KEYWORDS):
                    self.add_finding(
                        "ALERT",
                        f"Linea {line_number}: dominio FINANCIERO '{hostname}' redirigido a {ip} "
                        f"-> patron de troyano bancario / phishing. NO inicie sesion en ese sitio.")
                elif matches_keyword(name, SECURITY_DOMAIN_KEYWORDS):
                    self.add_finding(
                        "ALERT",
                        f"Linea {line_number}: dominio de seguridad '{hostname}' redirigido a {ip} "
                        f"-> intento de suplantar las actualizaciones del antivirus.")
                else:
                    self.add_finding(
                        "ALERT",
                        f"Linea {line_number}: '{hostname}' redirigido a la IP externa {ip} "
                        f"-> secuestro de DNS local (no es una configuracion habitual).")

        if blocked:
            # Las listas anti-publicidad generan miles de lineas: se resumen.
            examples = ", ".join(blocked[:3])
            self.log("INFO", f"{len(blocked)} dominios anulados hacia loopback/0.0.0.0 "
                             f"(tipico de listas anti-publicidad). Ejemplos: {examples}")
        if redirections == 0:
            self.log("OK", "El archivo hosts no contiene redirecciones a IPs externas.")
        self.progress(1.0, "Archivo hosts auditado")

    # =====================================================================
    # MODULO 7 - Estado de Defensas (sabotaje)                  [NUEVO v3.0]
    # =====================================================================
    def scan_security_defenses(self):
        """
        Audita (SOLO LECTURA) las directivas y servicios que el malware
        desactiva para sobrevivir: Defender, sus exclusiones, el firewall,
        el UAC y los servicios de seguridad.
        """
        hklm = winreg.HKEY_LOCAL_MACHINE

        # --- 1) Directivas de Windows Defender ---------------------------
        self.progress(0.05, "Comprobando directivas de Windows Defender...")
        sabotaged = 0
        for subkey, value_name, description, severity in DEFENDER_CHECKS:
            if self.stopped():
                return
            value, error = reg_read_dword(hklm, subkey, value_name)
            if error == "denied":
                self.log("WARN", f"Acceso denegado a {value_name} (se requiere administrador).")
                continue
            if error == "missing":
                continue                      # ausente = configuracion por defecto = correcto
            if value == 1:
                sabotaged += 1
                self.add_finding(severity, f"DEFENSA SABOTEADA: {description} "
                                           f"[{value_name}=1 en HKLM\\{subkey}]")
            else:
                self.log("OK", f"{value_name}={value} (sin sabotaje).")
        if sabotaged == 0:
            self.log("OK", "Ninguna directiva desactiva Windows Defender.")
        else:
            self.log("ALERT", "Si no instalo otro antivirus, estas directivas son obra de malware "
                              "o de un 'optimizador' que dejo el equipo indefenso.")

        # --- 2) Exclusiones de Defender ----------------------------------
        self.progress(0.35, "Revisando exclusiones de Defender...")
        for subkey, kind in DEFENDER_EXCLUSION_KEYS:
            if self.stopped():
                return
            try:
                values = reg_enum_values(hklm, subkey)
            except FileNotFoundError:
                continue
            except PermissionError:
                self.log("INFO", f"Exclusiones por {kind}: acceso denegado "
                                 f"(normal con Tamper Protection activo).")
                continue
            except OSError as exc:
                self.log("WARN", f"Exclusiones por {kind}: no se pudo leer ({exc}).")
                continue

            for name, _data, _vtype in values:
                if EXCLUSION_HIGH_RISK_RX.match(name.strip()):
                    self.add_finding("ALERT", f"Exclusion de Defender de ALTO RIESGO ({kind}): "
                                              f"'{name}' -> el malware alojado ahi no se analiza.")
                else:
                    self.add_finding("WARN", f"Exclusion de Defender ({kind}): '{name}' "
                                             f"-> verifique que la anadio usted.")

        # --- 3) Firewall de Windows --------------------------------------
        self.progress(0.6, "Comprobando el Firewall de Windows...")
        for profile_key, profile_label in FIREWALL_PROFILES:
            if self.stopped():
                return
            value, error = reg_read_dword(hklm, f"{FIREWALL_ROOT}\\{profile_key}", "EnableFirewall")
            if error == "denied":
                self.log("WARN", f"Firewall (perfil {profile_label}): acceso denegado.")
            elif error == "missing":
                self.log("INFO", f"Firewall (perfil {profile_label}): sin valor explicito "
                                 f"(activado por defecto).")
            elif value == 0:
                self.add_finding("ALERT", f"Firewall de Windows DESACTIVADO en el perfil "
                                          f"{profile_label} (EnableFirewall=0).")
            else:
                self.log("OK", f"Firewall (perfil {profile_label}): activado.")

        # --- 4) Control de cuentas de usuario (UAC) ----------------------
        self.progress(0.78, "Comprobando el Control de Cuentas (UAC)...")
        value, error = reg_read_dword(hklm, UAC_POLICY_KEY, "EnableLUA")
        if error is None and value == 0:
            self.add_finding("ALERT", "UAC DESACTIVADO (EnableLUA=0): cualquier programa puede "
                                      "elevarse sin pedir confirmacion.")
        elif error is None:
            self.log("OK", "UAC activado (EnableLUA=1).")
        value, error = reg_read_dword(hklm, UAC_POLICY_KEY, "ConsentPromptBehaviorAdmin")
        if error is None and value == 0:
            self.add_finding("WARN", "El UAC no pide confirmacion a los administradores "
                                     "(ConsentPromptBehaviorAdmin=0).")

        # --- 5) Servicios de seguridad deshabilitados --------------------
        self.progress(0.9, "Comprobando servicios de seguridad...")
        for service, description, severity in SECURITY_SERVICES:
            if self.stopped():
                return
            value, error = reg_read_dword(hklm, f"{SERVICES_ROOT}\\{service}", "Start")
            if error == "denied":
                self.log("INFO", f"Servicio {service}: acceso denegado (protegido).")
            elif error == "missing":
                self.log("INFO", f"Servicio {service} ({description}): no instalado.")
            elif value == 4:     # 4 = SERVICE_DISABLED
                self.add_finding(severity, f"Servicio DESHABILITADO: {service} ({description}) "
                                           f"-> Start=4 en el Registro.")
            else:
                self.log("OK", f"Servicio {service}: tipo de inicio {value} (habilitado).")
        self.progress(1.0, "Defensas auditadas")


# =============================================================================
# INTERFAZ GRAFICA
# =============================================================================
# Paleta "cyber" oscura
C_BG = "#0a0e14"
C_PANEL = "#111822"
C_PANEL_2 = "#172131"
C_BORDER = "#1f2a3a"
C_TEXT = "#c9d1d9"
C_MUTED = "#5c6773"
C_GREEN = "#00ff9c"
C_CYAN = "#00d4ff"
C_YELLOW = "#ffcc00"
C_RED = "#ff3b5c"
C_ORANGE = "#ff8c42"
C_TERMINAL = "#05080c"

FONT_UI = ("Segoe UI", 10)
FONT_UI_BOLD = ("Segoe UI Semibold", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_TINY = ("Segoe UI", 8)
FONT_TITLE = ("Segoe UI Black", 20)
FONT_MONO = ("Consolas", 10)
FONT_MONO_BOLD = ("Consolas", 10, "bold")
FONT_SCORE = ("Consolas", 22, "bold")

# Nivel -> (etiqueta visible, color)
LEVEL_STYLES = {
    "INFO":  ("INFO  ", C_CYAN),
    "OK":    ("OK    ", C_GREEN),
    "WARN":  ("AVISO ", C_YELLOW),
    "ALERT": ("ALERTA", C_RED),
    "ERROR": ("ERROR ", C_ORANGE),
    "SYS":   ("SYS   ", C_MUTED),
    "HEAD":  ("", C_GREEN),
}
# Niveles que se ocultan cuando el filtro "solo alertas" esta activo
FILTERED_LEVELS = ("INFO", "OK", "SYS")

# Banner ASCII generado por letras (Consolas renderiza los caracteres de caja)
_BANNER_LETTERS = {
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "V": ["██╗   ██╗", "██║   ██║", "██║   ██║", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚═══╝  "],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
}
BANNER = "\n".join("  " + " ".join(_BANNER_LETTERS[c][row] for c in "NOVA") for row in range(6))


class NovaPrivacyGuardApp:
    """Ventana principal. Solo el hilo principal toca los widgets."""

    def __init__(self, root):
        self.root = root
        self.stop_event = threading.Event()
        self.worker = None
        self._events = []                      # cola de eventos del motor
        self._events_lock = threading.Lock()
        self._closing = False
        self.log_lines = []                    # copia en texto plano para exportar
        self.findings = []                     # (hora, modulo, severidad, detalle)
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

    # ------------------------------------------------------------ ventana
    def _configure_window(self):
        self.root.title(f"{APP_NAME} v{APP_VERSION}  |  Modo SOLO LECTURA")
        self.root.configure(bg=C_BG)
        self.root.geometry("1220x880")
        self.root.minsize(1000, 700)

    def _configure_styles(self):
        style = ttk.Style(self.root)
        try:
            # 'clam' respeta colores personalizados (el tema 'vista' los ignora)
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Nova.Horizontal.TProgressbar", troughcolor=C_PANEL_2,
                        background=C_GREEN, borderwidth=0, thickness=16)
        style.configure("NovaAlert.Horizontal.TProgressbar", troughcolor=C_PANEL_2,
                        background=C_RED, borderwidth=0, thickness=16)
        style.configure("Nova.Vertical.TScrollbar", troughcolor=C_TERMINAL,
                        background=C_PANEL_2, borderwidth=0)

    def _make_button(self, parent, text, command, accent, compact=False):
        """Boton plano con efecto hover (tk.Button permite colores en Windows)."""
        button = tk.Button(parent, text=text, command=command,
                           font=FONT_SMALL if compact else FONT_UI_BOLD,
                           fg=accent, bg=C_PANEL_2, activeforeground=C_BG,
                           activebackground=accent, disabledforeground=C_MUTED,
                           relief="flat", bd=0, padx=10 if compact else 18,
                           pady=4 if compact else 8, cursor="hand2")

        def on_enter(_event):
            if str(button["state"]) != "disabled":
                button.configure(bg=accent, fg=C_BG)

        def on_leave(_event):
            button.configure(bg=C_PANEL_2, fg=accent)

        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)
        return button

    def _bind_shortcuts(self):
        """Atajos de teclado (comodos durante un triaje)."""
        self.root.bind("<F5>", lambda _e: self.start_scan())
        self.root.bind("<Escape>", lambda _e: self.stop_scan())
        self.root.bind("<Control-s>", lambda _e: self.export_report())
        self.root.bind("<Control-e>", lambda _e: self.export_findings_csv())
        self.root.bind("<Control-l>", lambda _e: self.clear_console())

    # ------------------------------------------------------ construccion UI
    def _build_ui(self):
        # --- Cabecera ------------------------------------------------------
        header = tk.Frame(self.root, bg=C_BG)
        header.pack(fill="x", padx=18, pady=(14, 0))
        tk.Label(header, text="◆ NOVA PRIVACY GUARD", font=FONT_TITLE,
                 fg=C_GREEN, bg=C_BG).pack(side="left")
        tk.Label(header, text=f"v{APP_VERSION}", font=FONT_SMALL,
                 fg=C_MUTED, bg=C_BG).pack(side="left", padx=(8, 0), pady=(12, 0))
        tk.Label(header, text=" ■ READ-ONLY  ·  ZERO DAMAGE ", font=("Consolas", 9, "bold"),
                 fg=C_BG, bg=C_GREEN, padx=8, pady=4).pack(side="right")
        tk.Label(self.root, text="Auditoría forense local  ·  Registro · Memoria · Hardware · PII · "
                                 "Red · DNS · Defensas",
                 font=FONT_UI, fg=C_MUTED, bg=C_BG, anchor="w").pack(fill="x", padx=20)
        tk.Frame(self.root, bg=C_BORDER, height=1).pack(fill="x", padx=18, pady=9)

        # --- Tarjetas de modulos: 2 filas x 4 columnas ---------------------
        cards = tk.Frame(self.root, bg=C_BG)
        cards.pack(fill="x", padx=18)
        for column in range(4):
            cards.columnconfigure(column, weight=1, uniform="cards")

        self.module_vars, self.module_status = [], []
        for index, (title, description) in enumerate(MODULE_INFO):
            row, column = divmod(index, 4)
            card = tk.Frame(cards, bg=C_PANEL, highlightbackground=C_BORDER, highlightthickness=1)
            card.grid(row=row, column=column, sticky="nsew",
                      padx=(0 if column == 0 else 8, 0), pady=(0 if row == 0 else 8, 0))

            var = tk.BooleanVar(value=True)
            tk.Checkbutton(card, text=f"0{index + 1}  {title}", variable=var, font=FONT_UI_BOLD,
                           fg=C_TEXT, bg=C_PANEL, activebackground=C_PANEL,
                           activeforeground=C_GREEN, selectcolor=C_BG, anchor="w",
                           bd=0, highlightthickness=0).pack(fill="x", padx=10, pady=(9, 0))
            tk.Label(card, text=description, font=FONT_SMALL, fg=C_MUTED, bg=C_PANEL,
                     anchor="w", justify="left", wraplength=235,
                     height=2).pack(fill="x", padx=12)
            status = tk.Label(card, text="● EN ESPERA", font=("Consolas", 9, "bold"),
                              fg=C_MUTED, bg=C_PANEL, anchor="w")
            status.pack(fill="x", padx=12, pady=(4, 9))

            self.module_vars.append(var)
            self.module_status.append(status)

        # --- Celda libre del grid: panel del indice de riesgo ---------------
        risk_row, risk_column = divmod(MODULE_COUNT, 4)
        risk_card = tk.Frame(cards, bg=C_PANEL, highlightbackground=C_GREEN, highlightthickness=1)
        risk_card.grid(row=risk_row, column=risk_column, sticky="nsew",
                       padx=(0 if risk_column == 0 else 8, 0), pady=(8, 0))
        tk.Label(risk_card, text="ÍNDICE DE RIESGO", font=("Consolas", 9, "bold"),
                 fg=C_MUTED, bg=C_PANEL, anchor="w").pack(fill="x", padx=12, pady=(9, 0))
        self.lbl_score = tk.Label(risk_card, text="0", font=FONT_SCORE, fg=C_GREEN, bg=C_PANEL)
        self.lbl_score.pack(side="left", padx=(12, 6))
        right = tk.Frame(risk_card, bg=C_PANEL)
        right.pack(side="left", fill="both", expand=True, pady=(0, 6))
        self.lbl_verdict = tk.Label(right, text="SIN ANALIZAR", font=("Consolas", 9, "bold"),
                                    fg=C_MUTED, bg=C_PANEL, anchor="w")
        self.lbl_verdict.pack(fill="x")
        selectors = tk.Frame(right, bg=C_PANEL)
        selectors.pack(fill="x", pady=(2, 0))
        self._make_button(selectors, "TODOS", lambda: self._select_modules(True),
                          C_CYAN, compact=True).pack(side="left")
        self._make_button(selectors, "NINGUNO", lambda: self._select_modules(False),
                          C_MUTED, compact=True).pack(side="left", padx=(4, 0))

        # --- Controles -----------------------------------------------------
        controls = tk.Frame(self.root, bg=C_BG)
        controls.pack(fill="x", padx=18, pady=(14, 4))
        self.btn_start = self._make_button(controls, "▶  INICIAR ESCANEO", self.start_scan, C_GREEN)
        self.btn_stop = self._make_button(controls, "■  DETENER", self.stop_scan, C_RED)
        self.btn_clear = self._make_button(controls, "⌫  LIMPIAR", self.clear_console, C_CYAN)
        self.btn_copy = self._make_button(controls, "⧉  COPIAR", self.copy_log, C_CYAN)
        self.btn_export = self._make_button(controls, "⇩  INFORME TXT", self.export_report, C_YELLOW)
        self.btn_csv = self._make_button(controls, "⇩  HALLAZGOS CSV",
                                         self.export_findings_csv, C_YELLOW)
        self.btn_start.pack(side="left")
        self.btn_stop.pack(side="left", padx=(8, 0))
        self.btn_csv.pack(side="right")
        self.btn_export.pack(side="right", padx=(0, 8))
        self.btn_copy.pack(side="right", padx=(0, 8))
        self.btn_clear.pack(side="right", padx=(0, 8))
        self.btn_stop.configure(state="disabled")

        # --- Barra de progreso ---------------------------------------------
        progress_row = tk.Frame(self.root, bg=C_BG)
        progress_row.pack(fill="x", padx=18, pady=(10, 2))
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progressbar = ttk.Progressbar(progress_row, style="Nova.Horizontal.TProgressbar",
                                           variable=self.progress_var, maximum=100)
        self.progressbar.pack(side="left", fill="x", expand=True)
        self.lbl_percent = tk.Label(progress_row, text="  0%", width=6, font=("Consolas", 11, "bold"),
                                    fg=C_GREEN, bg=C_BG, anchor="e")
        self.lbl_percent.pack(side="right")
        self.lbl_task = tk.Label(self.root, text="Listo. Selecciona los módulos y pulsa INICIAR "
                                                 "ESCANEO (F5).",
                                 font=FONT_SMALL, fg=C_MUTED, bg=C_BG, anchor="w")
        self.lbl_task.pack(fill="x", padx=20)

        # --- Barra de estado (se empaqueta antes que la consola expansible) --
        statusbar = tk.Frame(self.root, bg=C_PANEL)
        statusbar.pack(side="bottom", fill="x")
        self.lbl_state = tk.Label(statusbar, text="ESTADO: INACTIVO", font=("Consolas", 9, "bold"),
                                  fg=C_MUTED, bg=C_PANEL, padx=14, pady=5)
        self.lbl_state.pack(side="left")
        self.lbl_counters = tk.Label(statusbar, text="", font=("Consolas", 9),
                                     fg=C_TEXT, bg=C_PANEL, padx=14)
        self.lbl_counters.pack(side="right")

        # --- Consola tipo terminal ------------------------------------------
        frame = tk.Frame(self.root, bg=C_BORDER, padx=1, pady=1)
        frame.pack(fill="both", expand=True, padx=18, pady=(8, 12))
        titlebar = tk.Frame(frame, bg=C_PANEL)
        titlebar.pack(fill="x")
        tk.Label(titlebar, text="  ● ● ●    nova@guard:~$ tail -f live-audit.log", font=("Consolas", 9),
                 fg=C_MUTED, bg=C_PANEL, anchor="w").pack(side="left", pady=4)
        self.filter_var = tk.BooleanVar(value=False)
        tk.Checkbutton(titlebar, text="Solo alertas y avisos", variable=self.filter_var,
                       command=self._apply_filter, font=FONT_TINY, fg=C_MUTED, bg=C_PANEL,
                       activebackground=C_PANEL, activeforeground=C_YELLOW, selectcolor=C_BG,
                       bd=0, highlightthickness=0).pack(side="right", padx=8)

        body = tk.Frame(frame, bg=C_TERMINAL)
        body.pack(fill="both", expand=True)
        self.console = tk.Text(body, bg=C_TERMINAL, fg=C_TEXT, insertbackground=C_GREEN,
                               selectbackground="#1f3b57", font=FONT_MONO, relief="flat",
                               bd=0, padx=10, pady=8, wrap="word", state="disabled")
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.console.yview,
                                  style="Nova.Vertical.TScrollbar")
        self.console.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.console.pack(side="left", fill="both", expand=True)

        # Etiquetas de color de la consola
        self.console.tag_configure("ts", foreground=C_MUTED)
        self.console.tag_configure("msg", foreground=C_TEXT)
        self.console.tag_configure("msg_ALERT", foreground="#ff8095")
        self.console.tag_configure("msg_WARN", foreground="#ffe08a")
        self.console.tag_configure("head", foreground=C_GREEN, font=FONT_MONO_BOLD)
        self.console.tag_configure("banner", foreground=C_GREEN)
        for level, (_label, color) in LEVEL_STYLES.items():
            self.console.tag_configure(f"lvl_{level}", foreground=color, font=FONT_MONO_BOLD)
            # Etiqueta por linea: permite ocultar niveles con el filtro
            self.console.tag_configure(f"line_{level}")

        self._refresh_counters()

    def _print_banner(self):
        self.console.configure(state="normal")
        self.console.insert("end", BANNER + "\n", "banner")
        self.console.insert("end", f"  PRIVACY GUARD v{APP_VERSION}  ::  forensic read-only auditor "
                                   f"::  7 modulos\n\n", "head")
        self.console.configure(state="disabled")
        try:
            winver = sys.getwindowsversion()
            os_text = f"Windows {winver.major}.{winver.minor} build {winver.build}"
        except AttributeError:
            os_text = sys.platform
        self._append_log("SYS", f"Equipo: {os.environ.get('COMPUTERNAME', '?')} | "
                                f"Usuario: {os.environ.get('USERNAME', '?')} | {os_text} | "
                                f"Python {sys.version.split()[0]}")
        self._append_log("SYS", "Política Zero Damage: Registro con KEY_READ, archivos en modo 'rb', "
                                "sin terminar procesos ni cerrar conexiones.")
        self._append_log("SYS", "Atajos: F5 escanear · Esc detener · Ctrl+S informe · "
                                "Ctrl+E CSV · Ctrl+L limpiar.")
        if not IS_WINDOWS or winreg is None:
            self._append_log("ERROR", "Este sistema no es Windows: el escaneo está deshabilitado.")

    # ------------------------------------------------ comunicacion con hilo
    def emit(self, event):
        """Llamado desde el hilo de escaneo. Solo encola (thread-safe)."""
        with self._events_lock:
            self._events.append(event)

    def _poll_events(self):
        """Hilo principal: procesa eventos pendientes y se reprograma."""
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
            pass  # la ventana se esta destruyendo

    def _handle_event(self, event):
        kind = event[0]
        if kind == "log":
            self._append_log(event[1], event[2])
        elif kind == "finding":
            severity, module_index, detail = event[1], event[2], event[3]
            self.counters[severity] = self.counters.get(severity, 0) + 1
            self.findings.append((time.strftime("%Y-%m-%d %H:%M:%S"),
                                  MODULE_INFO[module_index][0], severity, detail))
            if severity == "ALERT":
                self.progressbar.configure(style="NovaAlert.Horizontal.TProgressbar")
        elif kind == "progress":
            percent = event[1]
            self.progress_var.set(percent)
            self.lbl_percent.configure(text=f"{percent:3.0f}%")
            if event[2]:
                text = event[2]
                self.lbl_task.configure(text=text if len(text) <= 120 else text[:117] + "...")
        elif kind == "module":
            self._set_module_state(*event[1:])
        elif kind == "done":
            self._on_scan_finished(event[1])

    # ----------------------------------------------------------- consola
    def _append_log(self, level, message):
        timestamp = time.strftime("%H:%M:%S")
        label, _color = LEVEL_STYLES.get(level, LEVEL_STYLES["INFO"])
        line_tag = f"line_{level}"
        self.console.configure(state="normal")
        if level == "HEAD":
            self.console.insert("end", f"\n[{timestamp}] {message}\n", ("head", line_tag))
            plain = f"\n[{timestamp}] {message}"
        else:
            body_tag = f"msg_{level}" if level in ("ALERT", "WARN") else "msg"
            self.console.insert("end", f"[{timestamp}] ", ("ts", line_tag))
            self.console.insert("end", f"[{label}] ", (f"lvl_{level}", line_tag))
            self.console.insert("end", message + "\n", (body_tag, line_tag))
            plain = f"[{timestamp}] [{label}] {message}"

        # Limitar el numero de lineas para no degradar el rendimiento
        line_count = int(self.console.index("end-1c").split(".")[0])
        if line_count > MAX_CONSOLE_LINES:
            self.console.delete("1.0", f"{line_count - MAX_CONSOLE_LINES}.0")
        self.console.configure(state="disabled")
        self.console.see("end")
        self.log_lines.append(plain)

    def _apply_filter(self):
        """Oculta/muestra las lineas informativas usando la opcion 'elide'."""
        hide = self.filter_var.get()
        for level in FILTERED_LEVELS:
            self.console.tag_configure(f"line_{level}", elide=hide)
        self.console.see("end")

    def _set_module_state(self, index, state, alerts, warns):
        label = self.module_status[index]
        if state == "RUNNING":
            label.configure(text="◉ ANALIZANDO...", fg=C_CYAN)
        elif state == "SKIPPED":
            label.configure(text="— OMITIDO", fg=C_MUTED)
        elif state == "CANCELLED":
            label.configure(text="■ CANCELADO", fg=C_ORANGE)
        elif state == "ERROR":
            label.configure(text="✖ ERROR", fg=C_ORANGE)
        elif alerts:
            label.configure(text=f"✖ {alerts} ALERTA(S)" + (f" · {warns} AVISO(S)" if warns else ""),
                            fg=C_RED)
        elif warns:
            label.configure(text=f"▲ {warns} AVISO(S)", fg=C_YELLOW)
        else:
            label.configure(text="✔ LIMPIO", fg=C_GREEN)

    def _refresh_counters(self):
        minutes, seconds = divmod(int(self.elapsed), 60)
        self.lbl_counters.configure(
            text=f"ALERTAS: {self.counters['ALERT']}   │   AVISOS: {self.counters['WARN']}"
                 f"   │   TIEMPO: {minutes:02d}:{seconds:02d}")
        score = compute_risk_score(self.counters["ALERT"], self.counters["WARN"])
        color = C_GREEN if score == 0 else C_YELLOW if score < 60 else C_RED
        self.lbl_score.configure(text=str(score), fg=color)
        if self.scan_started is not None or score:
            self.lbl_verdict.configure(text=risk_verdict(score), fg=color)

    def _select_modules(self, value):
        """Marca o desmarca las 7 casillas de golpe."""
        for var in self.module_vars:
            var.set(value)

    # ------------------------------------------------------------ acciones
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

        # Reinicio del estado visual
        self.counters = {"ALERT": 0, "WARN": 0}
        self.findings = []
        self.elapsed = 0.0
        self.progress_var.set(0)
        self.lbl_percent.configure(text="  0%")
        self.progressbar.configure(style="Nova.Horizontal.TProgressbar")
        for label in self.module_status:
            label.configure(text="● EN ESPERA", fg=C_MUTED)

        self.btn_start.configure(state="disabled", bg=C_PANEL_2, fg=C_GREEN)
        self.btn_stop.configure(state="normal")
        self.btn_export.configure(state="disabled")
        self.btn_csv.configure(state="disabled")
        self.lbl_state.configure(text="ESTADO: ESCANEANDO...", fg=C_CYAN)
        self._append_log("HEAD", "#### NUEVA AUDITORIA INICIADA ####")

        # Lanzamiento del motor en un hilo secundario (daemon: no bloquea el cierre)
        self.stop_event.clear()
        engine = ScanEngine(self.emit, self.stop_event, enabled)
        self.worker = threading.Thread(target=engine.run, name="NovaScanWorker", daemon=True)
        self.scan_started = time.time()
        self.worker.start()

    def stop_scan(self):
        if self.worker is not None and self.worker.is_alive():
            self.stop_event.set()
            self.btn_stop.configure(state="disabled")
            self.lbl_state.configure(text="ESTADO: DETENIENDO...", fg=C_ORANGE)
            self._append_log("SYS", "Cancelación solicitada. Esperando a que el módulo actual "
                                    "se detenga...")

    def _on_scan_finished(self, summary):
        self.scan_started = None
        self.elapsed = summary["elapsed"]
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled", bg=C_PANEL_2, fg=C_RED)
        self.btn_export.configure(state="normal")
        self.btn_csv.configure(state="normal")

        if summary["cancelled"]:
            self.lbl_state.configure(text="ESTADO: CANCELADO (resultados parciales)", fg=C_ORANGE)
            self.lbl_task.configure(text="Escaneo cancelado.")
        else:
            self.progress_var.set(100)
            self.lbl_percent.configure(text="100%")
            self.lbl_task.configure(text=f"Auditoría finalizada en {summary['elapsed']:.1f} s.")
            if summary["alerts"]:
                self.lbl_state.configure(text=f"ESTADO: COMPLETADO — {summary['alerts']} ALERTA(S) "
                                              "REQUIEREN REVISIÓN", fg=C_RED)
            elif summary["warns"]:
                self.lbl_state.configure(text="ESTADO: COMPLETADO — solo avisos menores", fg=C_YELLOW)
            else:
                self.lbl_state.configure(text="ESTADO: COMPLETADO — SISTEMA LIMPIO", fg=C_GREEN)

    def clear_console(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
        self.log_lines.clear()

    def copy_log(self):
        """Copia el log al portapapeles (util para pegarlo en un ticket)."""
        if not self.log_lines:
            messagebox.showinfo(APP_NAME, "No hay registros que copiar.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(self.log_lines))
        self._append_log("SYS", f"{len(self.log_lines)} líneas copiadas al portapapeles.")

    def export_report(self):
        """
        Operacion de escritura #1: guarda el log en la ruta que el usuario
        elija. Los numeros de tarjeta nunca estan en el log (solo nombres de
        archivo), por lo que el informe no propaga PII.
        """
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
                handle.write(f"Generado: {time.strftime('%Y-%m-%d %H:%M:%S')} | "
                             f"Equipo: {os.environ.get('COMPUTERNAME', '?')}\n")
                handle.write(f"Alertas: {self.counters['ALERT']} | Avisos: {self.counters['WARN']} | "
                             f"Índice de riesgo: {score}/100 ({risk_verdict(score)})\n")
                handle.write("=" * 79 + "\n")
                handle.write("\n".join(self.log_lines) + "\n")
            self._append_log("SYS", f"Informe exportado a: {path}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"No se pudo guardar el informe:\n{exc}")

    def export_findings_csv(self):
        """
        Operacion de escritura #2: exporta solo los hallazgos en CSV para
        analizarlos en una hoja de calculo o cargarlos en un SIEM.
        El CSV se genera a mano (sin el modulo 'csv') para no anadir imports.
        """
        if not self.findings:
            messagebox.showinfo(APP_NAME, "No hay hallazgos que exportar. "
                                          "Ejecuta un escaneo primero.")
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
            # utf-8-sig: Excel reconoce los acentos sin preguntar
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


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================
def main():
    root = tk.Tk()
    NovaPrivacyGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
