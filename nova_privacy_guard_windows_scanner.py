#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
 NOVA Privacy Guard v3.2  ::  UI 'Obsidian' + Licencias  -  Auditoria forense
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
   * Excepcion documentada [v3.2]: al activar la licencia se guarda
     %APPDATA%\\NOVA Privacy Guard\\licencia.dat (datos del propio programa,
     nunca del sistema auditado).

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
import hashlib
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
APP_VERSION = "3.2.0"

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
# LICENCIAS (activacion offline)                                      [v3.2]
# -----------------------------------------------------------------------------
# El programa solo guarda la HUELLA (SHA-256 truncado) de cada clave valida,
# nunca la clave en claro: el codigo fuente puede ser publico sin exponerlas.
# Las claves reales viven en un archivo privado fuera del repositorio
# (privado/LICENCIAS_NOVA_PRIVADO.csv), generado con tools/generar_licencias.py.
#
# Persistencia: al activar se escribe %APPDATA%\NOVA Privacy Guard\licencia.dat
# con la huella de la clave y un sello ligado a este equipo. Son datos propios
# del programa, no del sistema auditado: el Registro se sigue abriendo solo con
# KEY_READ (tambien para leer el MachineGuid).
#
# Limitacion: una verificacion offline dentro de un .exe de Python se puede
# parchear. Esto frena la copia casual; no sustituye a un servidor de
# activacion si hace falta limitar cada clave a un unico equipo.
# =============================================================================
LICENSE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"   # sin 0/O ni 1/I/L
LICENSE_LENGTH = 15
LICENSE_PEPPER = "60969e3aee009256042d24109ed07de0"
LICENSE_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"),
                           "NOVA Privacy Guard")
LICENSE_FILE = os.path.join(LICENSE_DIR, "licencia.dat")
LICENSE_MAX_ATTEMPTS = 5          # fallos seguidos antes del bloqueo temporal
LICENSE_LOCKOUT_SECONDS = 30

# Huellas de las 100 licencias validas. Revocar una clave = borrar su huella.
VALID_LICENSE_HASHES = frozenset({
    "00860858efcc3c98895fcd3f3f4f5c16", "031f2e4fda0456c1329cc8e34e6776c4", "0681c2b758c454d2c7999a4bf9e31aae",
    "0a64e5914f8ea5a0f9a1acf37a35ba45", "0d5fd89f714656794eb605c9afc4009e", "0f5f6818017f3d149be4834422e58daf",
    "12379a30b53b9026d3e96739d6985301", "1242813672c3e4380f9270129b2045a0", "13aef8b281459c02f8808d9a16f604c0",
    "1445d22b857d45e08176adba3d3d649c", "1514729e58369ae2c7ff6beb0b0a350f", "15e5274732798625e7174f60747c0f9c",
    "1c6bc76fb3f6fb60de25aca98d6f6924", "1cb7c4a7c8539761a5a1603e13fde24c", "1faf6632ad80126af50c657f0d04f2d9",
    "20045ddbd530f1885a53b81c5bf99914", "24ee7b881030676f55e938275c442053", "252f2ad8b58707bf2e8a77488fa7445d",
    "2a077599bda6fabe919865b5d710e693", "2baf64bfed65ee13361cf29a145362c1", "2f9495d0203189856f16a22303c7986e",
    "348896d468f308cec8d50574efc6545c", "3807d4778fff2f7be05c243353a29cd4", "3afc6f120a297e3581aeb8f23f9976d0",
    "3d178e440467a8b13eeb8b74e0c38dee", "3d965e122e2770e2bfbd4940faa22181", "3ef30862fc765d74e466cf66f8a45465",
    "4273b7dedff4c6bd9c6e2f7e0ee6301a", "4415f9b32032979618127b58958b68bd", "44394b3cb7e7003c07821c8171e0386f",
    "4a6b82575323b7af9cc9a467c796c0af", "4d2a35932b0ae1e4e7119addbd1f665e", "527c09704214f57e465c2260401c9cd5",
    "532828ef7bdde765bd8acbcf77031625", "5752918151164e0753fe07d4e08ed31b", "5a9c7f67feb2d87e3ee0ca3a768b93ce",
    "63fe76203df36af43fd1374ae2e6a52f", "6b1ca9613f133bad4ed418c4dc008f0b", "70e0aac1d17f7f21edee6d8b14dc315d",
    "7155da4464704e8e819c4517b6d6595e", "717afe79a87be407683ca1d025cd2a50", "71dc25c39839456ae7d297d9b0f940a9",
    "78e4c6dd051056ee8264a458fc3d0102", "7ab58c3a7ca485abee6f57b873c5922f", "7b9a71d728b638d2e45729e35009edca",
    "7d17eb5953d274096516edb5cc6ac294", "7e35d8c0f6cf4ba2b8011ee2a649c1da", "85de1926246058a15b153fc8c7802f90",
    "86452b840e63088b836d3c5a7f6fcd27", "870c65de9dd886097441d52d20b6551d", "8cabaa5970cc7109c499d97653c678ed",
    "8fe72a0c20018b444bdb9220d27d25a3", "9127267e445a4553c609d255ebc54cb3", "91c7a33b6993645ef2cbba3ac27d1320",
    "9390efea82c0f048bc013d92132ea6a3", "94d6b7c0932bf84f4fd92a4659badf31", "951a5271b61d3c3c315bf237c9322101",
    "95ce318cdd23dc7c3bd0234718e1501c", "9ada20c9d86b1565fb28f9756a49781d", "a55f0f3e9e9576a212a07993ce3e6c7e",
    "a5fca014ac32c1359d55318200d457c7", "a7024e4ca1dbd6ec13eb055475ffd1ef", "a8b531bdf81f6a72767cae334b13507d",
    "a97b26904e12d76f6ff89dfb4429db34", "ac27c39f5f5f292b7d389299e55ec0fe", "af8b85a814dbe27b72d2886ddb05a562",
    "b4b32b8cd9cdfc1e3d6820716a7882e8", "b601a0827b139e477889a95f7410d15c", "b6f931e3b0f1dfc42cb5bbb2d0d636f7",
    "b87ae637a9cde46457c738aa5470b018", "b90e882175e6832624e746b70d4cd47f", "bbc49d03edb1e4d37713799d2893e681",
    "bd1380bdd3caadf4075fe64a48b2dcd2", "c37d27e89f4b12eebfd63ce1aa001807", "c5cfa54be83b8f0b078133563bd19e9e",
    "c5fe0ab84a7c15af31f3517395a6aec1", "c78ff344d36a8a5af550b094bdd73bbd", "cad0d5401643939238ff3506f43ccb17",
    "cd1d6ac8c6333bfd83e20abebb5e007d", "d0518a0f852e40a70181384c5c407ff6", "d18e34cda2ddcf19daa9bc0d2020c804",
    "d1e1f3730268bc3ebb38e0ef2716a70a", "d2a4b9a398820fb295f5c01d7081d3da", "d3da1f7d16462af41ca45b51493a7416",
    "da61742f36dbc448f1953dd3bfc0dd71", "db9fecb6bd0f5f84e8212da9a8269544", "dc07a18e0a503b3a19f94877029eac67",
    "dee8bb870da07505d7f6461bd8dbfc5b", "e053857e3e9b24dd281b37d078057238", "e2b9aa18c97431772d96c7085b96f55d",
    "e30a9f2fa9157ac001099efb5f284c10", "e443220f8d9d724e2dcbd047560ebd94", "e8362688b4305f5f1b75db097d2653f8",
    "e92674245d9e605d30c1952c9553518a", "eab6b5625230f09672ca9aaa7acee866", "eb0f27f3cb9b9474b55d4b0791903656",
    "ed55ff30f62ebcac6557a5d7c22a11af", "ef1aa93e338c228b154faaf30895b499", "f1962b44a7f9f85c91c70fda4ee8aa21",
    "f224a89707cd9185d9e97668f1b71190",
})


def _license_digest(text):
    """SHA-256 truncado a 128 bits (32 caracteres hexadecimales)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def parse_license_input(text):
    """
    Normaliza lo que teclea el usuario (ignora guiones y espacios, pasa a
    mayusculas). Devuelve (clave, None) si el formato es correcto o
    (None, motivo) si no lo es.
    """
    cleaned = re.sub(r"[\s\-]", "", text or "").upper()
    if len(cleaned) != LICENSE_LENGTH:
        return None, (f"La clave debe tener {LICENSE_LENGTH} caracteres "
                      f"(has escrito {len(cleaned)}).")
    invalid = sorted({char for char in cleaned if char not in LICENSE_ALPHABET})
    if invalid:
        return None, ("Caracteres que no existen en las licencias: " + " ".join(invalid) +
                      "  (las claves nunca usan 0, O, 1, I ni L).")
    return cleaned, None


def format_license_key(key):
    """'ABCDEFGHJKMNPQR' -> 'ABCDE-FGHJK-MNPQR'."""
    return f"{key[:5]}-{key[5:10]}-{key[10:]}"


def license_key_hash(key):
    """Huella de una clave ya normalizada (lo unico que el programa conoce)."""
    return _license_digest(f"{LICENSE_PEPPER}|key|{key}")


def is_valid_license(key):
    """True si la clave normalizada pertenece a las licencias emitidas."""
    return license_key_hash(key) in VALID_LICENSE_HASHES


def get_machine_id():
    """
    Identificador estable del equipo: el MachineGuid de Windows, leido con
    KEY_READ. Si no esta disponible se recurre a equipo + usuario.
    """
    if winreg is not None:
        for view_flag in (winreg.KEY_WOW64_64KEY, 0):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Microsoft\Cryptography",
                                    0, winreg.KEY_READ | view_flag) as key:
                    value, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if value:
                        return str(value).lower()
            except OSError:
                continue
    return f"{os.environ.get('COMPUTERNAME', '?')}|{os.environ.get('USERNAME', '?')}".lower()


def _machine_seal(key_hash):
    """Sello que ata una activacion a este equipo concreto."""
    return _license_digest(f"{LICENSE_PEPPER}|machine|{key_hash}|{get_machine_id()}")


def save_license(key):
    """
    Guarda la activacion: huella + sello del equipo + ultimos 4 caracteres
    (solo para mostrarlos). La clave completa no se escribe en disco.
    Devuelve False si no se pudo guardar: entonces vale solo esta sesion.
    """
    key_hash = license_key_hash(key)
    try:
        os.makedirs(LICENSE_DIR, exist_ok=True)
        with open(LICENSE_FILE, "w", encoding="utf-8") as handle:
            handle.write(f"{key_hash}\n{_machine_seal(key_hash)}\n{key[-4:]}\n")
        return True
    except OSError:
        return False


def load_saved_license():
    """
    Devuelve los ultimos 4 caracteres de la licencia activada en este equipo,
    o None si no hay una activacion valida: no existe, se copio desde otro
    equipo, fue manipulada o la clave se revoco en una version posterior.
    """
    try:
        with open(LICENSE_FILE, encoding="utf-8") as handle:
            lines = [line.strip() for line in handle.read().splitlines()]
    except OSError:
        return None
    if len(lines) < 3:
        return None
    key_hash, seal, hint = lines[0], lines[1], lines[2]
    if key_hash not in VALID_LICENSE_HASHES:
        return None
    if seal != _machine_seal(key_hash):
        return None
    if len(hint) != 4 or any(char not in LICENSE_ALPHABET for char in hint):
        return None
    return hint


def masked_license(hint):
    """Muestra una licencia sin revelarla: •••••-•••••-•XXXX."""
    return f"•••••-•••••-•{hint}"


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
# INTERFAZ GRAFICA  ::  NOVA UI 3.1  "Obsidian"
# -----------------------------------------------------------------------------
# Rediseno completo de la capa visual. El motor (ScanEngine) no se toca: la GUI
# sigue hablando con el a traves de la misma cola de eventos thread-safe.
#
# Decisiones de diseno:
#   * Los controles se DIBUJAN sobre tk.Canvas (botones con esquinas
#     redondeadas, medidor de riesgo, barra de progreso) porque los widgets
#     nativos de tkinter tienen bordes 3D imposibles de aplanar del todo.
#   * Paleta oscura profunda con acentos neon y una sola fuente sin serifas
#     para la interfaz; monoespaciada solo dentro de la consola.
#   * Layout de panel de control: barra superior + lateral de mando + area de
#     trabajo (tarjetas de modulos sobre la consola en vivo).
# =============================================================================
from tkinter import font as tkfont

# --- Paleta -----------------------------------------------------------------
C_BG = "#0B0F19"           # fondo profundo
C_PANEL = "#111827"        # tarjetas y paneles
C_PANEL_ALT = "#161F32"    # panel elevado / hover
C_PANEL_HI = "#1B2639"     # pista de medidores
C_BORDER = "#1F2A3D"       # bordes en reposo
C_BORDER_HI = "#2F3E58"    # bordes al pasar el raton
C_TEXT = "#E5E7EB"         # texto principal
C_TEXT_DIM = "#9AA7B8"     # texto secundario
C_MUTED = "#64748B"        # texto terciario / deshabilitado
C_CONSOLE = "#080C14"      # fondo de la terminal

C_CYAN = "#22D3EE"         # informacion
C_EMERALD = "#34D399"      # sistema limpio / correcto
C_AMBER = "#FBBF24"        # avisos
C_CRIMSON = "#F43F5E"      # alertas
C_VIOLET = "#A78BFA"       # acento decorativo
C_BLUE = "#60A5FA"         # acento decorativo
C_ORANGE = "#FB923C"       # errores de ejecucion

# Acento decorativo de cada tarjeta de modulo (mismo orden que MODULE_INFO).
# Se evita el carmesi: esta reservado para las alertas y confundiria al usuario.
MODULE_ACCENTS = (C_CYAN, C_VIOLET, C_EMERALD, C_AMBER, C_BLUE, C_CYAN, C_VIOLET)

# --- Tipografia -------------------------------------------------------------
UI_FAMILY = "Segoe UI"       # tkinter recurre a Helvetica si no existe
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

# Nivel -> (etiqueta del chip, color de acento)
LEVEL_STYLES = {
    "INFO":  ("INFO", C_CYAN),
    "OK":    ("OK", C_EMERALD),
    "WARN":  ("AVISO", C_AMBER),
    "ALERT": ("ALERTA", C_CRIMSON),
    "ERROR": ("ERROR", C_ORANGE),
    "SYS":   ("SYS", C_MUTED),
    "HEAD":  ("", C_EMERALD),
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


# =============================================================================
# UTILIDADES DE DIBUJO
# =============================================================================
def blend(color_a, color_b, ratio):
    """Mezcla dos colores #RRGGBB. ratio=0 -> color_a, ratio=1 -> color_b."""
    ratio = min(max(ratio, 0.0), 1.0)
    a = [int(color_a[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(color_b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * ratio) for i in range(3))


def rounded_points(x1, y1, x2, y2, radius):
    """
    Puntos de un rectangulo redondeado para create_polygon(..., smooth=True).
    tkinter no dibuja esquinas redondeadas de forma nativa: se simulan
    duplicando los vertices y dejando que el suavizado haga la curva.
    """
    radius = min(radius, abs(x2 - x1) / 2, abs(y2 - y1) / 2)
    return [
        x1 + radius, y1, x2 - radius, y1, x2, y1, x2, y1 + radius,
        x2, y2 - radius, x2, y2, x2 - radius, y2, x1 + radius, y2,
        x1, y2, x1, y2 - radius, x1, y1 + radius, x1, y1,
    ]


def score_color(score):
    """Color del indice de riesgo segun su gravedad."""
    if score == 0:
        return C_EMERALD
    if score < 25:
        return C_EMERALD
    if score < 60:
        return C_AMBER
    return C_CRIMSON


# =============================================================================
# WIDGETS PERSONALIZADOS
# =============================================================================
class NeoButton(tk.Canvas):
    """
    Boton plano dibujado sobre un Canvas: esquinas redondeadas, sin relieve 3D
    y transicion suave de color al pasar el raton (animacion por interpolacion).
    kind: 'primary' (relleno), 'ghost' (contorno) o 'toggle' (interruptor).
    """

    HOVER_STEP = 0.22       # velocidad de la transicion (0-1 por fotograma)
    FRAME_MS = 16           # ~60 fps

    def __init__(self, parent, text, command=None, kind="ghost", accent=C_CYAN,
                 height=38, radius=9, font=FONT_BTN, surface=None, padding=22):
        surface = surface or parent["bg"]
        super().__init__(parent, height=height, bg=surface, highlightthickness=0,
                         bd=0, takefocus=0)
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
        self._active = False          # solo para kind='toggle'
        self._animation = None

        self.configure(width=tkfont.Font(font=font).measure(text) + padding * 2,
                       cursor="hand2")
        self.bind("<Configure>", lambda _e: self._draw())
        self.bind("<Enter>", lambda _e: self._animate_to(1.0))
        self.bind("<Leave>", lambda _e: self._on_leave())
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    # ---------------------------------------------------------- interaccion
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

    # ------------------------------------------------------------- estados
    def set_enabled(self, enabled):
        self._enabled = bool(enabled)
        self._hover = self._target = 0.0
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw()

    def set_active(self, active):
        """Estado encendido/apagado de los botones tipo interruptor."""
        self._active = bool(active)
        self._draw()

    def set_text(self, text):
        self.text = text
        self._draw()

    # ------------------------------------------------------------- pintado
    def _palette(self):
        """Devuelve (relleno, contorno, color_de_texto) segun estado y tipo."""
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
    """Barra de progreso plana con extremos redondeados."""

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
                                smooth=True, splinesteps=12,
                                fill=self.accent, outline=self.accent)


class RiskGauge(tk.Canvas):
    """
    Medidor de riesgo en arco (240 grados) con animacion de aguja.
    El numero central y el arco comparten color para leerse de un vistazo.
    """

    SWEEP = 240             # grados totales del arco
    START = 210             # grado inicial (izquierda-abajo)

    def __init__(self, parent, size=196, thickness=13, surface=C_PANEL):
        super().__init__(parent, width=size, height=int(size * 0.66),
                         bg=surface, highlightthickness=0, bd=0)
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

        # Un arco de 240 grados baja hasta medio radio por debajo del centro:
        # el alto util equivale a 1.5 radios, no a un diametro completo.
        margin = self.thickness / 2 + 4
        diameter = min(width - margin * 2, (height - margin) * 4 / 3)
        if diameter < 40:
            return
        x1 = (width - diameter) / 2
        y1 = margin
        box = (x1, y1, x1 + diameter, y1 + diameter)

        # Pista de fondo
        self.create_arc(box, start=self.START, extent=-self.SWEEP, style="arc",
                        width=self.thickness, outline=C_PANEL_HI)
        # Arco de valor
        color = score_color(self.value)
        extent = -self.SWEEP * self.value / 100.0
        if abs(extent) > 0.8:
            self.create_arc(box, start=self.START, extent=extent, style="arc",
                            width=self.thickness, outline=color)

        # Numero central: la tipografia se adapta al diametro disponible para
        # que el medidor siga siendo legible cuando la ventana es pequena.
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
    """
    Tarjeta de modulo. Toda su superficie es clicable para activar o desactivar
    el modulo (mas comodo que una casilla diminuta) y cambia de estado durante
    el escaneo: en espera, analizando, limpio, con avisos o con alertas.
    """

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

        # Franja de acento superior: color = estado del modulo
        self.stripe = tk.Frame(self, bg=accent, height=3)
        self.stripe.pack(fill="x")

        header = tk.Frame(self, bg=C_PANEL)
        header.pack(fill="x", padx=14, pady=(12, 0))
        self.chip = tk.Label(header, text=f"{index + 1:02d}", font=FONT_LABEL,
                             fg=accent, bg=blend(C_PANEL, accent, 0.14), padx=6, pady=2)
        self.chip.pack(side="left")
        self.switch = tk.Label(header, text="●", font=(UI_FAMILY, 11),
                               fg=accent, bg=C_PANEL)
        self.switch.pack(side="right")

        self.title = tk.Label(self, text=title, font=FONT_H2, fg=C_TEXT, bg=C_PANEL,
                              anchor="w", justify="left", wraplength=180)
        self.title.pack(fill="x", padx=14, pady=(8, 0))
        self.description = tk.Label(self, text=description, font=FONT_SMALL, fg=C_MUTED,
                                    bg=C_PANEL, anchor="nw", justify="left",
                                    wraplength=190, height=2)
        self.description.pack(fill="x", padx=14, pady=(2, 0))
        self.status = tk.Label(self, text="● EN ESPERA", font=FONT_LABEL, fg=C_MUTED,
                               bg=C_PANEL, anchor="w")
        self.status.pack(fill="x", padx=14, pady=(8, 12))

        # Un solo gesto: clic en cualquier punto de la tarjeta
        self._surfaces = [self, header, self.chip, self.switch, self.title,
                          self.description, self.status]
        for widget in self._surfaces:
            widget.bind("<Button-1>", self._toggle)
            widget.bind("<Enter>", self._on_enter)
            widget.bind("<Leave>", self._on_leave)
            widget.configure(cursor="hand2")

    # ------------------------------------------------------------ interaccion
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
        self.switch.configure(text="●" if enabled else "○",
                              fg=self.accent if enabled else C_MUTED)
        self.title.configure(fg=C_TEXT if enabled else C_MUTED)
        self.chip.configure(fg=self.accent if enabled else C_MUTED)
        # En reposo la franja va atenuada: el color pleno significa "resultado"
        self.stripe.configure(bg=blend(C_PANEL, self.accent, 0.5) if enabled else C_BORDER)
        if not enabled:
            self.status.configure(text="○ DESACTIVADO", fg=C_MUTED)
        else:
            self.status.configure(text="● EN ESPERA", fg=C_MUTED)

    # ---------------------------------------------------------------- estado
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


class LicenseGate(tk.Frame):
    """
    Pantalla de activacion. Se muestra antes que la ventana principal y no deja
    pasar sin una clave valida. Tras LICENSE_MAX_ATTEMPTS fallos seguidos
    bloquea la entrada LICENSE_LOCKOUT_SECONDS segundos para frenar a quien
    prueba claves a mano.
    """

    def __init__(self, root, on_success):
        super().__init__(root, bg=C_BG)
        self.root = root
        self.on_success = on_success
        self.attempts = 0
        self._lock_remaining = 0
        self._formatting = False
        self._done = False

        root.title(f"{APP_NAME} v{APP_VERSION}  ·  Activación de licencia")
        root.configure(bg=C_BG)
        width, height = 560, 480
        screen_w, screen_h = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{width}x{height}+{(screen_w - width) // 2}+"
                      f"{max((screen_h - height) // 2 - 40, 0)}")
        root.minsize(520, 460)

        self.pack(fill="both", expand=True)
        self._build()

    def _build(self):
        card = tk.Frame(self, bg=C_PANEL, highlightbackground=C_BORDER,
                        highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center", width=468)
        tk.Frame(card, bg=C_EMERALD, height=3).pack(fill="x")
        body = tk.Frame(card, bg=C_PANEL)
        body.pack(fill="both", padx=32, pady=(26, 26))

        brand = tk.Frame(body, bg=C_PANEL)
        brand.pack(anchor="w")
        tk.Label(brand, text="NOVA", font=(UI_FAMILY, 17, "bold"), fg=C_EMERALD,
                 bg=C_PANEL).pack(side="left")
        tk.Label(brand, text="PRIVACY GUARD", font=(UI_FAMILY, 17, "bold"), fg=C_TEXT,
                 bg=C_PANEL).pack(side="left", padx=(7, 0))

        tk.Label(body, text="ACTIVACIÓN DE LICENCIA", font=FONT_LABEL, fg=C_MUTED,
                 bg=C_PANEL).pack(anchor="w", pady=(18, 4))
        tk.Label(body, text="Introduce tu clave de 15 caracteres para desbloquear el auditor.",
                 font=FONT_BODY, fg=C_TEXT_DIM, bg=C_PANEL, wraplength=400,
                 justify="left").pack(anchor="w")

        self.key_var = tk.StringVar()
        self.key_var.trace_add("write", self._autoformat)
        self.entry = tk.Entry(body, textvariable=self.key_var,
                              font=(MONO_FAMILY, 17, "bold"), justify="center",
                              bg=C_CONSOLE, fg=C_TEXT, insertbackground=C_EMERALD,
                              disabledbackground=C_CONSOLE, disabledforeground=C_MUTED,
                              relief="flat", bd=0, highlightthickness=1,
                              highlightbackground=C_BORDER, highlightcolor=C_EMERALD)
        self.entry.pack(fill="x", pady=(18, 6), ipady=10)
        self.entry.bind("<Return>", lambda _event: self._activate())
        tk.Label(body, text="Formato XXXXX-XXXXX-XXXXX  ·  los guiones se añaden solos",
                 font=FONT_SMALL, fg=C_MUTED, bg=C_PANEL).pack(anchor="w")

        self.message = tk.Label(body, text="", font=FONT_BODY, fg=C_MUTED, bg=C_PANEL,
                                wraplength=400, justify="left", anchor="nw", height=2)
        self.message.pack(fill="x", pady=(12, 4))

        buttons = tk.Frame(body, bg=C_PANEL)
        buttons.pack(fill="x", pady=(4, 0))
        self.btn_activate = NeoButton(buttons, "ACTIVAR", self._activate, kind="primary",
                                      accent=C_EMERALD, height=42, surface=C_PANEL)
        self.btn_activate.pack(side="left", expand=True, fill="x", padx=(0, 6))
        NeoButton(buttons, "SALIR", self.root.destroy, accent=C_MUTED, height=42,
                  surface=C_PANEL).pack(side="left", expand=True, fill="x", padx=(6, 0))

        tk.Label(body, text="La activación se guarda solo en este equipo. "
                            "La clave no se envía a ningún servidor.",
                 font=FONT_SMALL, fg=C_MUTED, bg=C_PANEL, wraplength=400,
                 justify="left").pack(anchor="w", pady=(18, 0))
        self.entry.focus_set()

    # ------------------------------------------------------------ entrada
    def _autoformat(self, *_args):
        """
        Traza de escritura del campo. El formato se aplica en after_idle, FUERA
        de la traza: Tcl no vuelve a notificar a los demas observadores de una
        variable modificada dentro de su propia traza, y el Entry seguiria
        mostrando el texto sin formatear aunque la variable ya lo estuviera.
        """
        if self._formatting:
            return
        self._formatting = True
        self.after_idle(self._apply_format)

    def _apply_format(self):
        """Mayusculas, solo letras y numeros, maximo 15, guion cada 5."""
        raw = re.sub(r"[^0-9A-Za-z]", "", self.key_var.get()).upper()[:LICENSE_LENGTH]
        formatted = "-".join(raw[i:i + 5] for i in range(0, len(raw), 5))
        if formatted != self.key_var.get():
            self.key_var.set(formatted)
            self.entry.icursor("end")
        self._formatting = False

    def _show(self, text, color):
        self.message.configure(text=text, fg=color)

    # ---------------------------------------------------------- activacion
    def _activate(self):
        if self._done or self._lock_remaining > 0:
            return
        self._apply_format()                    # lo validado = lo que se ve
        key, error = parse_license_input(self.key_var.get())
        if error:
            self._show(error, C_AMBER)          # formato: no cuenta como intento
            return
        if not is_valid_license(key):
            self.attempts += 1
            remaining = LICENSE_MAX_ATTEMPTS - self.attempts
            if remaining <= 0:
                self._start_lockout()
            else:
                self._show(f"Clave no válida. Te quedan {remaining} intento(s) "
                           f"antes del bloqueo temporal.", C_CRIMSON)
                self.entry.select_range(0, "end")
            return

        self._done = True
        self.btn_activate.set_enabled(False)
        persisted = save_license(key)
        self._show("Licencia válida. Abriendo NOVA Privacy Guard...", C_EMERALD)
        self.after(450, lambda: self.on_success(key[-4:], persisted))

    def _start_lockout(self):
        self._lock_remaining = LICENSE_LOCKOUT_SECONDS
        self.attempts = 0
        self.btn_activate.set_enabled(False)
        self.entry.configure(state="disabled")
        self._tick_lockout()

    def _tick_lockout(self):
        if self._lock_remaining <= 0:
            self.btn_activate.set_enabled(True)
            self.entry.configure(state="normal")
            self.entry.select_range(0, "end")
            self.entry.focus_set()
            self._show("Puedes volver a intentarlo.", C_MUTED)
            return
        self._show(f"Demasiados intentos fallidos. Espera {self._lock_remaining} s "
                   f"para volver a intentarlo.", C_CRIMSON)
        self._lock_remaining -= 1
        self.after(1000, self._tick_lockout)


class NovaPrivacyGuardApp:
    """
    Ventana principal (UI 3.1 'Obsidian').
    Solo el hilo principal toca los widgets: el motor deja eventos en una cola
    protegida por un Lock y aqui se consumen con root.after().
    """

    def __init__(self, root, license_hint=None):
        self.root = root
        self.license_hint = license_hint       # ultimos 4 caracteres de la licencia
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
        self.root.title(f"{APP_NAME} v{APP_VERSION}  ·  Modo SOLO LECTURA")
        self.root.configure(bg=C_BG)
        # El tamano ideal (1320x900) no cabe en pantallas de 1366x768: se ajusta
        # al escritorio disponible y la ventana se centra.
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        width = min(1320, screen_w - 80)
        height = min(900, screen_h - 120)
        self.root.geometry(f"{width}x{height}+{(screen_w - width) // 2}+"
                           f"{max((screen_h - height) // 2 - 20, 0)}")
        self.root.minsize(1120, 620)

    def _configure_styles(self):
        """Solo queda ttk para la barra de desplazamiento de la consola."""
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")   # el tema 'vista' ignora los colores
        except tk.TclError:
            pass
        style.configure("Nova.Vertical.TScrollbar", troughcolor=C_CONSOLE,
                        background=C_PANEL_ALT, darkcolor=C_PANEL_ALT,
                        lightcolor=C_PANEL_ALT, bordercolor=C_CONSOLE,
                        arrowcolor=C_MUTED, borderwidth=0, arrowsize=12)
        style.map("Nova.Vertical.TScrollbar",
                  background=[("active", C_BORDER_HI)])

    # ------------------------------------------------------ construccion UI
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

    # ---- barra superior --------------------------------------------------
    def _build_appbar(self):
        bar = tk.Frame(self.root, bg=C_BG)
        bar.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 16))

        brand = tk.Frame(bar, bg=C_BG)
        brand.pack(side="left")
        line = tk.Frame(brand, bg=C_BG)
        line.pack(anchor="w")
        tk.Label(line, text="NOVA", font=FONT_BRAND, fg=C_EMERALD, bg=C_BG).pack(side="left")
        tk.Label(line, text="PRIVACY GUARD", font=FONT_BRAND, fg=C_TEXT,
                 bg=C_BG).pack(side="left", padx=(8, 0))
        tk.Label(brand, text="Auditoría forense local  ·  7 módulos  ·  sin agentes ni telemetría",
                 font=FONT_BODY, fg=C_MUTED, bg=C_BG).pack(anchor="w", pady=(2, 0))

        badges = tk.Frame(bar, bg=C_BG)
        badges.pack(side="right")
        self._badge(badges, "■  READ-ONLY · ZERO DAMAGE", C_EMERALD).pack(side="right")
        host = f"{os.environ.get('COMPUTERNAME', '?')} / {os.environ.get('USERNAME', '?')}"
        tk.Label(badges, text=host, font=FONT_SMALL, fg=C_MUTED,
                 bg=C_BG).pack(side="right", padx=(0, 14))

        tk.Frame(self.root, bg=C_BORDER, height=1).grid(row=0, column=0, sticky="sew",
                                                        padx=24)

    def _badge(self, parent, text, accent):
        """Pastilla redondeada dibujada en Canvas (no existe en tkinter)."""
        width = tkfont.Font(font=FONT_LABEL).measure(text) + 26
        canvas = tk.Canvas(parent, width=width, height=26, bg=C_BG,
                           highlightthickness=0, bd=0)
        canvas.create_polygon(rounded_points(1, 1, width - 1, 25, 12), smooth=True,
                              splinesteps=16, fill=blend(C_BG, accent, 0.16),
                              outline=blend(C_BG, accent, 0.45))
        canvas.create_text(width / 2, 13, text=text, fill=accent, font=FONT_LABEL)
        return canvas

    # ---- lateral de mando -------------------------------------------------
    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=C_BG, width=300, height=600)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        sidebar.grid_propagate(False)

        # Se usa grid con peso SOLO en la fila del medidor: cuando la pantalla
        # es baja (portatiles de 768 px) el arco se encoge y los contadores y
        # los botones conservan su tamano intacto.
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(0, weight=1, minsize=150)

        # Medidor de riesgo (fila elastica)
        gauge_card = tk.Frame(sidebar, bg=C_PANEL, highlightbackground=C_BORDER,
                              highlightthickness=1)
        gauge_card.grid(row=0, column=0, sticky="nsew")
        tk.Label(gauge_card, text="ÍNDICE DE RIESGO", font=FONT_LABEL, fg=C_MUTED,
                 bg=C_PANEL).pack(anchor="w", padx=16, pady=(12, 0))
        self.lbl_verdict = tk.Label(gauge_card, text="SIN ANALIZAR", font=FONT_H1,
                                    fg=C_MUTED, bg=C_PANEL)
        self.lbl_verdict.pack(side="bottom", pady=(0, 12))
        self.gauge = RiskGauge(gauge_card, size=214, thickness=13)
        self.gauge.pack(padx=16, pady=(4, 0), fill="both", expand=True)

        # Contadores primarios (tiempo y modulos viven en la barra de estado:
        # son secundarios y alli no compiten por el alto del lateral)
        stats = tk.Frame(sidebar, bg=C_BG)
        stats.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        stats.grid_columnconfigure(0, weight=1, uniform="stat")
        stats.grid_columnconfigure(1, weight=1, uniform="stat")
        self.stat_alerts = self._stat_tile(stats, "ALERTAS", C_CRIMSON, 0, 0)
        self.stat_warns = self._stat_tile(stats, "AVISOS", C_AMBER, 0, 1)

        actions = tk.Frame(sidebar, bg=C_BG)
        actions.grid(row=2, column=0, sticky="ew", pady=(14, 0))
        self._build_actions(actions)

        tk.Label(sidebar, text=f"v{APP_VERSION}  ·  F5 escanear · Esc detener · "
                               f"Ctrl+S · Ctrl+E",
                 font=FONT_SMALL, fg=C_MUTED, bg=C_BG,
                 justify="left").grid(row=3, column=0, sticky="w", pady=(12, 0))

    def _build_actions(self, actions):
        """Bloque de control: escaneo, exportaciones y utilidades."""
        tk.Label(actions, text="CONTROL DE ESCANEO", font=FONT_LABEL, fg=C_MUTED,
                 bg=C_BG).pack(anchor="w", pady=(0, 8))
        self.btn_start = NeoButton(actions, "INICIAR ESCANEO", self.start_scan,
                                   kind="primary", accent=C_EMERALD, height=42)
        self.btn_start.pack(fill="x")
        self.btn_stop = NeoButton(actions, "DETENER", self.stop_scan,
                                  accent=C_CRIMSON, height=34)
        self.btn_stop.pack(fill="x", pady=(8, 0))
        self.btn_stop.set_enabled(False)

        grid = tk.Frame(actions, bg=C_BG)
        grid.pack(fill="x", pady=(12, 0))
        grid.grid_columnconfigure(0, weight=1, uniform="act")
        grid.grid_columnconfigure(1, weight=1, uniform="act")
        self.btn_clear = NeoButton(grid, "LIMPIAR", self.clear_console, accent=C_CYAN,
                                   height=31, font=FONT_SMALL, padding=10)
        self.btn_copy = NeoButton(grid, "COPIAR", self.copy_log, accent=C_CYAN,
                                  height=31, font=FONT_SMALL, padding=10)
        self.btn_export = NeoButton(grid, "INFORME TXT", self.export_report,
                                    accent=C_AMBER, height=31, font=FONT_SMALL, padding=10)
        self.btn_csv = NeoButton(grid, "HALLAZGOS CSV", self.export_findings_csv,
                                 accent=C_AMBER, height=31, font=FONT_SMALL, padding=10)
        self.btn_clear.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self.btn_copy.grid(row=0, column=1, sticky="ew", padx=(4, 0))
        self.btn_export.grid(row=1, column=0, sticky="ew", padx=(0, 4), pady=(8, 0))
        self.btn_csv.grid(row=1, column=1, sticky="ew", padx=(4, 0), pady=(8, 0))

    def _stat_tile(self, parent, label, accent, row, column, value="0"):
        """Panel pequeno con una cifra grande. Devuelve la etiqueta del valor."""
        tile = tk.Frame(parent, bg=C_PANEL, highlightbackground=C_BORDER,
                        highlightthickness=1)
        tile.grid(row=row, column=column, sticky="nsew",
                  padx=(0, 5) if column == 0 else (5, 0),
                  pady=(0, 0) if row == 0 else (10, 0))
        value_label = tk.Label(tile, text=value, font=FONT_STAT, fg=accent, bg=C_PANEL)
        value_label.pack(anchor="w", padx=14, pady=(8, 0))
        tk.Label(tile, text=label, font=FONT_LABEL, fg=C_MUTED,
                 bg=C_PANEL).pack(anchor="w", padx=14, pady=(0, 8))
        return value_label

    # ---- area de trabajo --------------------------------------------------
    def _build_workspace(self, parent):
        workspace = tk.Frame(parent, bg=C_BG)
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.grid_rowconfigure(2, weight=1, minsize=150)   # la consola nunca desaparece
        workspace.grid_columnconfigure(0, weight=1)

        # --- Rejilla de tarjetas (2 filas x 4 columnas) --------------------
        cards = tk.Frame(workspace, bg=C_BG)
        cards.grid(row=0, column=0, sticky="ew")
        for column in range(4):
            cards.grid_columnconfigure(column, weight=1, uniform="cards")

        self.cards = []
        for index, (title, description) in enumerate(MODULE_INFO):
            row, column = divmod(index, 4)
            card = ModuleCard(cards, index, title, description,
                              MODULE_ACCENTS[index % len(MODULE_ACCENTS)],
                              self._on_module_toggle)
            card.grid(row=row, column=column, sticky="nsew",
                      padx=(0 if column == 0 else 10, 0),
                      pady=(0 if row == 0 else 10, 0))
            self.cards.append(card)
        self.module_vars = [card.var for card in self.cards]

        # Celda libre: selector rapido de modulos
        row, column = divmod(MODULE_COUNT, 4)
        selector = tk.Frame(cards, bg=C_PANEL, highlightbackground=C_BORDER,
                            highlightthickness=1)
        selector.grid(row=row, column=column, sticky="nsew",
                      padx=(0 if column == 0 else 10, 0), pady=(10, 0))
        tk.Label(selector, text="SELECCIÓN", font=FONT_LABEL, fg=C_MUTED,
                 bg=C_PANEL).pack(anchor="w", padx=14, pady=(14, 0))
        tk.Label(selector, text="Haz clic en una tarjeta\npara activarla o no",
                 font=FONT_SMALL, fg=C_MUTED, bg=C_PANEL, justify="left",
                 anchor="w").pack(fill="x", padx=14, pady=(4, 8))
        buttons = tk.Frame(selector, bg=C_PANEL)
        buttons.pack(fill="x", padx=14, pady=(0, 14))
        NeoButton(buttons, "TODOS", lambda: self._select_modules(True), accent=C_EMERALD,
                  height=30, font=FONT_SMALL, surface=C_PANEL,
                  padding=12).pack(side="left", expand=True, fill="x", padx=(0, 4))
        NeoButton(buttons, "NINGUNO", lambda: self._select_modules(False), accent=C_MUTED,
                  height=30, font=FONT_SMALL, surface=C_PANEL,
                  padding=12).pack(side="left", expand=True, fill="x", padx=(4, 0))

        # --- Progreso -------------------------------------------------------
        progress_card = tk.Frame(workspace, bg=C_PANEL, highlightbackground=C_BORDER,
                                 highlightthickness=1)
        progress_card.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        head = tk.Frame(progress_card, bg=C_PANEL)
        head.pack(fill="x", padx=18, pady=(14, 0))
        self.lbl_task = tk.Label(head, text="Listo. Selecciona los módulos y pulsa "
                                            "INICIAR ESCANEO (F5).",
                                 font=FONT_BODY, fg=C_TEXT_DIM, bg=C_PANEL, anchor="w")
        self.lbl_task.pack(side="left")
        self.lbl_percent = tk.Label(head, text="0%", font=FONT_H1, fg=C_EMERALD,
                                    bg=C_PANEL)
        self.lbl_percent.pack(side="right")
        self.progress = NeoProgress(progress_card, height=8, surface=C_PANEL,
                                    accent=C_EMERALD)
        self.progress.pack(fill="x", padx=18, pady=(10, 16))

        # --- Consola --------------------------------------------------------
        console_card = tk.Frame(workspace, bg=C_CONSOLE, highlightbackground=C_BORDER,
                                highlightthickness=1)
        console_card.grid(row=2, column=0, sticky="nsew", pady=(16, 0))
        console_card.grid_rowconfigure(1, weight=1)
        console_card.grid_columnconfigure(0, weight=1)

        titlebar = tk.Frame(console_card, bg=C_PANEL)
        titlebar.grid(row=0, column=0, sticky="ew")
        dots = tk.Canvas(titlebar, width=52, height=26, bg=C_PANEL,
                         highlightthickness=0, bd=0)
        for position, color in enumerate((C_CRIMSON, C_AMBER, C_EMERALD)):
            x = 16 + position * 13
            dots.create_oval(x - 4, 9, x + 4, 17, fill=blend(C_PANEL, color, 0.75),
                             outline="")
        dots.pack(side="left")
        tk.Label(titlebar, text="nova@guard  ~  registro en vivo", font=(MONO_FAMILY, 9),
                 fg=C_MUTED, bg=C_PANEL).pack(side="left", pady=5)
        self.filter_var = tk.BooleanVar(value=False)
        self.btn_filter = NeoButton(titlebar, "SOLO ALERTAS", self._toggle_filter,
                                    kind="toggle", accent=C_AMBER, height=24,
                                    radius=7, font=FONT_SMALL, surface=C_PANEL,
                                    padding=12)
        self.btn_filter.pack(side="right", padx=10, pady=4)

        self.console = tk.Text(console_card, bg=C_CONSOLE, fg=C_TEXT_DIM,
                               insertbackground=C_EMERALD, selectbackground="#1D3A5C",
                               font=FONT_MONO, relief="flat", bd=0, padx=18, pady=14,
                               wrap="word", state="disabled", spacing1=2, spacing3=3,
                               cursor="arrow")
        self.console.grid(row=1, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(console_card, orient="vertical",
                                  command=self.console.yview,
                                  style="Nova.Vertical.TScrollbar")
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.console.configure(yscrollcommand=scrollbar.set)

        # Sintaxis de la consola: chips de nivel + cuerpo atenuado
        self.console.tag_configure("ts", foreground=C_MUTED)
        self.console.tag_configure("msg", foreground=C_TEXT_DIM)
        self.console.tag_configure("msg_ALERT", foreground="#FFC2CD")
        self.console.tag_configure("msg_WARN", foreground="#FFE3A3")
        self.console.tag_configure("msg_OK", foreground="#A7F3D0")
        self.console.tag_configure("head", foreground=C_EMERALD, font=FONT_MONO_BOLD,
                                   spacing1=10, spacing3=6)
        self.console.tag_configure("banner", foreground=C_EMERALD)
        self.console.tag_configure("subtitle", foreground=C_MUTED)
        for level, (_label, color) in LEVEL_STYLES.items():
            self.console.tag_configure(f"chip_{level}", foreground=C_BG,
                                       background=color, font=(MONO_FAMILY, 9, "bold"))
            # Etiqueta por linea: permite ocultar niveles con el filtro
            self.console.tag_configure(f"line_{level}")

    # ---- barra de estado --------------------------------------------------
    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=C_PANEL, height=30)
        bar.grid(row=2, column=0, sticky="ew")
        self.state_dot = tk.Label(bar, text="●", font=(UI_FAMILY, 10), fg=C_MUTED,
                                  bg=C_PANEL)
        self.state_dot.pack(side="left", padx=(24, 6))
        self.lbl_state = tk.Label(bar, text="INACTIVO", font=FONT_LABEL, fg=C_MUTED,
                                  bg=C_PANEL)
        self.lbl_state.pack(side="left", pady=7)
        tk.Label(bar, text="Registro: KEY_READ  ·  Archivos: modo 'rb'  ·  "
                           "Procesos: solo lectura",
                 font=FONT_SMALL, fg=C_MUTED, bg=C_PANEL).pack(side="right", padx=(0, 24))
        tk.Label(bar, text="│", font=FONT_SMALL, fg=C_BORDER_HI,
                 bg=C_PANEL).pack(side="right", padx=14)
        self.stat_time = tk.Label(bar, text="TIEMPO 00:00", font=FONT_LABEL, fg=C_CYAN,
                                  bg=C_PANEL)
        self.stat_time.pack(side="right")
        self.stat_modules = tk.Label(bar, text=f"MÓDULOS {MODULE_COUNT}/{MODULE_COUNT}",
                                     font=FONT_LABEL, fg=C_EMERALD, bg=C_PANEL)
        self.stat_modules.pack(side="right", padx=(0, 16))
        if self.license_hint:
            tk.Label(bar, text=f"LICENCIA {masked_license(self.license_hint)}",
                     font=FONT_LABEL, fg=C_EMERALD, bg=C_PANEL).pack(side="right",
                                                                     padx=(0, 16))

    def _bind_shortcuts(self):
        """Atajos de teclado (comodos durante un triaje)."""
        self.root.bind("<F5>", lambda _e: self.start_scan())
        self.root.bind("<Escape>", lambda _e: self.stop_scan())
        self.root.bind("<Control-s>", lambda _e: self.export_report())
        self.root.bind("<Control-e>", lambda _e: self.export_findings_csv())
        self.root.bind("<Control-l>", lambda _e: self.clear_console())

    def _print_banner(self):
        self.console.configure(state="normal")
        self.console.insert("end", BANNER + "\n", "banner")
        self.console.insert("end", f"  PRIVACY GUARD v{APP_VERSION}   ::   auditor forense "
                                   f"de solo lectura   ::   7 módulos\n\n", "subtitle")
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
        if self.license_hint:
            self._append_log("SYS", f"Licencia activa en este equipo: "
                                    f"{masked_license(self.license_hint)}")
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
            self.console.insert("end", f"{message}\n", ("head", line_tag))
            plain = f"\n[{timestamp}] {message}"
        else:
            body_tag = f"msg_{level}" if level in ("ALERT", "WARN", "OK") else "msg"
            self.console.insert("end", f"{timestamp}  ", ("ts", line_tag))
            self.console.insert("end", f" {label} ", (f"chip_{level}", line_tag))
            self.console.insert("end", "  " + message + "\n", (body_tag, line_tag))
            plain = f"[{timestamp}] [{label}] {message}"

        # Limitar el numero de lineas para no degradar el rendimiento
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
        """Oculta/muestra las lineas informativas usando la opcion 'elide'."""
        hide = self.filter_var.get()
        for level in FILTERED_LEVELS:
            self.console.tag_configure(f"line_{level}", elide=hide)
        self.console.see("end")

    # -------------------------------------------------------------- estado
    def _set_module_state(self, index, state, alerts, warns):
        self.cards[index].set_status(state, alerts, warns)

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
        self.stat_modules.configure(text=f"MÓDULOS {active}/{MODULE_COUNT}",
                                    fg=C_EMERALD if active else C_MUTED)

    def _select_modules(self, value):
        """Marca o desmarca las 7 tarjetas de golpe."""
        for card in self.cards:
            card.var.set(value)
            card.reset()
        self._on_module_toggle()

    def _set_state_pill(self, text, color):
        self.lbl_state.configure(text=text, fg=color)
        self.state_dot.configure(fg=color)

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
            self.btn_stop.set_enabled(False)
            self._set_state_pill("DETENIENDO", C_ORANGE)
            self._append_log("SYS", "Cancelación solicitada. Esperando a que el módulo actual "
                                    "se detenga...")

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
                self._set_state_pill(f"COMPLETADO · {summary['alerts']} ALERTA(S) POR REVISAR",
                                     C_CRIMSON)
            elif summary["warns"]:
                self._set_state_pill("COMPLETADO · SOLO AVISOS MENORES", C_AMBER)
            else:
                self._set_state_pill("COMPLETADO · SISTEMA LIMPIO", C_EMERALD)
        self.gauge.set_score(summary["score"])
        self.lbl_verdict.configure(text=risk_verdict(summary["score"]),
                                   fg=score_color(summary["score"]))

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

    def launch(license_hint, persisted=True):
        """Sustituye la pantalla de activacion por la ventana principal."""
        for widget in root.winfo_children():
            widget.destroy()
        app = NovaPrivacyGuardApp(root, license_hint=license_hint)
        if not persisted:
            app._append_log("WARN", "No se pudo guardar la activacion en %APPDATA%: "
                                    "la licencia solo vale para esta sesion.")

    saved_hint = load_saved_license()
    if saved_hint:
        launch(saved_hint)            # equipo ya activado: directo a la aplicacion
    else:
        LicenseGate(root, on_success=launch)
    root.mainloop()


if __name__ == "__main__":
    main()
