#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
 NOVA Privacy Guard  -  Auditoría forense local de privacidad para Windows
===============================================================================
 VERSIÓN 3.1.0 Obsidian - Corrección de Importación Tkinter
===============================================================================
"""

import os
import sys
import time
import threading
import subprocess
import re
import ctypes
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import font as tkfont

# winreg solo existe en Windows.
try:
    import winreg
except ImportError:
    winreg = None

# =============================================================================
# CONFIGURACION GENERAL Y CONSTANTES DEL MOTOR
# =============================================================================
APP_NAME = "NOVA Privacy Guard"
APP_VERSION = "3.1.0 Obsidian"

IS_WINDOWS = sys.platform.startswith("win")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

POLL_MS = 80
MAX_CONSOLE_LINES = 5000
MAX_PII_FILE_SIZE = 20 * 1024 * 1024
PII_EXTENSIONS = (".txt", ".csv")

MODULE_INFO = (
    ("Registro (Startup)", "Claves Run / RunOnce en HKCU y HKLM"),
    ("Procesos (Memoria)", "tasklist vs. lista negra de malware"),
    ("Hardware (Cam/Mic)", "ConsentStore: acceso activo a cámara y micro"),
    ("Fugas de PII",       "Tarjetas sin cifrar en Documentos (.txt/.csv)"),
    ("Auditoría de Red",   "Conexiones activas y puertos peligrosos (netstat)"),
    ("Integridad DNS",     "Secuestro de archivo Hosts local"),
    ("Estado Defensas",    "Sabotaje de Windows Defender en Registro"),
)
MODULE_COUNT = len(MODULE_INFO)

RUN_SUBKEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)

STARTUP_HEURISTICS = (
    (re.compile(r"\\(?:temp|tmp)\\"), "Se ejecuta desde carpeta temporal", "ALERT"),
    (re.compile(r"\.(?:vbs|vbe|js|jse|wsf|wsh|hta)\b"), "Script de Windows Script Host", "ALERT"),
    (re.compile(r"\b(?:wscript|cscript|mshta)(?:\.exe)?\b"), "Intérprete de scripts", "ALERT"),
    (re.compile(r"powershell.*?(?:-e|-w\s+hidden|downloadstring|\biex\b)"), "PowerShell ofuscado", "ALERT"),
    (re.compile(r"https?://"), "Comando contiene URL remota", "ALERT"),
)

PROCESS_BLACKLIST = {
    "nc.exe": "Netcat - shell inversa", "ncat.exe": "Ncat - shell inversa",
    "keylogger.exe": "Keylogger genérico", "mimikatz.exe": "Mimikatz",
    "njrat.exe": "njRAT", "darkcomet.exe": "DarkComet",
    "remcos.exe": "Remcos RAT", "asyncrat.exe": "AsyncRAT",
}

CONSENT_BASE = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
CAPABILITIES = (("webcam", "Cámara web"), ("microphone", "Micrófono"))
FILETIME_EPOCH_DIFF = 116444736000000000
FILETIME_PER_SECOND = 10_000_000

CARD_CANDIDATE_RX = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?!-?\d)")
DANGEROUS_PORTS = {"4444", "1337", "666", "31337", "4445", "5555"}
DNS_TARGETS = ["facebook.com", "google.com", "youtube.com", "twitter.com", "instagram.com", "whatsapp.com"]

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def compute_risk_score(alerts, warns):
    if alerts == 0 and warns == 0:
        return 0
    score = (alerts * 35) + (warns * 10)
    return min(100, score)

def risk_verdict(score):
    if score == 0: return "SISTEMA SEGURO"
    if score < 25: return "RIESGO BAJO"
    if score < 60: return "RIESGO MODERADO"
    return "RIESGO CRÍTICO"

def filetime_to_str(filetime):
    try:
        if not filetime: return "-"
        epoch = (filetime - FILETIME_EPOCH_DIFF) / FILETIME_PER_SECOND
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))
    except:
        return "fecha inválida"

def read_text_readonly(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="ignore")
    return raw.decode("utf-8", errors="ignore")

def reg_query_int(key, value_name):
    try:
        data, _ = winreg.QueryValueEx(key, value_name)
        return int(data)
    except:
        return None

# =============================================================================
# MOTOR DE ESCANEO (7 MÓDULOS)
# =============================================================================
class ScanEngine:
    def __init__(self, emit, stop_event, enabled_modules):
        self.emit = emit
        self.stop_event = stop_event
        self.enabled = list(enabled_modules)
        self.findings = [] 
        self._current = 0
        self._completed = 0
        self._total = max(1, sum(1 for flag in self.enabled if flag))

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

    def run(self):
        started = time.time()
        cancelled = False
        steps = (
            self.scan_registry_startup, self.scan_processes,
            self.scan_hardware_privacy, self.scan_pii_leaks,
            self.scan_network, self.scan_dns, self.scan_defenses
        )
        try:
            self.log("SYS", "Motor iniciado en hilo secundario - modo SOLO LECTURA activo.")
            for index, step in enumerate(steps):
                if not self.enabled[index]:
                    self.emit(("module", index, "SKIPPED", 0, 0))
                    continue
                if self.stopped():
                    cancelled = True
                    break

                self._current = index
                self.emit(("module", index, "RUNNING", 0, 0))
                self.log("HEAD", f"==== MODULO {index + 1}/{MODULE_COUNT} :: {MODULE_INFO[index][0].upper()} ====")
                before = len(self.findings)
                try:
                    step()
                except Exception as exc:
                    self.log("ERROR", f"Fallo en el módulo: {exc!r}")
                
                new = self.findings[before:]
                alerts = sum(1 for f in new if f[1] == "ALERT")
                warns = sum(1 for f in new if f[1] == "WARN")
                state = "CANCELLED" if self.stopped() else "DONE"
                self.emit(("module", index, state, alerts, warns))
                
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
            
            self.log("HEAD", "==== RESUMEN DE LA AUDITORIA ====")
            if cancelled:
                self.log("WARN", "Escaneo cancelado: resultados parciales.")
            self.log("INFO", f"Duración: {elapsed:.1f} s | Alertas: {alerts} | Índice de Riesgo: {score}/100")
            
            self.emit(("done", {"alerts": alerts, "warns": warns, "score": score,
                                "elapsed": elapsed, "cancelled": cancelled}))

    def scan_registry_startup(self):
        self.progress(0.5, "Analizando claves de arranque (Run/RunOnce)...")
        hits = 0
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for subkey in RUN_SUBKEYS:
                if self.stopped(): return
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                        index = 0
                        while True:
                            try:
                                name, data, _ = winreg.EnumValue(key, index)
                                command = str(data).lower()
                                for regex, reason, severity in STARTUP_HEURISTICS:
                                    if regex.search(command):
                                        hits += 1
                                        self.add_finding(severity, f"[{name}] {reason}: {command}")
                                index += 1
                            except OSError:
                                break
                except OSError:
                    continue
        if hits == 0: self.log("OK", "Ninguna entrada de arranque maliciosa detectada.")
        self.progress(1.0, "Registro auditado")

    def scan_processes(self):
        self.progress(0.5, "Ejecutando tasklist...")
        try:
            result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            self.log("ERROR", f"Fallo al invocar tasklist: {e}")
            return

        hits = 0
        for line in result.stdout.splitlines():
            if self.stopped(): return
            match = re.match(r'^"([^"]+)","(\d+)"', line.strip())
            if match:
                name = match.group(1).lower()
                pid = match.group(2)
                if name in PROCESS_BLACKLIST:
                    hits += 1
                    self.add_finding("ALERT", f"Proceso malicioso activo: {name} (PID {pid}) -> {PROCESS_BLACKLIST[name]}")
        if hits == 0: self.log("OK", "Ningún proceso en memoria coincide con la lista negra.")
        self.progress(1.0, "Procesos auditados")

    def scan_hardware_privacy(self):
        self.progress(0.5, "Consultando ConsentStore...")
        hits = 0
        for capability, label in CAPABILITIES:
            if self.stopped(): return
            path = f"{CONSENT_BASE}\\{capability}"
            try:
                subkeys = []
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            subkeys.append(winreg.EnumKey(key, index))
                            index += 1
                        except OSError: break
                
                for app in subkeys:
                    app_path = f"{path}\\{app}"
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, app_path, 0, winreg.KEY_READ) as app_key:
                        start = reg_query_int(app_key, "LastUsedTimeStart")
                        stop = reg_query_int(app_key, "LastUsedTimeStop")
                        if start and (stop == 0 or stop < start):
                            hits += 1
                            self.add_finding("ALERT", f"{label} EN USO AHORA MISMO por: {app}")
            except OSError:
                continue
        if hits == 0: self.log("OK", "Ninguna aplicación está espiando cámara o micrófono en este momento.")
        self.progress(1.0, "Hardware auditado")

    def scan_pii_leaks(self):
        docs = os.path.join(os.path.expanduser("~"), "Documents")
        if not os.path.isdir(docs): return
        
        self.progress(0.2, "Indexando Documentos...")
        candidates = []
        for root, dirs, files in os.walk(docs):
            if self.stopped(): return
            for f in files:
                if f.lower().endswith(PII_EXTENSIONS):
                    candidates.append(os.path.join(root, f))
        
        hits = 0
        total = max(1, len(candidates))
        for i, path in enumerate(candidates):
            if self.stopped(): return
            if i % 5 == 0: self.progress(0.2 + 0.8 * (i / total), f"Analizando: {os.path.basename(path)}")
            try:
                if os.path.getsize(path) > MAX_PII_FILE_SIZE: continue
                text = read_text_readonly(path)
                if CARD_CANDIDATE_RX.search(text):
                    hits += 1
                    self.add_finding("WARN", f"Posible fuga PII (Tarjetas) en: {os.path.relpath(path, docs)}")
            except:
                continue
        if hits == 0: self.log("OK", "No se detectaron tarjetas expuestas en Documentos.")
        self.progress(1.0, "PII auditada")

    def scan_network(self):
        self.progress(0.5, "Ejecutando netstat...")
        try:
            res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            self.log("ERROR", f"Fallo al invocar netstat: {e}")
            return
            
        hits = 0
        for line in res.stdout.splitlines():
            if self.stopped(): return
            if "ESTABLISHED" in line:
                parts = line.split()
                if len(parts) >= 4:
                    local_ip_port = parts[1]
                    foreign_ip = parts[2]
                    port = local_ip_port.split(":")[-1]
                    if port in DANGEROUS_PORTS:
                        hits += 1
                        self.add_finding("ALERT", f"Conexión ACTIVA en puerto peligroso ({port}) hacia {foreign_ip}")
        if hits == 0: self.log("OK", "Ninguna conexión activa en puertos sospechosos de RATs.")
        self.progress(1.0, "Auditoría de Red completada")

    def scan_dns(self):
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        self.progress(0.5, "Verificando archivo Hosts...")
        if not os.path.exists(hosts_path):
            self.log("OK", "Archivo hosts no modificado (no existe).")
            return
            
        hits = 0
        try:
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"): continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip, domain = parts[0], parts[1].lower()
                        if ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                            for target in DNS_TARGETS:
                                if target in domain:
                                    hits += 1
                                    self.add_finding("ALERT", f"DNS Secuestrado: {domain} redirige a IP Externa {ip}")
        except Exception as e:
            self.log("WARN", f"No se pudo leer archivo hosts: {e}")
            
        if hits == 0: self.log("OK", "Archivo hosts limpio de redirecciones (Phishing).")
        self.progress(1.0, "Auditoría DNS completada")

    def scan_defenses(self):
        self.progress(0.5, "Auditando directivas de Windows Defender...")
        paths = [
            r"SOFTWARE\Policies\Microsoft\Windows Defender",
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        ]
        hits = 0
        for path in paths:
            if self.stopped(): return
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
                    for val in ["DisableAntiSpyware", "DisableRealtimeMonitoring"]:
                        if reg_query_int(key, val) == 1:
                            hits += 1
                            self.add_finding("ALERT", f"Defensas saboteadas: '{val}' está activado en el Registro.")
            except OSError:
                continue
        if hits == 0: self.log("OK", "Políticas de Windows Defender intactas y operativas.")
        self.progress(1.0, "Auditoría de Defensas completada")


# =============================================================================
# INTERFAZ GRAFICA :: UI 3.1 "Obsidian"
# =============================================================================
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
FONT_LABEL = (MONO_FAMILY, 8, "bold")
FONT_MONO = (MONO_FAMILY, 10)
FONT_MONO_BOLD = (MONO_FAMILY, 10, "bold")

LEVEL_STYLES = {
    "INFO":  ("INFO", C_CYAN), "OK": ("OK", C_EMERALD),
    "WARN":  ("AVISO", C_AMBER), "ALERT": ("ALERTA", C_CRIMSON),
    "ERROR": ("ERROR", C_ORANGE), "SYS": ("SYS", C_MUTED), "HEAD": ("", C_EMERALD),
}
FILTERED_LEVELS = ("INFO", "OK", "SYS")

_BANNER_LETTERS = {
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "V": ["██╗   ██╗", "██║   ██║", "██║   ██║", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚═══╝  "],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚╝  ╚╝  "],
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
    if score == 0: return C_EMERALD
    if score < 25: return C_EMERALD
    if score < 60: return C_AMBER
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
        if not self._enabled: return
        self._target = target
        if self._animation is None: self._step()

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

    def _palette(self):
        if not self._enabled: return C_PANEL, C_BORDER, C_MUTED
        if self.kind == "primary":
            fill = blend(self.accent, "#FFFFFF", 0.12 * self._hover)
            if self._pressed: fill = blend(fill, C_BG, 0.2)
            return fill, fill, C_BG
        if self.kind == "toggle" and self._active:
            fill = blend(C_PANEL_ALT, self.accent, 0.22 + 0.10 * self._hover)
            return fill, self.accent, self.accent
        fill = blend(C_PANEL_ALT, self.accent, 0.16 * self._hover)
        if self._pressed: fill = blend(fill, C_BG, 0.25)
        outline = blend(C_BORDER, self.accent, self._hover)
        text_color = blend(C_TEXT_DIM, self.accent, max(self._hover, 0.55))
        return fill, outline, text_color

    def _draw(self):
        width, height = self.winfo_width(), self.winfo_height()
        if width <= 1 or height <= 1: return
        fill, outline, text_color = self._palette()
        self.delete("all")
        self.create_polygon(rounded_points(1, 1, width - 1, height - 1, self.radius),
                            smooth=True, splinesteps=16, fill=fill, outline=outline)
        self.create_text(width / 2, height / 2 + 1, text=self.text, fill=text_color, font=self.font)

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
        if width <= 1: return
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
        if width <= 1: return
        self.delete("all")
        margin = self.thickness / 2 + 4
        diameter = min(width - margin * 2, (height - margin) * 4 / 3)
        if diameter < 40: return
        x1 = (width - diameter) / 2
        y1 = margin
        box = (x1, y1, x1 + diameter, y1 + diameter)
        self.create_arc(box, start=self.START, extent=-self.SWEEP, style="arc", width=self.thickness, outline=C_PANEL_HI)
        color = score_color(self.value)
        extent = -self.SWEEP * self.value / 100.0
        if abs(extent) > 0.8:
            self.create_arc(box, start=self.START, extent=extent, style="arc", width=self.thickness, outline=color)
        center_x = x1 + diameter / 2
        center_y = y1 + diameter / 2
        score_size = max(16, min(34, int(diameter * 0.23)))
        self.create_text(center_x, center_y - score_size * 0.12, text=f"{int(round(self.value))}", fill=color, font=(UI_FAMILY, score_size, "bold"))

class ModuleCard(tk.Frame):
    STATUS_TEXT = {
        "PENDING": ("EN ESPERA", C_MUTED), "RUNNING": ("ANALIZANDO", C_CYAN),
        "SKIPPED": ("OMITIDO", C_MUTED), "CANCELLED": ("CANCELADO", C_ORANGE),
        "ERROR": ("ERROR", C_ORANGE), "CLEAN": ("LIMPIO", C_EMERALD),
    }

    def __init__(self, parent, index, title, description, accent, on_toggle):
        super().__init__(parent, bg=C_PANEL, highlightbackground=C_BORDER, highlightcolor=C_BORDER, highlightthickness=1)
        self.index = index
        self.accent = accent
        self.on_toggle = on_toggle
        self.var = tk.BooleanVar(value=True)

        self.stripe = tk.Frame(self, bg=accent, height=3)
        self.stripe.pack(fill="x")
        header = tk.Frame(self, bg=C_PANEL)
        header.pack(fill="x", padx=14, pady=(12, 0))
        self.chip = tk.Label(header, text=f"{index + 1:02d}", font=FONT_LABEL, fg=accent, bg=blend(C_PANEL, accent, 0.14), padx=6, pady=2)
        self.chip.pack(side="left")
        self.switch = tk.Label(header, text="●", font=(UI_FAMILY, 11), fg=accent, bg=C_PANEL)
        self.switch.pack(side="right")
        self.title = tk.Label(self, text=title, font=FONT_H2, fg=C_TEXT, bg=C_PANEL, anchor="w", justify="left")
        self.title.pack(fill="x", padx=14, pady=(8, 0))
        self.description = tk.Label(self, text=description, font=FONT_SMALL, fg=C_MUTED, bg=C_PANEL, anchor="nw", justify="left", height=2)
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
        if self.on_toggle: self.on_toggle()

    def _on_enter(self, _event=None):
        for w in self._surfaces: 
            if w is not self.chip: w.configure(bg=C_PANEL_ALT)
        self.configure(highlightbackground=C_BORDER_HI)

    def _on_leave(self, _event=None):
        for w in self._surfaces: 
            if w is not self.chip: w.configure(bg=C_PANEL)
        self.configure(highlightbackground=C_BORDER)

    def _refresh_enabled(self):
        enabled = self.var.get()
        self.switch.configure(text="●" if enabled else "○", fg=self.accent if enabled else C_MUTED)
        self.title.configure(fg=C_TEXT if enabled else C_MUTED)
        self.status.configure(text="● EN ESPERA" if enabled else "○ DESACTIVADO", fg=C_MUTED)

    def reset(self):
        self._refresh_enabled()

    def set_status(self, state, alerts=0, warns=0):
        if state == "DONE":
            if alerts: text, color = f"{alerts} ALERTA(S)", C_CRIMSON
            elif warns: text, color = f"{warns} AVISO(S)", C_AMBER
            else: text, color = self.STATUS_TEXT["CLEAN"]
        else:
            text, color = self.STATUS_TEXT.get(state, self.STATUS_TEXT["PENDING"])
        self.status.configure(text=f"● {text}", fg=color)
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
        self.counters = {"ALERT": 0, "WARN": 0}
        self.scan_started = None
        self.elapsed = 0.0

        self._configure_window()
        self._configure_styles()
        self._build_ui()
        self._print_banner()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(POLL_MS, self._poll_events)

    def _configure_window(self):
        self.root.title(f"{APP_NAME} v{APP_VERSION}  ·  Modo SOLO LECTURA")
        self.root.configure(bg=C_BG)
        self.root.geometry("1220x880")
        self.root.minsize(1000, 700)

    def _configure_styles(self):
        style = ttk.Style(self.root)
        try: style.theme_use("clam")
        except: pass
        style.configure("Nova.Vertical.TScrollbar", troughcolor=C_CONSOLE, background=C_PANEL_ALT, borderwidth=0)

    def _build_ui(self):
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Barra superior
        bar = tk.Frame(self.root, bg=C_BG)
        bar.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 16))
        tk.Label(bar, text="NOVA PRIVACY GUARD", font=FONT_BRAND, fg=C_EMERALD, bg=C_BG).pack(side="left")

        body = tk.Frame(self.root, bg=C_BG)
        body.grid(row=1, column=0, sticky="nsew", padx=24, pady=(0, 14))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)

        # Sidebar izquierdo
        sidebar = tk.Frame(body, bg=C_BG, width=260)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        sidebar.grid_propagate(False)

        gauge_card = tk.Frame(sidebar, bg=C_PANEL, highlightbackground=C_BORDER, highlightthickness=1)
        gauge_card.pack(fill="x", pady=(0, 15))
        tk.Label(gauge_card, text="ÍNDICE DE RIESGO", font=FONT_LABEL, fg=C_MUTED, bg=C_PANEL).pack(anchor="w", padx=16, pady=(12, 0))
        self.lbl_verdict = tk.Label(gauge_card, text="SIN ANALIZAR", font=FONT_H1, fg=C_MUTED, bg=C_PANEL)
        self.lbl_verdict.pack(side="bottom", pady=(0, 12))
        self.gauge = RiskGauge(gauge_card, size=200, thickness=12)
        self.gauge.pack(padx=16, pady=(4, 0))

        self.btn_start = NeoButton(sidebar, "INICIAR ESCANEO", self.start_scan, kind="primary", accent=C_EMERALD, height=42)
        self.btn_start.pack(fill="x", pady=(0, 8))
        self.btn_stop = NeoButton(sidebar, "DETENER", self.stop_scan, accent=C_CRIMSON, height=34)
        self.btn_stop.pack(fill="x")
        self.btn_stop.set_enabled(False)

        # Área de trabajo derecho
        workspace = tk.Frame(body, bg=C_BG)
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.grid_rowconfigure(1, weight=1)
        workspace.grid_columnconfigure(0, weight=1)

        cards = tk.Frame(workspace, bg=C_BG)
        cards.grid(row=0, column=0, sticky="ew")
        for c in range(4): cards.grid_columnconfigure(c, weight=1, uniform="cards")

        self.cards = []
        for index, (title, description) in enumerate(MODULE_INFO):
            r, col = divmod(index, 4)
            card = ModuleCard(cards, index, title, description, MODULE_ACCENTS[index % len(MODULE_ACCENTS)], None)
            card.grid(row=r, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 0), pady=(0 if r == 0 else 8, 0))
            self.cards.append(card)
        self.module_vars = [card.var for card in self.cards]

        # Consola
        console_card = tk.Frame(workspace, bg=C_CONSOLE, highlightbackground=C_BORDER, highlightthickness=1)
        console_card.grid(row=1, column=0, sticky="nsew", pady=(15, 0))
        console_card.grid_rowconfigure(1, weight=1)
        console_card.grid_columnconfigure(0, weight=1)

        titlebar = tk.Frame(console_card, bg=C_PANEL)
        titlebar.grid(row=0, column=0, sticky="ew")
        tk.Label(titlebar, text="  nova@guard  ~  registro en vivo", font=(MONO_FAMILY, 9), fg=C_MUTED, bg=C_PANEL).pack(side="left", pady=5)

        self.console = tk.Text(console_card, bg=C_CONSOLE, fg=C_TEXT_DIM, font=FONT_MONO, relief="flat", bd=0, padx=14, pady=10, state="disabled")
        self.console.grid(row=1, column=0, sticky="nsew")

        for level, (_, color) in LEVEL_STYLES.items():
            self.console.tag_configure(f"chip_{level}", foreground=C_BG, background=color, font=(MONO_FAMILY, 9, "bold"))
        self.console.tag_configure("head", foreground=C_EMERALD, font=FONT_MONO_BOLD)

    def emit(self, event):
        with self._events_lock: self._events.append(event)

    def _poll_events(self):
        if self._closing: return
        with self._events_lock:
            events, self._events = self._events, []
        for ev in events: self._handle_event(ev)
        try: self.root.after(POLL_MS, self._poll_events)
        except tk.TclError: pass

    def _handle_event(self, event):
        kind = event[0]
        if kind == "log": self._append_log(event[1], event[2])
        elif kind == "finding":
            sev, mod_idx = event[1], event[2]
            self.counters[sev] = self.counters.get(sev, 0) + 1
        elif kind == "module": self.cards[event[1]].set_status(event[2], event[3], event[4])
        elif kind == "done": self._on_scan_finished(event[1])

    def _append_log(self, level, message):
        timestamp = time.strftime("%H:%M:%S")
        self.console.configure(state="normal")
        if level == "HEAD":
            self.console.insert("end", f"{message}\n", "head")
        else:
            self.console.insert("end", f"[{timestamp}] {message}\n")
        self.console.configure(state="disabled")
        self.console.see("end")

    def start_scan(self):
        if self.worker is not None and self.worker.is_alive(): return
        enabled = [var.get() for var in self.module_vars]
        self.counters = {"ALERT": 0, "WARN": 0}
        self.stop_event.clear()
        engine = ScanEngine(self.emit, self.stop_event, enabled)
        self.worker = threading.Thread(target=engine.run, daemon=True)
        self.btn_start.set_enabled(False)
        self.btn_stop.set_enabled(True)
        self.worker.start()

    def stop_scan(self):
        if self.worker: self.stop_event.set()

    def _on_scan_finished(self, summary):
        self.btn_start.set_enabled(True)
        self.btn_stop.set_enabled(False)
        self.gauge.set_score(summary["score"])
        self.lbl_verdict.configure(text=risk_verdict(summary["score"]), fg=score_color(summary["score"]))

    def clear_console(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")

    def copy_log(self): pass
    def export_report(self): pass
    def export_findings_csv(self): pass

    def _on_close(self):
        self._closing = True
        self.root.destroy()

def main():
    root = tk.Tk()
    NovaPrivacyGuardApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
