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


class NovaPrivacyGuardApp:
    """
    Ventana principal (UI 3.1 'Obsidian').
    Solo el hilo principal toca los widgets: el motor deja eventos en una cola
    protegida por un Lock y aqui se consumen con root.after().
    """

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
    NovaPrivacyGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
