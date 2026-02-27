"""
Dark theme stylesheet and colour palette for NexaFlow GUI.
"""

from __future__ import annotations

# ── Colour palette ──────────────────────────────────────────────────────
COLORS = {
    "bg_primary": "#0d1117",
    "bg_secondary": "#161b22",
    "bg_tertiary": "#21262d",
    "bg_card": "#1c2128",
    "bg_input": "#0d1117",
    "border": "#30363d",
    "border_light": "#3d444d",
    "text_primary": "#e6edf3",
    "text_secondary": "#8b949e",
    "text_muted": "#6e7681",
    "accent_blue": "#58a6ff",
    "accent_green": "#3fb950",
    "accent_red": "#f85149",
    "accent_orange": "#d29922",
    "accent_purple": "#bc8cff",
    "accent_cyan": "#39d2c0",
    "accent_teal": "#2ea88a",
    "hover": "#292e36",
    "pressed": "#1a1f27",
    "selection": "#1f3a5f",
    "shadow": "rgba(0, 0, 0, 0.4)",
}

# ── Fonts ───────────────────────────────────────────────────────────────
FONT_FAMILY = '"SF Pro Display", "Segoe UI", "Helvetica Neue", Arial, sans-serif'
MONO_FONT = '"SF Mono", "Fira Code", "Cascadia Code", Menlo, Consolas, monospace'


def build_stylesheet() -> str:
    """Return the full application QSS stylesheet."""
    c = COLORS
    return f"""
    /* ── Global ───────────────────────── */
    QMainWindow, QDialog {{
        background-color: {c["bg_primary"]};
        color: {c["text_primary"]};
        font-family: {FONT_FAMILY};
        font-size: 13px;
    }}
    QWidget {{
        color: {c["text_primary"]};
        font-family: {FONT_FAMILY};
    }}

    /* ── Tab Widget ───────────────────── */
    QTabWidget::pane {{
        border: 1px solid {c["border"]};
        border-radius: 8px;
        background: {c["bg_secondary"]};
        margin-top: -1px;
    }}
    QTabBar {{
        background: transparent;
    }}
    QTabBar::tab {{
        background: {c["bg_tertiary"]};
        color: {c["text_secondary"]};
        border: 1px solid {c["border"]};
        border-bottom: none;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        padding: 10px 24px;
        margin-right: 2px;
        font-weight: 500;
        font-size: 13px;
    }}
    QTabBar::tab:selected {{
        background: {c["bg_secondary"]};
        color: {c["accent_cyan"]};
        border-bottom: 2px solid {c["accent_cyan"]};
    }}
    QTabBar::tab:hover:!selected {{
        background: {c["hover"]};
        color: {c["text_primary"]};
    }}

    /* ── Group Box (Cards) ────────────── */
    QGroupBox {{
        background: {c["bg_card"]};
        border: 1px solid {c["border"]};
        border-radius: 10px;
        margin-top: 16px;
        padding: 28px 16px 16px 16px;
        font-weight: 600;
        font-size: 14px;
        color: {c["text_primary"]};
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 4px 12px;
        color: {c["accent_cyan"]};
        font-size: 13px;
        font-weight: 700;
        letter-spacing: 0.5px;
    }}

    /* ── Labels ───────────────────────── */
    QLabel {{
        color: {c["text_primary"]};
        font-size: 13px;
    }}
    QLabel[class="heading"] {{
        font-size: 18px;
        font-weight: 700;
        color: {c["text_primary"]};
    }}
    QLabel[class="subheading"] {{
        font-size: 13px;
        color: {c["text_secondary"]};
    }}
    QLabel[class="mono"] {{
        font-family: {MONO_FONT};
        font-size: 12px;
        color: {c["accent_blue"]};
    }}
    QLabel[class="stat-value"] {{
        font-size: 22px;
        font-weight: 700;
        color: {c["accent_cyan"]};
    }}
    QLabel[class="stat-label"] {{
        font-size: 11px;
        color: {c["text_muted"]};
        text-transform: uppercase;
        letter-spacing: 1px;
    }}

    /* ── Inputs ───────────────────────── */
    QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {{
        background: {c["bg_input"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 8px 12px;
        min-height: 28px;
        color: {c["text_primary"]};
        font-size: 13px;
        font-family: {MONO_FONT};
        selection-background-color: {c["selection"]};
    }}
    QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {{
        border-color: {c["accent_cyan"]};
    }}
    QLineEdit:disabled {{
        background: {c["bg_tertiary"]};
        color: {c["text_muted"]};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 30px;
    }}
    QComboBox::down-arrow {{
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 6px solid {c["text_secondary"]};
        margin-right: 8px;
    }}
    QComboBox QAbstractItemView {{
        background: {c["bg_card"]};
        border: 1px solid {c["border"]};
        selection-background-color: {c["selection"]};
        color: {c["text_primary"]};
    }}

    /* ── Buttons ──────────────────────── */
    QPushButton {{
        background: {c["bg_tertiary"]};
        color: {c["text_primary"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 8px 20px;
        font-weight: 600;
        font-size: 13px;
    }}
    QPushButton:hover {{
        background: {c["hover"]};
        border-color: {c["border_light"]};
    }}
    QPushButton:pressed {{
        background: {c["pressed"]};
    }}
    QPushButton:disabled {{
        background: {c["bg_tertiary"]};
        color: {c["text_muted"]};
        border-color: {c["border"]};
    }}
    QPushButton[class="primary"] {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
            stop:0 {c["accent_cyan"]}, stop:1 {c["accent_teal"]});
        color: {c["bg_primary"]};
        border: none;
        font-weight: 700;
    }}
    QPushButton[class="primary"]:hover {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
            stop:0 #4de0d0, stop:1 #35c49e);
    }}
    QPushButton[class="danger"] {{
        background: {c["accent_red"]};
        color: white;
        border: none;
        font-weight: 700;
    }}
    QPushButton[class="danger"]:hover {{
        background: #e5443d;
    }}
    QPushButton[class="success"] {{
        background: {c["accent_green"]};
        color: {c["bg_primary"]};
        border: none;
        font-weight: 700;
    }}

    /* ── Tables ───────────────────────── */
    QTableWidget, QTableView {{
        background: {c["bg_card"]};
        alternate-background-color: {c["bg_tertiary"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
        gridline-color: {c["border"]};
        color: {c["text_primary"]};
        font-size: 12px;
        selection-background-color: {c["selection"]};
    }}
    QHeaderView::section {{
        background: {c["bg_tertiary"]};
        color: {c["text_secondary"]};
        border: none;
        border-bottom: 2px solid {c["border"]};
        padding: 8px 12px;
        font-weight: 600;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    QTableWidget::item {{
        padding: 6px 12px;
        border-bottom: 1px solid {c["border"]};
    }}

    /* ── Scrollbar ────────────────────── */
    QScrollBar:vertical {{
        background: {c["bg_secondary"]};
        width: 8px;
        border-radius: 4px;
    }}
    QScrollBar::handle:vertical {{
        background: {c["border_light"]};
        border-radius: 4px;
        min-height: 30px;
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    QScrollBar:horizontal {{
        background: {c["bg_secondary"]};
        height: 8px;
        border-radius: 4px;
    }}
    QScrollBar::handle:horizontal {{
        background: {c["border_light"]};
        border-radius: 4px;
        min-width: 30px;
    }}

    /* ── Text Browser / Log ───────────── */
    QTextBrowser, QTextEdit, QPlainTextEdit {{
        background: {c["bg_input"]};
        color: {c["text_primary"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 8px;
        font-family: {MONO_FONT};
        font-size: 12px;
        selection-background-color: {c["selection"]};
    }}

    /* ── Progress Bar ─────────────────── */
    QProgressBar {{
        background: {c["bg_tertiary"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        text-align: center;
        color: {c["text_primary"]};
        height: 20px;
        font-size: 11px;
    }}
    QProgressBar::chunk {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
            stop:0 {c["accent_cyan"]}, stop:1 {c["accent_teal"]});
        border-radius: 5px;
    }}

    /* ── Splitter ─────────────────────── */
    QSplitter::handle {{
        background: {c["border"]};
    }}
    QSplitter::handle:horizontal {{
        width: 1px;
    }}
    QSplitter::handle:vertical {{
        height: 1px;
    }}

    /* ── Status Bar ───────────────────── */
    QStatusBar {{
        background: {c["bg_tertiary"]};
        color: {c["text_secondary"]};
        border-top: 1px solid {c["border"]};
        font-size: 12px;
        padding: 4px 12px;
    }}

    /* ── Tooltips ─────────────────────── */
    QToolTip {{
        background: {c["bg_card"]};
        color: {c["text_primary"]};
        border: 1px solid {c["border"]};
        border-radius: 4px;
        padding: 6px 10px;
        font-size: 12px;
    }}

    /* ── Menu ─────────────────────────── */
    QMenuBar {{
        background: {c["bg_tertiary"]};
        color: {c["text_primary"]};
        border-bottom: 1px solid {c["border"]};
    }}
    QMenuBar::item:selected {{
        background: {c["hover"]};
    }}
    QMenu {{
        background: {c["bg_card"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 4px;
    }}
    QMenu::item {{
        padding: 8px 30px 8px 20px;
        border-radius: 4px;
    }}
    QMenu::item:selected {{
        background: {c["selection"]};
    }}
    """
