"""
Reusable widget helpers for NexaFlow GUI panels.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


def make_stat_card(label: str, initial: str = "—") -> tuple[QWidget, QLabel]:
    """
    Return (card_widget, value_label) for a dashboard stat.
    """
    card = QFrame()
    card.setObjectName("statCard")
    card.setStyleSheet("""
        QFrame#statCard {
            background: #1c2128;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 16px;
        }
    """)
    lay = QVBoxLayout(card)
    lay.setSpacing(4)
    lay.setContentsMargins(16, 14, 16, 14)

    val = QLabel(initial)
    val.setProperty("class", "stat-value")
    val.setAlignment(Qt.AlignmentFlag.AlignLeft)
    lay.addWidget(val)

    lbl = QLabel(label.upper())
    lbl.setProperty("class", "stat-label")
    lay.addWidget(lbl)

    return card, val


def make_section_header(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setProperty("class", "heading")
    return lbl


def make_primary_button(text: str) -> QPushButton:
    btn = QPushButton(text)
    btn.setProperty("class", "primary")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setMinimumHeight(38)
    return btn


def make_danger_button(text: str) -> QPushButton:
    btn = QPushButton(text)
    btn.setProperty("class", "danger")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setMinimumHeight(38)
    return btn


def make_success_button(text: str) -> QPushButton:
    btn = QPushButton(text)
    btn.setProperty("class", "success")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setMinimumHeight(38)
    return btn


def h_line() -> QFrame:
    """Horizontal separator."""
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet("color: #30363d;")
    return line


def truncate_addr(addr: str, n: int = 8) -> str:
    if len(addr) <= n * 2 + 1:
        return addr
    return f"{addr[:n]}…{addr[-n:]}"
