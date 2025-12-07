"""Simple PyQt5 front-end for the sa015bcr key derivation."""
from __future__ import annotations

import sys
from typing import Callable

from PyQt5 import QtCore, QtGui, QtWidgets

from keylib import derive_key_from_algo


def normalize_seed(text: str) -> bytes:
    """Strip separators and turn the GUI seed field into raw bytes."""
    filtered = ''.join(ch for ch in text if ch not in ' ,:_')
    if len(filtered) != 10:
        raise ValueError("Seed must be exactly 5 bytes (10 hex digits)")
    try:
        return bytes.fromhex(filtered)
    except ValueError as exc:
        raise ValueError("Seed contains invalid hex digits") from exc


def parse_algo(text: str) -> int:
    """Accept decimal or hex algorithm input and return an int."""
    text = text.strip()
    if not text:
        raise ValueError("Algorithm cannot be empty")
    try:
        value = int(text, 0)
    except ValueError as exc:
        raise ValueError("Algorithm must be an integer (decimal or 0x hex)") from exc
    if not 0 <= value <= 0xFFFF:
        raise ValueError("Algorithm must fit in 16 bits")
    return value


class KeyWidget(QtWidgets.QWidget):
    """Main application widget that wires the form to keylib."""
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("FW ForgePoint 5 Byte Key Calculator")
        self.setMinimumWidth(360)

        self.seed_input = QtWidgets.QLineEdit()
        self.seed_input.setPlaceholderText("8CE7D1FD06")
        self.seed_input.setMaxLength(20)

        self.algo_input = QtWidgets.QLineEdit("0x87")
        self.algo_input.setMaxLength(6)

        self.derive_button = QtWidgets.QPushButton("Get Key")
        self.derive_button.clicked.connect(self.handle_derive)

        self.output_field = QtWidgets.QLineEdit()
        self.output_field.setReadOnly(True)
        self.output_field.setPlaceholderText("Key will appear here")
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
        self.output_field.setFont(font)

        self.iterations_label = QtWidgets.QLabel(" ")
        self.status_label = QtWidgets.QLabel()
        self.status_label.setWordWrap(True)

        form = QtWidgets.QFormLayout()
        form.addRow("Seed (hex)", self.seed_input)
        form.addRow("Algorithm", self.algo_input)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.derive_button)
        layout.addWidget(QtWidgets.QLabel("Calculated 5 byte Key:"))
        layout.addWidget(self.output_field)
        layout.addWidget(self.iterations_label)
        layout.addWidget(self.status_label)
        layout.addStretch(1)

    def show_error(self, message: str) -> None:
        """Display an error message and clear the output field."""
        self.status_label.setStyleSheet("color: red;")
        self.status_label.setText(message)
        self.output_field.clear()

    def show_success(self, message: str) -> None:
        """Display a success message without touching the key field."""
        self.status_label.setStyleSheet("color: #007700;")
        self.status_label.setText(message)

    @QtCore.pyqtSlot()
    def handle_derive(self) -> None:
        """Validate inputs, run the derivation, and render the key."""
        try:
            seed = normalize_seed(self.seed_input.text())
            algo = parse_algo(self.algo_input.text())
        except ValueError as exc:
            self.show_error(str(exc))
            return

        try:
            mac, iterations, _ = derive_key_from_algo(algo, seed)
        except ValueError as exc:
            self.show_error(str(exc))
            return

        self.output_field.setText(mac.hex())
        self.show_success("Key calculated successfully")


def main() -> int:
    """Spin up the Qt event loop and show the widget."""
    app = QtWidgets.QApplication(sys.argv)
    widget = KeyWidget()
    widget.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
