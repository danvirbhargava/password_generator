
import sys
import secrets
import string
import math
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QProgressBar, QCheckBox, QSlider, QFrame)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QClipboard, QAction

# -----------------------------------------------------------------------------
# Business Logic (Model)
# -----------------------------------------------------------------------------

class PasswordGenerator:
    """Handles the logic of password generation and strength estimation."""

    @staticmethod
    def generate(length: int, use_upper: bool, use_lower: bool, use_numbers: bool, use_symbols: bool) -> str:
        """Generates a cryptographically secure random password."""
        if not any([use_upper, use_lower, use_numbers, use_symbols]):
            return ""

        alphabet = ""
        if use_upper:
            alphabet += string.ascii_uppercase
        if use_lower:
            alphabet += string.ascii_lowercase
        if use_numbers:
            alphabet += string.digits
        if use_symbols:
            alphabet += string.punctuation

        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def calculate_strength(password: str) -> tuple[int, str]:
        """Calculates strength score (0-4) and label."""
        if not password:
            return 0, "Too Short"

        pool_size = 0
        if any(c.isupper() for c in password): pool_size += 26
        if any(c.islower() for c in password): pool_size += 26
        if any(c.isdigit() for c in password): pool_size += 10
        if any(c in string.punctuation for c in password): pool_size += 32
        
        if pool_size == 0:
            return 0, "Weak"

        entropy = len(password) * math.log2(pool_size)

        if entropy < 28: return 0, "Weak"
        elif entropy < 36: return 1, "Fair"
        elif entropy < 60: return 2, "Good"
        elif entropy < 128: return 3, "Strong"
        else: return 4, "Very Strong"


# -----------------------------------------------------------------------------
# User Interface (View & Controller)
# -----------------------------------------------------------------------------

class PasswordGeneratorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Password Generator")
        self.setFixedSize(450, 600)
        
        # Determine if we are in dark mode (heuristic) or just force a clean light theme
        # For simplicity and reliability, we'll implement a clean custom stylesheet
        self._apply_styles()

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.setSpacing(20)
        self.layout.setContentsMargins(30, 30, 30, 30)

        self._build_ui()
        self.generate_password() # Initial generation

    def _apply_styles(self):
        # Dark Mode Theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
            }
            QLabel {
                font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
                color: #ffffff;
            }
            QLineEdit {
                background-color: #3b3b3b;
                border: 1px solid #555555;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Courier New';
                font-size: 18px;
                color: #ffffff;
            }
            QPushButton {
                background-color: #0a84ff;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #007aff;
            }
            QPushButton:pressed {
                background-color: #0062cc;
            }
            QPushButton#copyButton {
                background-color: #4a4a4a;
                color: #64d2ff;
            }
            QPushButton#copyButton:hover {
                background-color: #555555;
            }
            QGroupBox {
                border: none;
            }
            QCheckBox {
                color: #ffffff;
                spacing: 8px;
                font-size: 14px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid #888;
                background: #3b3b3b;
            }
            QCheckBox::indicator:checked {
                background-color: #0a84ff;
                border-color: #0a84ff;
                image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSIzIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwb2x5bGluZSBwb2ludHM9IjIwIDYgOSAxNyA0IDEyIi8+PC9zdmc+);
            }
            QProgressBar {
                border: none;
                background-color: #4a4a4a;
                border-radius: 4px;
                height: 8px;
                text-align: center;
            }
            QProgressBar::chunk {
                border-radius: 4px;
            }
            QSlider::groove:horizontal {
                border: 1px solid #555555;
                height: 4px;
                background: #4a4a4a;
                margin: 2px 0;
                border-radius: 2px;
            }
            QSlider::handle:horizontal {
                background: #d0d0d0;
                border: 1px solid #555555;
                width: 18px;
                height: 18px;
                margin: -8px 0;
                border-radius: 9px;
            }
        """)

    def _build_ui(self):
        # Header
        header_label = QLabel("Password Generator")
        header_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #1d1d1f;")
        self.layout.addWidget(header_label, alignment=Qt.AlignmentFlag.AlignCenter)
        self.layout.addSpacing(10)

        # Password Display
        display_layout = QHBoxLayout()
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        display_layout.addWidget(self.password_display)

        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setObjectName("copyButton")
        self.copy_btn.setFixedWidth(80)
        self.copy_btn.clicked.connect(self.copy_to_clipboard)
        display_layout.addWidget(self.copy_btn)
        
        self.layout.addLayout(display_layout)

        # Strength Meter
        self.strength_bar = QProgressBar()
        self.strength_bar.setTextVisible(False)
        self.layout.addWidget(self.strength_bar)

        self.strength_label = QLabel("Strength: Weak")
        self.strength_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.strength_label.setStyleSheet("font-size: 12px; font-weight: bold; color: #8e8e93;")
        self.layout.addWidget(self.strength_label)
        
        self.layout.addSpacing(10)

        # Length Slider
        length_layout = QHBoxLayout()
        length_label = QLabel("Length:")
        self.length_value_label = QLabel("16")
        self.length_value_label.setStyleSheet("font-weight: bold;")
        
        length_layout.addWidget(length_label)
        length_layout.addStretch()
        length_layout.addWidget(self.length_value_label)
        self.layout.addLayout(length_layout)

        self.length_slider = QSlider(Qt.Orientation.Horizontal)
        self.length_slider.setMinimum(6)
        self.length_slider.setMaximum(64)
        self.length_slider.setValue(16)
        self.length_slider.valueChanged.connect(self.update_length_label)
        self.length_slider.valueChanged.connect(self.generate_password)
        self.layout.addWidget(self.length_slider)

        self.layout.addSpacing(10)

        # Options
        options_layout = QVBoxLayout()
        self.chk_upper = QCheckBox("Uppercase (A-Z)")
        self.chk_upper.setChecked(True)
        self.chk_upper.stateChanged.connect(self.generate_password)
        
        self.chk_lower = QCheckBox("Lowercase (a-z)")
        self.chk_lower.setChecked(True)
        self.chk_lower.stateChanged.connect(self.generate_password)
        
        self.chk_numbers = QCheckBox("Numbers (0-9)")
        self.chk_numbers.setChecked(True)
        self.chk_numbers.stateChanged.connect(self.generate_password)
        
        self.chk_symbols = QCheckBox("Symbols (!@#$)")
        self.chk_symbols.setChecked(True)
        self.chk_symbols.stateChanged.connect(self.generate_password)

        # Grid-like arrangement for check boxes
        row1 = QHBoxLayout()
        row1.addWidget(self.chk_upper)
        row1.addWidget(self.chk_lower)
        options_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(self.chk_numbers)
        row2.addWidget(self.chk_symbols)
        options_layout.addLayout(row2)

        self.layout.addLayout(options_layout)
        self.layout.addStretch()

        # Generate Button
        generate_btn = QPushButton("Generate New Password")
        generate_btn.setMinimumHeight(50)
        generate_btn.setStyleSheet("font-size: 16px;")
        generate_btn.clicked.connect(self.generate_password)
        self.layout.addWidget(generate_btn)

    def update_length_label(self, value):
        self.length_value_label.setText(str(value))

    def generate_password(self):
        length = self.length_slider.value()
        use_upper = self.chk_upper.isChecked()
        use_lower = self.chk_lower.isChecked()
        use_numbers = self.chk_numbers.isChecked()
        use_symbols = self.chk_symbols.isChecked()

        # Prevent unchecking all
        if not any([use_upper, use_lower, use_numbers, use_symbols]):
            self.chk_lower.setChecked(True)
            use_lower = True

        pwd = PasswordGenerator.generate(length, use_upper, use_lower, use_numbers, use_symbols)
        self.password_display.setText(pwd)
        self._update_strength_meter(pwd)

    def _update_strength_meter(self, password):
        score, label = PasswordGenerator.calculate_strength(password)
        
        # Color & Value
        colors = {
            0: "#ff3b30", # Red
            1: "#ff9500", # Orange
            2: "#ffcc00", # Yellow
            3: "#34c759", # Green
            4: "#30b0c7"  # Teal/Blue-Green
        }
        color = colors.get(score, "#e5e5ea")
        
        # Animate value slightly? No, just set it.
        # Map 0-4 to 20, 40, 60, 80, 100
        val = (score + 1) * 20
        
        self.strength_bar.setValue(val)
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                background-color: #e5e5ea;
                border-radius: 4px;
                height: 8px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 4px;
            }}
        """)
        
        self.strength_label.setText(f"Strength: {label}")
        self.strength_label.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {color};")

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.password_display.text())
        
        # Flash effect
        original_style = self.password_display.styleSheet()
        self.password_display.setStyleSheet("""
            QLineEdit {
                background-color: #d1f7c4; 
                border: 1px solid #34c759;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Courier New';
                font-size: 18px;
                color: #1d1d1f;
            }
        """)
        QTimer.singleShot(200, lambda: self._reset_display_style())

    def _reset_display_style(self):
        # Revert to default style defined in _apply_styles via global stylesheet 
        # or specific widget override. Since we used gloabl CSS for QLineEdit, 
        # setting empty string here might reverting to parent/app style? 
        # Actually explicit setStyleSheet overrides app style. verify.
        # It's safer to re-apply the specific desired style or just clear if it falls back correctly.
        # Let's just re-apply the input style from _apply_styles
        self.password_display.setStyleSheet("""
            QLineEdit {
                background-color: #ffffff;
                border: 1px solid #d1d1d6;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Courier New';
                font-size: 18px;
                color: #1d1d1f;
            }
        """)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordGeneratorApp()
    window.show()
    sys.exit(app.exec())
