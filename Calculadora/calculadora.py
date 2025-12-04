from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox

class Calculadora(QWidget):
    def __init__(self):
        super().__init__()

        # Título de la ventana
        self.setWindowTitle("Calculadora de conversiones - Martín Leónel")

        # Etiquetas
        self.label_bin = QLabel("Número Binario:")
        self.label_hex = QLabel("Número Hexadecimal:")

        # Entradas
        self.input_bin = QLineEdit()
        self.input_hex = QLineEdit()

        # Botones
        self.btn_bin_to_hex = QPushButton("Binario → Hexadecimal")
        self.btn_hex_to_bin = QPushButton("Hexadecimal → Binario")

        # Conectar botones a funciones
        self.btn_bin_to_hex.clicked.connect(self.convert_bin_to_hex)
        self.btn_hex_to_bin.clicked.connect(self.convert_hex_to_bin)

        # Layouts
        v_layout = QVBoxLayout()
        h_bin = QHBoxLayout()
        h_hex = QHBoxLayout()
        h_buttons = QHBoxLayout()

        h_bin.addWidget(self.label_bin)
        h_bin.addWidget(self.input_bin)

        h_hex.addWidget(self.label_hex)
        h_hex.addWidget(self.input_hex)

        h_buttons.addWidget(self.btn_bin_to_hex)
        h_buttons.addWidget(self.btn_hex_to_bin)

        v_layout.addLayout(h_bin)
        v_layout.addLayout(h_hex)
        v_layout.addLayout(h_buttons)

        self.setLayout(v_layout)

    def convert_bin_to_hex(self):
        binario = self.input_bin.text()
        try:
            decimal = int(binario, 2)
            hexa = hex(decimal)[2:].upper()
            self.input_hex.setText(hexa)
        except ValueError:
            QMessageBox.warning(self, "Error", "Número binario inválido")

    def convert_hex_to_bin(self):
        hexa = self.input_hex.text()
        try:
            decimal = int(hexa, 16)
            binario = bin(decimal)[2:]
            self.input_bin.setText(binario)
        except ValueError:
            QMessageBox.warning(self, "Error", "Número hexadecimal inválido")


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    calc = Calculadora()
    calc.show()
    sys.exit(app.exec())
