import sys
import webbrowser

from PySide2.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QGroupBox, QLineEdit, QPlainTextEdit, \
    QHBoxLayout, QComboBox, QPushButton, QFileDialog, QDialog, QMessageBox, QFormLayout

VERSION_MAJOR = 0
VERSION_MINOR = 1
VERSION_BUILD = 0

VERSION = f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_BUILD}"

EXPECTED_STR = "Expected"
OBTAINED_STR = "Obtained"
RESULTS_LST = [EXPECTED_STR, OBTAINED_STR]

SEVERITY_STR = "Severity"
REPRODUCIBILITY_STR = "Reproducibility"
IMPACT_LST = [SEVERITY_STR, REPRODUCIBILITY_STR]

IMPACT_LOW_STR = "Low"
IMPACT_MED_STR = "Medium"
IMPACT_HIGH_STR = "High"
IMPACT_ITEMS = [IMPACT_LOW_STR, IMPACT_MED_STR, IMPACT_HIGH_STR]

PRIORITY_NONE_STR = "None"
PRIORITY_URGENT_STR = "Urgent"
PRIORITY_ITEMS = [PRIORITY_NONE_STR] + IMPACT_ITEMS + [PRIORITY_URGENT_STR]


class Window(QMainWindow):
    def __init__(self, parent=None):
        super(Window, self).__init__(parent)
        self.setWindowTitle(f"Bug report - v. {VERSION}")
        self.central_widget = QWidget()
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        self.setCentralWidget(self.central_widget)
        version_box = QGroupBox("Version")
        version_layout = QVBoxLayout()
        version_box.setLayout(version_layout)
        self.version = QLineEdit()
        version_layout.addWidget(self.version)
        self.layout.addWidget(version_box)

        env_box = QGroupBox("Environment")
        env_layout = QVBoxLayout()
        env_box.setLayout(env_layout)
        self.environment = QLineEdit()
        env_layout.addWidget(self.environment)
        self.layout.addWidget(env_box)

        desc_box = QGroupBox("Description")
        desc_layout = QVBoxLayout()
        desc_box.setLayout(desc_layout)
        self.description = QPlainTextEdit()
        desc_layout.addWidget(self.description)
        self.layout.addWidget(desc_box)

        res_box = QGroupBox("Results")
        res_layout = QHBoxLayout()
        self.results = dict()
        for res in RESULTS_LST:
            box = QGroupBox(res)
            lay = QVBoxLayout()
            box.setLayout(lay)
            self.results[res] = QPlainTextEdit()
            lay.addWidget(self.results[res])
            res_layout.addWidget(box)
        res_box.setLayout(res_layout)
        self.layout.addWidget(res_box)

        proto_box = QGroupBox("Protocol")
        proto_layout = QVBoxLayout()
        self.protocol = QPlainTextEdit()
        proto_layout.addWidget(self.protocol)
        proto_box.setLayout(proto_layout)
        self.layout.addWidget(proto_box)

        stack_box = QGroupBox("Stacktrace (if any)")
        stack_layout = QVBoxLayout()
        self.stacktrace = QPlainTextEdit()
        stack_layout.addWidget(self.stacktrace)
        stack_box.setLayout(stack_layout)
        self.layout.addWidget(stack_box)

        impact_box = QGroupBox("Impact")
        impact_layout = QHBoxLayout()
        self.impact = dict()
        for imp in IMPACT_LST:
            box = QGroupBox(imp)
            lay = QVBoxLayout()
            box.setLayout(lay)
            self.impact[imp] = QComboBox()
            self.impact[imp].addItems(IMPACT_ITEMS)
            self.impact[imp].currentTextChanged.connect(lambda: self.set_priority())
            lay.addWidget(self.impact[imp])
            impact_layout.addWidget(box)
        impact_box.setLayout(impact_layout)
        self.layout.addWidget(impact_box)

        prio_box = QGroupBox("Priority")
        prio_layout = QVBoxLayout()
        self.priority = QComboBox()
        self.priority.addItems(PRIORITY_ITEMS)
        prio_layout.addWidget(self.priority)
        prio_box.setLayout(prio_layout)
        self.layout.addWidget(prio_box)

        file_box = QGroupBox("Attachments")
        file_layout = QHBoxLayout()
        self.attachment = QLineEdit()
        file_layout.addWidget(self.attachment)
        file_button = QPushButton("...")
        file_button.clicked.connect(lambda: self.browse_file())
        file_layout.addWidget(file_button)
        file_box.setLayout(file_layout)
        self.layout.addWidget(file_box)

        generate_box = QGroupBox("Generate")
        generate_layout = QHBoxLayout()
        gen_report_button = QPushButton("Generate Report")
        gen_report_button.clicked.connect(self.save_report)
        generate_layout.addWidget(gen_report_button)
        gen_email_button = QPushButton("Generate email")
        gen_email_button.clicked.connect(self.enter_address)
        generate_layout.addWidget(gen_email_button)
        generate_box.setLayout(generate_layout)
        self.layout.addWidget(generate_box)

    def set_priority(self):
        sever = self.impact[SEVERITY_STR].currentText()
        repro = self.impact[REPRODUCIBILITY_STR].currentText()
        if sever == repro == IMPACT_LOW_STR:
            self.priority.setCurrentText(PRIORITY_NONE_STR)
        elif sever in [IMPACT_LOW_STR, IMPACT_MED_STR] and repro in [IMPACT_LOW_STR, IMPACT_MED_STR] and \
                not repro == sever:
            self.priority.setCurrentText(IMPACT_LOW_STR)
        elif (sever == IMPACT_LOW_STR and repro == IMPACT_HIGH_STR) or \
                (sever == IMPACT_HIGH_STR and repro == IMPACT_LOW_STR) or \
                (sever == IMPACT_MED_STR and repro == IMPACT_MED_STR):
            self.priority.setCurrentText(IMPACT_MED_STR)
        elif sever in [IMPACT_HIGH_STR, IMPACT_MED_STR] and repro in [IMPACT_HIGH_STR, IMPACT_MED_STR] and \
                not repro == sever:
            self.priority.setCurrentText(IMPACT_HIGH_STR)
        elif repro == sever == IMPACT_HIGH_STR:
            self.priority.setCurrentText(PRIORITY_URGENT_STR)

    def browse_file(self):
        path = QFileDialog(self, "Add file", "~", "*")
        if path.exec_() == QDialog.Accepted:
            self.attachment.setText(path.selectedFiles()[0])

    def save_report(self):
        path = QFileDialog(self, "Save Report", "", "*.log")
        if path.exec_() == QDialog.Accepted:
            with open(path.selectedFiles()[0], "w") as report:
                report.write("Bug report\n\n")
                report.write(f"1. Version: {self.version.text()}\n")
                report.write(f"2. Environment: {self.environment.text()}\n")
                report.write(f"3. What's going on?:\n{self.description.toPlainText()}\n")
                report.write(f"4.a Results Expected:\n{self.results[EXPECTED_STR].toPlainText()}\n")
                report.write(f"4.b Results Obtained:\n{self.results[OBTAINED_STR].toPlainText()}\n")
                report.write(f"5. Protocol:\n{self.protocol.toPlainText()}\n")
                report.write(f"6. Stacktrace:\n{self.stacktrace.toPlainText()}\n")
                report.write(f"7. Impact:\n\tSeverity: {self.impact[SEVERITY_STR].currentText()}"
                             f"\n\tReproducibility: {self.impact[REPRODUCIBILITY_STR].currentText()}\n")
                report.write(f"8. Priority: {self.priority.currentText()}\n")
            validation_box = QMessageBox()
            validation_box.setWindowTitle("Success")
            validation_box.setText(f"Save successful at {path.selectedFiles()[0]}\nDon't forget the attachment.")
            validation_box.setIcon(QMessageBox.Information)
            validation_box.setStandardButtons(QMessageBox.Ok)
            validation_box.exec_()

    def enter_address(self):
        address_dialog = QDialog(self)
        address_dialog.setWindowTitle("Email to...")
        form_layout = QFormLayout()
        email_line_edit = QLineEdit("guillaume.gautier@altran.com")
        form_layout.addRow("Email:", email_line_edit)
        accept_button = QPushButton("Send")
        accept_button.clicked.connect(lambda: self.send_email(email_line_edit.text()))
        accept_button.clicked.connect(address_dialog.close)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(address_dialog.close)
        form_layout.addRow(accept_button, cancel_button)
        address_dialog.setLayout(form_layout)
        address_dialog.exec_()

    def send_email(self, address):
        subject = f"Bug report - V. {self.version.text()}".replace(" ", "%20")
        body = f"Bug report\n\n" \
               f"Version: {self.version.text()}\n" \
               f"Environment: {self.environment.text()}\n" \
               f"What's going on:\n{self.description.toPlainText()}\n" \
               f"Results Expected:\n{self.results[EXPECTED_STR].toPlainText()}\n" \
               f"Results Obtained:\n{self.results[OBTAINED_STR].toPlainText()}\n" \
               f"Protocol:\n{self.protocol.toPlainText()}\n" \
               f"Stacktrace:\n{self.stacktrace.toPlainText()}" \
               f"Impact:\nSeverity: {self.impact[SEVERITY_STR].currentText()}\n" \
               f"Reproducibility: {self.impact[REPRODUCIBILITY_STR].currentText()}\n" \
               f"Priority: {self.priority.currentText()}\n" \
               f"Additional files: attached".replace('\n', '%0d%0a').replace('?', '..')
        print(body)
        webbrowser.open(f"mailto:{address}&subject={subject}&body={body}")


if __name__ == '__main__':
    app = QApplication()
    win = Window()
    win.show()
    sys.exit(app.exec_())
