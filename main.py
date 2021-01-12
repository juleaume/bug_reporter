import sys
import webbrowser

from PySide2.QtCore import Qt
from PySide2.QtGui import QMouseEvent, QCloseEvent
from PySide2.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QGroupBox, QLineEdit, QPlainTextEdit, \
    QHBoxLayout, QComboBox, QPushButton, QFileDialog, QDialog, QMessageBox, QFormLayout, QMenu, QScrollArea

python_requirements = (3, 6)
if sys.version_info < python_requirements:
    print("You must run Python {}.{} or above".format(python_requirements[0], python_requirements[1]))
    sys.exit(1)

VERSION_MAJOR = 0
VERSION_MINOR = 3
VERSION_BUILD = 4

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
    dark_mode = False
    high_contrast = False

    def __init__(self, parent=None):
        super(Window, self).__init__(parent)
        self.setGeometry(0, 0, 600, 800)
        self.setWindowTitle(f"Bug report - v. {VERSION}")
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.central_layout = QVBoxLayout()
        self.central_widget.setLayout(self.central_layout)
        self.scroll_area = QScrollArea(widgetResizable=True)
        self.central_layout.addWidget(self.scroll_area)
        self.scroll_widget = QWidget()
        self.scroll_area.setWidget(self.scroll_widget)

        self.layout = QVBoxLayout()
        self.scroll_widget.setLayout(self.layout)

        env_ver_layout = QHBoxLayout()
        version_box = QGroupBox("Version")
        version_layout = QVBoxLayout()
        version_box.setLayout(version_layout)
        self.version = QLineEdit()
        version_layout.addWidget(self.version)
        env_ver_layout.addWidget(version_box)
        version_box.setToolTip(
            f"Name the current version where the bug occurred, e.g. V.{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_BUILD}"
        )

        env_box = QGroupBox("Environment")
        env_layout = QVBoxLayout()
        env_box.setLayout(env_layout)
        self.environment = QLineEdit()
        env_layout.addWidget(self.environment)
        env_ver_layout.addWidget(env_box)
        env_box.setToolTip("Specify the environment of work, e.g. OS, hardware version, current configuration...")

        self.layout.addLayout(env_ver_layout)

        desc_box = QGroupBox("Description")
        desc_layout = QVBoxLayout()
        desc_box.setLayout(desc_layout)
        self.description = QPlainTextEdit()
        desc_layout.addWidget(self.description)
        desc_box.setToolTip("Describe your problem, what is going on?")
        self.layout.addWidget(desc_box)

        res_box = QGroupBox("Results")
        res_layout = QHBoxLayout()
        self.results = dict()
        result_help = {
            OBTAINED_STR: "What you got",
            EXPECTED_STR: "What you were supposed to get"
        }
        for res in RESULTS_LST:
            box = QGroupBox(res)
            lay = QVBoxLayout()
            box.setLayout(lay)
            box.setToolTip(result_help[res])
            self.results[res] = QPlainTextEdit()
            lay.addWidget(self.results[res])
            res_layout.addWidget(box)
        res_box.setLayout(res_layout)
        self.layout.addWidget(res_box)

        proto_box = QGroupBox("Protocol")
        proto_layout = QVBoxLayout()
        self.protocol = QPlainTextEdit("1.")
        proto_layout.addWidget(self.protocol)
        proto_box.setLayout(proto_layout)
        proto_box.setToolTip("Describe the steps to reproduce the bug")
        self.layout.addWidget(proto_box)

        stack_box = QGroupBox("Stacktrace (if any)")
        stack_layout = QVBoxLayout()
        self.stacktrace = QPlainTextEdit()
        stack_layout.addWidget(self.stacktrace)
        stack_box.setLayout(stack_layout)
        stack_box.setToolTip("If you have a Stacktrace, it is welcomed here")
        self.layout.addWidget(stack_box)

        impact_box = QGroupBox("Impact")
        impact_layout = QHBoxLayout()
        self.impact = dict()
        prio_help = {
            SEVERITY_STR: "How severe this bug is (low: a little bit annoying, high: everything is broken)",
            REPRODUCIBILITY_STR: "How often this bug occurs "
                                 "(low: almost never or in a very specific condition, high: always)"
        }
        for imp in IMPACT_LST:
            box = QGroupBox(imp)
            lay = QVBoxLayout()
            box.setLayout(lay)
            box.setToolTip(prio_help[imp])
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
        prio_box.setToolTip("Is set automatically but can be overridden if needed")
        self.layout.addWidget(prio_box)

        file_box = QGroupBox("Attachments")
        file_layout = QHBoxLayout()
        self.attachment = QLineEdit()
        file_layout.addWidget(self.attachment)
        file_button = QPushButton("...")
        file_button.clicked.connect(lambda: self.browse_file())
        file_layout.addWidget(file_button)
        file_box.setLayout(file_layout)
        file_box.setToolTip("If you need to add a file")
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
        self.central_layout.addWidget(generate_box)

    def set_priority(self):
        """
        Sets the priority given the severity and probability
        if both low => None
        if med/low => Low
        if low/high or both med => med
        if med/high => high
        if both high => urgent
        :return: None
        """
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

    def can_generate_report(self) -> bool:
        """
        check if a report can be generated
        :return: True if a report can be generated, False else
        """
        can_generate = True
        list_of_lines = [self.version, self.environment]
        for line in list_of_lines:
            can_generate &= not line.text() == ""
        list_of_plains = [self.description, self.results[EXPECTED_STR], self.results[OBTAINED_STR], self.protocol]
        for plain in list_of_plains:
            can_generate &= not plain.toPlainText() == ""
        return can_generate

    def show_missing(self):
        missing_text = ""
        list_of_lines = [self.version, self.environment]
        lists_line_names = ["Version number", "Environment"]
        for line, name in zip(list_of_lines, lists_line_names):
            if line.text() == "":
                missing_text += f"\t- {name}\n"
        list_of_plains = [self.description, self.results[EXPECTED_STR], self.results[OBTAINED_STR], self.protocol]
        lists_plain_names = ["Description", "Expected results", "Obtained results", "Protocol"]
        for plain, name in zip(list_of_plains, lists_plain_names):
            if plain.toPlainText() == "":
                missing_text += f"\t- {name}\n"
        error_box = QMessageBox(self)
        error_box.setWindowTitle("Error")
        error_box.setText(f"Cannot generate report, missing following fields:\n{missing_text}")
        error_box.setIcon(QMessageBox.Warning)
        error_box.setStandardButtons(QMessageBox.Ok)
        error_box.exec_()

    def browse_file(self):
        """
        opens a dialog file and set the attachment line entry with the text
        :return: None
        """
        path = QFileDialog(self, "Add file", "~", "*")
        if path.exec_() == QDialog.Accepted:
            self.attachment.setText(path.selectedFiles()[0])

    def save_report(self):
        """
        Saves the report as a file
        :return: None
        """
        if self.can_generate_report():
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
        else:
            self.show_missing()

    def enter_address(self):
        """
        opens a dialog to enter the dev's address
        :return:
        """
        if self.can_generate_report():
            address_dialog = QDialog(self)
            address_dialog.setWindowTitle("Email to...")
            form_layout = QFormLayout()
            email_line_edit = QLineEdit("guillaume.gautier@altran.com")
            cc_line_edit = QLineEdit()
            form_layout.addRow("Email:", email_line_edit)
            form_layout.addRow("CC:", cc_line_edit)
            accept_button = QPushButton("Send")
            accept_button.clicked.connect(lambda: self.send_email(email_line_edit.text(), cc_line_edit.text()))
            accept_button.clicked.connect(address_dialog.close)
            cancel_button = QPushButton("Cancel")
            cancel_button.clicked.connect(address_dialog.close)
            form_layout.addRow(accept_button, cancel_button)
            address_dialog.setLayout(form_layout)
            address_dialog.setFixedWidth(500)
            address_dialog.exec_()
        else:
            self.show_missing()

    def send_email(self, address, cc):
        """
        opens a web browser and automatically writes an email to the address
        :param address: the address to send the mail to
        :param cc: the copy-carbon to send to
        :return: None
        """
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
        if not cc == "":
            cc_address = f"&cc={cc}"
        else:
            cc_address = ""
        webbrowser.open(f"mailto:{address}{cc_address}&subject={subject}&body={body}")

    def _create_menu(self, event: QMouseEvent):
        context_menu = QMenu(self)
        context_menu.addAction("Toggle dark mode", self.set_dark_mode)
        context_menu.addAction("Toggle high contrast", self.set_high_contrast)
        context_menu.addAction("Generate report", self.save_report)
        context_menu.addAction("Send email to...", self.enter_address)
        if sys.platform == "win32":
            context_menu.addAction("Create shortcut", self.create_shortcut)
        context_menu.addAction("Quit Report", self.close)
        context_menu.exec_(self.mapToGlobal(event.pos()))

    def set_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self.high_contrast = False
        if self.dark_mode:
            self.setStyleSheet("background-color: #002b36; color: #b58900")
        else:
            self.setStyleSheet("")

    def set_high_contrast(self):
        self.high_contrast = not self.high_contrast
        self.dark_mode = False
        if self.high_contrast:
            self.setStyleSheet("background-color: black; color: white")
        else:
            self.setStyleSheet("")

    def create_shortcut(self):
        confirmation_box = QMessageBox(self)
        confirmation_box.setWindowTitle("Confirmation?")
        confirmation_box.setText("Are you sure you want to create a shortcut?")
        confirmation_box.setStandardButtons(QMessageBox.No | QMessageBox.Yes)
        confirmation_box.setIcon(QMessageBox.Question)
        confirmation_box.setDefaultButton(QMessageBox.No)
        if confirmation_box.exec_() == QMessageBox.Yes:
            with open("report.bat", 'w') as bat_file:
                bat_file.write(f"{sys.executable} {sys.argv[0]}")
            # TODO créer un lien du bureau vers le bat

    def exit_confirmation(self):
        """
        Create and shows a dialog box asking the user if they are sure they want to quit
        :return: None
        """
        confirmation_box = QMessageBox(self)
        confirmation_box.setWindowTitle("Quit?")
        confirmation_box.setText("Are you sure you want to quit?")
        confirmation_box.setStandardButtons(QMessageBox.No | QMessageBox.Yes)
        confirmation_box.setIcon(QMessageBox.Question)
        confirmation_box.setDefaultButton(QMessageBox.No)
        return confirmation_box.exec_() == QMessageBox.Yes

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.RightButton:
            self._create_menu(event)
            event.accept()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.exit_confirmation():
            event.accept()
        else:
            event.ignore()


if __name__ == '__main__':
    app = QApplication()
    win = Window()
    win.show()
    sys.exit(app.exec_())
