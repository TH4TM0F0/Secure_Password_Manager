"""
Qt GUI wrapper for the Secure Password Manager CLI app.

Run from the repository root with:
    python password_manager_gui.py

Requires a Qt binding, for example:
    pip install PyQt6
"""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path
from typing import Callable, Optional

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QStackedWidget,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    ALIGN_CENTER = Qt.AlignmentFlag.AlignCenter
    PASSWORD_ECHO = QLineEdit.EchoMode.Password
    HEADER_STRETCH = QHeaderView.ResizeMode.Stretch
    SELECT_ROWS = QAbstractItemView.SelectionBehavior.SelectRows
    NO_EDIT = QAbstractItemView.EditTrigger.NoEditTriggers
    MSG_YES = QMessageBox.StandardButton.Yes
    MSG_NO = QMessageBox.StandardButton.No
    app_exec = lambda app: app.exec()
except ImportError:
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QFont
    from PyQt5.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QStackedWidget,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    ALIGN_CENTER = Qt.AlignCenter
    PASSWORD_ECHO = QLineEdit.Password
    HEADER_STRETCH = QHeaderView.Stretch
    SELECT_ROWS = QAbstractItemView.SelectRows
    NO_EDIT = QAbstractItemView.NoEditTriggers
    MSG_YES = QMessageBox.Yes
    MSG_NO = QMessageBox.No
    app_exec = lambda app: app.exec_()


PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

VaultManager = None


def get_vault_manager_class():
    global VaultManager
    if VaultManager is None:
        from src.core.vault_manager import VaultManager as LoadedVaultManager

        VaultManager = LoadedVaultManager
    return VaultManager


class PasswordManagerWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.manager: Optional[VaultManager] = None

        self.setWindowTitle("Secure Password Manager")
        self.resize(1050, 680)
        self.setMinimumSize(900, 620)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_page = self._build_login_page()
        self.app_page = self._build_app_page()
        self.stack.addWidget(self.login_page)
        self.stack.addWidget(self.app_page)

        self._apply_styles()

    def _build_login_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setAlignment(ALIGN_CENTER)

        panel = QFrame()
        panel.setObjectName("loginPanel")
        panel.setFixedWidth(420)
        layout = QVBoxLayout(panel)
        layout.setSpacing(16)

        title = QLabel("Secure Password Manager")
        title.setObjectName("title")
        subtitle = QLabel("Sign in with your vault username and master password.")
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Master password")
        self.password_input.setEchoMode(PASSWORD_ECHO)
        self.password_input.returnPressed.connect(self.login)

        login_button = QPushButton("Unlock Vault")
        login_button.setObjectName("primaryButton")
        login_button.clicked.connect(self.login)

        self.login_status = QLabel("")
        self.login_status.setObjectName("errorText")
        self.login_status.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(8)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_input)
        layout.addWidget(login_button)
        layout.addWidget(self.login_status)

        outer.addWidget(panel)
        return page

    def _build_app_page(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(18, 18, 18, 18)

        top = QHBoxLayout()
        self.session_label = QLabel("")
        self.session_label.setObjectName("sessionLabel")
        lock_button = QPushButton("Lock")
        lock_button.clicked.connect(self.lock)
        top.addWidget(self.session_label)
        top.addStretch()
        top.addWidget(lock_button)

        tabs = QTabWidget()
        tabs.addTab(self._build_credentials_tab(), "Credentials")
        tabs.addTab(self._build_transfer_tab(), "Export / Import")
        tabs.addTab(self._build_status_tab(), "Vault Status")
        tabs.addTab(self._build_log_tab(), "Activity Log")

        root.addLayout(top)
        root.addWidget(tabs)
        return page

    def _build_credentials_tab(self) -> QWidget:
        tab = QWidget()
        layout = QHBoxLayout(tab)

        left = QVBoxLayout()
        self.credentials_table = QTableWidget(0, 3)
        self.credentials_table.setHorizontalHeaderLabels(["Website", "Username", "Password"])
        self.credentials_table.horizontalHeader().setSectionResizeMode(HEADER_STRETCH)
        self.credentials_table.setSelectionBehavior(SELECT_ROWS)
        self.credentials_table.setEditTriggers(NO_EDIT)
        self.credentials_table.itemSelectionChanged.connect(self.populate_selected_credential)

        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_credentials)

        left.addWidget(self.credentials_table)
        left.addWidget(refresh_button)

        right = QVBoxLayout()

        editor = QGroupBox("Credential")
        form = QFormLayout(editor)
        self.website_field = QLineEdit()
        self.credential_username_field = QLineEdit()
        self.credential_password_field = QLineEdit()
        self.credential_password_field.setEchoMode(PASSWORD_ECHO)
        form.addRow("Website", self.website_field)
        form.addRow("Username", self.credential_username_field)
        form.addRow("Password", self.credential_password_field)

        button_grid = QGridLayout()
        add_button = QPushButton("Add")
        retrieve_button = QPushButton("Retrieve")
        update_button = QPushButton("Update")
        delete_button = QPushButton("Delete")
        clear_button = QPushButton("Clear")
        add_button.clicked.connect(self.add_credential)
        retrieve_button.clicked.connect(self.retrieve_credential)
        update_button.clicked.connect(self.update_credential)
        delete_button.clicked.connect(self.delete_credential)
        clear_button.clicked.connect(self.clear_credential_form)
        button_grid.addWidget(add_button, 0, 0)
        button_grid.addWidget(retrieve_button, 0, 1)
        button_grid.addWidget(update_button, 1, 0)
        button_grid.addWidget(delete_button, 1, 1)
        button_grid.addWidget(clear_button, 2, 0, 1, 2)

        self.retrieve_output = QTextEdit()
        self.retrieve_output.setReadOnly(True)
        self.retrieve_output.setPlaceholderText("Retrieved credentials appear here.")

        right.addWidget(editor)
        right.addLayout(button_grid)
        right.addWidget(self.retrieve_output)
        right.addStretch()

        layout.addLayout(left, 2)
        layout.addLayout(right, 1)
        return tab

    def _build_transfer_tab(self) -> QWidget:
        tab = QWidget()
        layout = QHBoxLayout(tab)

        export_group = QGroupBox("Export Vault")
        export_layout = QFormLayout(export_group)
        self.recipient_field = QLineEdit()
        export_button = QPushButton("Export")
        export_button.clicked.connect(self.export_vault)
        export_layout.addRow("Recipient username", self.recipient_field)
        export_layout.addRow(export_button)

        import_group = QGroupBox("Import Vault")
        import_layout = QFormLayout(import_group)
        self.import_file_field = QLineEdit()
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_import_file)
        file_row = QHBoxLayout()
        file_row.addWidget(self.import_file_field)
        file_row.addWidget(browse_button)
        self.sender_field = QLineEdit()
        self.import_password_field = QLineEdit()
        self.import_password_field.setEchoMode(PASSWORD_ECHO)
        import_button = QPushButton("Import")
        import_button.clicked.connect(self.import_vault)
        import_layout.addRow("Export file", file_row)
        import_layout.addRow("Sender username", self.sender_field)
        import_layout.addRow("Master password", self.import_password_field)
        import_layout.addRow(import_button)

        layout.addWidget(export_group)
        layout.addWidget(import_group)
        return tab

    def _build_status_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.status_table = QTableWidget(0, 2)
        self.status_table.setHorizontalHeaderLabels(["Item", "Value"])
        self.status_table.horizontalHeader().setSectionResizeMode(HEADER_STRETCH)
        self.status_table.setEditTriggers(NO_EDIT)

        actions = QHBoxLayout()
        refresh_status_button = QPushButton("Refresh Status")
        prepare_transfer_button = QPushButton("Prepare DH Transfer Keys")
        refresh_status_button.clicked.connect(self.refresh_status)
        prepare_transfer_button.clicked.connect(self.prepare_dh_transfer)
        actions.addWidget(refresh_status_button)
        actions.addWidget(prepare_transfer_button)
        actions.addStretch()

        layout.addWidget(self.status_table)
        layout.addLayout(actions)
        return tab

    def _build_log_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        clear_log_button = QPushButton("Clear Log")
        clear_log_button.clicked.connect(self.log_output.clear)
        layout.addWidget(self.log_output)
        layout.addWidget(clear_log_button)
        return tab

    def login(self) -> None:
        username = self.username_input.text().strip()
        master_password = self.password_input.text().strip()

        if not username:
            self.login_status.setText("Username cannot be empty.")
            return
        if not master_password:
            self.login_status.setText("Master password cannot be empty.")
            return

        try:
            vault_manager_class = get_vault_manager_class()
            output, manager = self.capture_output(
                self.initialize_manager,
                vault_manager_class,
                username,
                master_password,
            )
            self.manager = manager
            self.session_label.setText(f"Signed in as {username}")
            self.login_status.clear()
            self.stack.setCurrentWidget(self.app_page)
            self.append_log(output or "Vault initialized.")
            self.refresh_credentials()
            self.refresh_status()
        except Exception as exc:
            self.login_status.setText(f"Failed to initialize vault: {exc}")

    def initialize_manager(self, vault_manager_class, username: str, master_password: str):
        manager = vault_manager_class(username, master_password)
        manager.vault.load_and_verify()
        return manager

    def lock(self) -> None:
        self.manager = None
        self.password_input.clear()
        self.import_password_field.clear()
        self.clear_credential_form()
        self.credentials_table.setRowCount(0)
        self.retrieve_output.clear()
        self.status_table.setRowCount(0)
        self.stack.setCurrentWidget(self.login_page)

    def add_credential(self) -> None:
        if not self.require_manager():
            return
        website = self.website_field.text().strip()
        username = self.credential_username_field.text().strip()
        password = self.credential_password_field.text().strip()
        if not all([website, username, password]):
            self.show_warning("All fields are required to add a credential.")
            return

        self.run_manager_action(lambda: self.manager.add(website, username, password))
        self.refresh_credentials()

    def retrieve_credential(self) -> None:
        if not self.require_manager():
            return
        website = self.website_field.text().strip()
        if not website:
            self.show_warning("Website is required.")
            return

        try:
            result = self.manager.vault.retrieve_credential(website)
            if isinstance(result, dict):
                self.credential_username_field.setText(result["username"])
                self.credential_password_field.setText(result["password"])
                message = (
                    f"Found credential for {website}:\n"
                    f"Username: {result['username']}\n"
                    f"Password: {result['password']}"
                )
            else:
                message = str(result)
            self.retrieve_output.setPlainText(message)
            self.append_log(message)
        except Exception as exc:
            self.handle_error("Retrieve failed", exc)

    def update_credential(self) -> None:
        if not self.require_manager():
            return
        website = self.website_field.text().strip()
        username = self.credential_username_field.text().strip() or None
        password = self.credential_password_field.text().strip() or None
        if not website:
            self.show_warning("Website is required.")
            return
        if username is None and password is None:
            self.show_warning("Enter a new username, a new password, or both.")
            return

        self.run_manager_action(lambda: self.manager.update(website, username, password))
        self.refresh_credentials()

    def delete_credential(self) -> None:
        if not self.require_manager():
            return
        website = self.website_field.text().strip()
        if not website:
            self.show_warning("Website is required.")
            return

        confirmed = QMessageBox.question(
            self,
            "Delete Credential",
            f"Delete the credential for {website}?",
            MSG_YES | MSG_NO,
            MSG_NO,
        )
        if confirmed != MSG_YES:
            return

        self.run_manager_action(lambda: self.manager.delete(website))
        self.clear_credential_form()
        self.refresh_credentials()

    def export_vault(self) -> None:
        if not self.require_manager():
            return
        recipient = self.recipient_field.text().strip()
        if not recipient:
            self.show_warning("Recipient username is required.")
            return

        self.run_manager_action(lambda: self.manager.export_vault(recipient))
        self.refresh_status()

    def import_vault(self) -> None:
        if not self.require_manager():
            return
        file_path = self.import_file_field.text().strip()
        sender = self.sender_field.text().strip()
        master_password = self.import_password_field.text().strip()
        if not all([file_path, sender, master_password]):
            self.show_warning("Export file, sender username, and master password are required.")
            return

        self.run_manager_action(lambda: self.manager.import_vault(file_path, sender, master_password))
        self.refresh_credentials()
        self.refresh_status()

    def prepare_dh_transfer(self) -> None:
        if not self.require_manager():
            return

        self.run_manager_action(lambda: self.manager.prepare_dh_transfer())
        self.refresh_status()

    def browse_import_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Export File",
            str(PROJECT_ROOT / "data" / "exports"),
            "JSON Files (*.json);;All Files (*)",
        )
        if file_path:
            self.import_file_field.setText(file_path)

    def refresh_credentials(self) -> None:
        if not self.require_manager(silent=True):
            return
        try:
            self.manager.vault.load_and_verify()
            credentials = getattr(self.manager.vault, "_Vault__credentials", {})
            self.credentials_table.setRowCount(0)
            for row, (website, values) in enumerate(sorted(credentials.items())):
                self.credentials_table.insertRow(row)
                self.credentials_table.setItem(row, 0, QTableWidgetItem(website))
                self.credentials_table.setItem(row, 1, QTableWidgetItem(values.get("username", "")))
                self.credentials_table.setItem(row, 2, QTableWidgetItem("********"))
        except Exception as exc:
            self.handle_error("Refresh failed", exc)

    def refresh_status(self) -> None:
        if not self.require_manager(silent=True):
            return

        data_dir = PROJECT_ROOT / "data"
        keys_dir = data_dir / "keys"
        config_dir = data_dir / "config"
        vault_dir = data_dir / "vaults"
        exports_dir = data_dir / "exports"
        username = self.manager.username
        credentials = getattr(self.manager.vault, "_Vault__credentials", {})

        rows = [
            ("Signed-in user", username),
            ("Stored credentials", str(len(credentials))),
            ("Vault file", str(vault_dir / f"{username}_vault.json")),
            ("ElGamal public key", str(keys_dir / f"{username}_public_key.json")),
            ("ElGamal private key", str(keys_dir / f"{username}_private_key.json")),
            ("DH public key", str(keys_dir / f"{username}_dh_public.json")),
            ("DH private key", str(keys_dir / f"{username}_dh_private.json")),
            ("ElGamal config", str(config_dir / "elgamal_params.json")),
            ("Diffie-Hellman config", str(config_dir / "diffie_hellman_params.json")),
            ("Exports folder", str(exports_dir)),
        ]

        self.status_table.setRowCount(0)
        for row, (label, value) in enumerate(rows):
            self.status_table.insertRow(row)
            self.status_table.setItem(row, 0, QTableWidgetItem(label))
            self.status_table.setItem(row, 1, QTableWidgetItem(value))

    def populate_selected_credential(self) -> None:
        selected = self.credentials_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        website_item = self.credentials_table.item(row, 0)
        username_item = self.credentials_table.item(row, 1)
        if website_item:
            self.website_field.setText(website_item.text())
        if username_item:
            self.credential_username_field.setText(username_item.text())
        self.credential_password_field.clear()

    def clear_credential_form(self) -> None:
        self.website_field.clear()
        self.credential_username_field.clear()
        self.credential_password_field.clear()
        self.retrieve_output.clear()

    def run_manager_action(self, action: Callable[[], object]) -> None:
        try:
            output, _ = self.capture_output(action)
            self.append_log(output or "Operation completed.")
        except Exception as exc:
            self.handle_error("Operation failed", exc)

    def capture_output(self, func: Callable, *args, **kwargs):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            result = func(*args, **kwargs)
        return stream.getvalue().strip(), result

    def append_log(self, text: str) -> None:
        if text:
            self.log_output.append(text)

    def handle_error(self, title: str, exc: Exception) -> None:
        message = str(exc)
        self.append_log(f"{title}: {message}")
        QMessageBox.critical(self, title, message)

    def show_warning(self, message: str) -> None:
        QMessageBox.warning(self, "Missing Information", message)

    def require_manager(self, silent: bool = False) -> bool:
        if self.manager is not None:
            return True
        if not silent:
            QMessageBox.warning(self, "Locked", "Unlock a vault first.")
        return False

    def _apply_styles(self) -> None:
        app_font = QFont("Segoe UI", 10)
        self.setFont(app_font)
        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background: #f6f7f9;
                color: #20242a;
            }
            #loginPanel, QGroupBox {
                background: #ffffff;
                border: 1px solid #d9dee7;
                border-radius: 8px;
            }
            #loginPanel {
                padding: 22px;
            }
            #title {
                font-size: 24px;
                font-weight: 700;
            }
            #subtitle, #sessionLabel {
                color: #55606f;
            }
            #errorText {
                color: #b42318;
            }
            QLineEdit, QTextEdit, QTableWidget {
                background: #ffffff;
                border: 1px solid #ccd3df;
                border-radius: 6px;
                padding: 8px;
                selection-background-color: #2563eb;
            }
            QTableWidget {
                gridline-color: #e3e7ee;
            }
            QHeaderView::section {
                background: #e9edf4;
                border: none;
                padding: 8px;
                font-weight: 600;
            }
            QPushButton {
                background: #ffffff;
                border: 1px solid #b9c2d0;
                border-radius: 6px;
                padding: 8px 12px;
            }
            QPushButton:hover {
                background: #eef4ff;
                border-color: #7aa7ff;
            }
            QPushButton#primaryButton {
                background: #2563eb;
                color: white;
                border-color: #2563eb;
                font-weight: 600;
            }
            QPushButton#primaryButton:hover {
                background: #1d4ed8;
            }
            QTabWidget::pane {
                border: 1px solid #d9dee7;
                background: #ffffff;
                border-radius: 6px;
            }
            QTabBar::tab {
                background: #e9edf4;
                padding: 9px 16px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                font-weight: 600;
            }
            """
        )


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = PasswordManagerWindow()
    window.show()
    return app_exec(app)


if __name__ == "__main__":
    raise SystemExit(main())
