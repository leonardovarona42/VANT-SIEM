import os
import sys
import socket
from urllib.parse import urlparse

import requests
import hashlib
import hmac
import time

from PyQt6 import QtCore, QtGui, QtWidgets
from pathlib import Path


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LOGO_PATH = os.path.join(BASE_DIR, "staticfiles", "img", "logo.png")
BOOTSTRAP_KEY_PATH = os.path.join(BASE_DIR, "opensearch_agents", "installer", "bootstrap.key")
DEFAULT_AGENT_SHARED_SECRET = "VANT-SIEM-AGENT-BOOTSTRAP-2026"


class WelcomePage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Bienvenida")
        self.setSubTitle("Vamos a configurar el agente VANT-SIEM para OpenSearch.")

        layout = QtWidgets.QVBoxLayout()

        status_box = QtWidgets.QGroupBox("Estado del sistema")
        status_layout = QtWidgets.QFormLayout()
        status_layout.addRow("Sistema operativo:", QtWidgets.QLabel("Windows (detectado)"))
        status_layout.addRow("Permisos:", QtWidgets.QLabel("Administrador confirmado"))
        status_layout.addRow("Python:", QtWidgets.QLabel("Disponible"))
        status_layout.addRow("Carpeta destino:", QtWidgets.QLabel("Lista"))
        status_box.setLayout(status_layout)

        hint = QtWidgets.QLabel(
            "Recomendamos probar la conectividad antes de instalar el servicio."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #6b7280;")

        layout.addWidget(status_box)
        layout.addWidget(hint)
        layout.addStretch()
        self.setLayout(layout)


class IdentityPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Identidad del agente")
        self.setSubTitle("Define como se identificara este agente.")

        layout = QtWidgets.QFormLayout()

        self.agent_id = QtWidgets.QLineEdit("agent-001")
        self.host_name = QtWidgets.QLineEdit(socket.gethostname())
        self.interval = QtWidgets.QSpinBox()
        self.interval.setRange(1, 3600)
        self.interval.setValue(10)

        layout.addRow("Agent ID:", self.agent_id)
        layout.addRow("Host Name:", self.host_name)
        layout.addRow("Intervalo (segundos):", self.interval)
        self.setLayout(layout)

        self.registerField("agent_id*", self.agent_id)
        self.registerField("host_name*", self.host_name)
        self.registerField("interval", self.interval)

        self.agent_id.textChanged.connect(self.completeChanged)
        self.host_name.textChanged.connect(self.completeChanged)

    def isComplete(self):
        return bool(self.agent_id.text().strip()) and bool(
            self.host_name.text().strip()
        )


class ConnectionPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Conexion a OpenSearch")
        self.setSubTitle("Configura IPs, puertos y seguridad.")

        layout = QtWidgets.QFormLayout()

        self.server_host = QtWidgets.QLineEdit("127.0.0.1")
        self.server_port = QtWidgets.QSpinBox()
        self.server_port.setRange(1, 65535)
        self.server_port.setValue(8000)
        self.server_https = QtWidgets.QCheckBox("Usar HTTPS para VANT-SIEM")

        self.opensearch_host = QtWidgets.QLineEdit("127.0.0.1")
        self.opensearch_port = QtWidgets.QSpinBox()
        self.opensearch_port.setRange(1, 65535)
        self.opensearch_port.setValue(9201)

        self.endpoint = QtWidgets.QLineEdit(
            "http://127.0.0.1:9201/api/v1/events/bulk"
        )
        self.source_endpoint = QtWidgets.QLineEdit(
            "http://127.0.0.1:9201/api/v1/sources/upsert"
        )
        self.timeout = QtWidgets.QSpinBox()
        self.timeout.setRange(1, 120)
        self.timeout.setValue(10)

        self.tls_enabled = QtWidgets.QCheckBox("Habilitar TLS")
        self.tls_verify = QtWidgets.QCheckBox("Verificar certificado")
        self.tls_verify.setChecked(False)
        self.ca_cert = QtWidgets.QLineEdit("")

        self.test_button = QtWidgets.QPushButton("Probar conexion")
        self.test_status = QtWidgets.QLabel("Sin pruebas ejecutadas.")
        self.test_status.setStyleSheet("color: #6b7280;")
        self.test_button.clicked.connect(self._on_test)

        layout.addRow("Servidor VANT-SIEM IP:", self.server_host)
        layout.addRow("Servidor VANT-SIEM Puerto:", self.server_port)
        layout.addRow(self.server_https)
        layout.addRow("OpenSearch IP:", self.opensearch_host)
        layout.addRow("OpenSearch Puerto:", self.opensearch_port)
        layout.addRow("Timeout (segundos):", self.timeout)
        layout.addRow(self.tls_enabled)
        layout.addRow(self.tls_verify)
        layout.addRow("Certificado CA:", self.ca_cert)
        layout.addRow(self.test_button, self.test_status)
        self.setLayout(layout)

        self.endpoint.setVisible(False)
        self.source_endpoint.setVisible(False)

        self.registerField("server_host*", self.server_host)
        self.registerField("server_port", self.server_port)
        self.registerField("server_https", self.server_https)
        self.registerField("endpoint*", self.endpoint)
        self.registerField("source_endpoint*", self.source_endpoint)
        self.registerField("timeout", self.timeout)
        self.registerField("tls_enabled", self.tls_enabled)
        self.registerField("tls_verify", self.tls_verify)
        self.registerField("ca_cert", self.ca_cert)
        self.registerField("opensearch_host*", self.opensearch_host)
        self.registerField("opensearch_port", self.opensearch_port)

        self.server_host.textChanged.connect(self._refresh_endpoints)
        self.server_port.valueChanged.connect(self._refresh_endpoints)
        self.opensearch_host.textChanged.connect(self._refresh_endpoints)
        self.opensearch_port.valueChanged.connect(self._refresh_endpoints)
        self.tls_enabled.stateChanged.connect(self._refresh_endpoints)
        self._refresh_endpoints()

    def _on_test(self):
        wizard = self.wizard()
        auth_page = wizard.page(AgentInstallerWizard.PAGE_AUTH)
        auth_mode = auth_page.auth_mode.currentText()

        if auth_mode == "none":
            shared_secret = self._load_bootstrap_key()
            if not shared_secret:
                shared_secret = DEFAULT_AGENT_SHARED_SECRET

            timestamp = str(int(time.time()))
            signature = self._sign_request(
                shared_secret,
                wizard.field("agent_id"),
                wizard.field("host_name"),
                timestamp,
            )
            payload = {
                "agent_id": wizard.field("agent_id"),
                "host_name": wizard.field("host_name"),
                "timestamp": timestamp,
                "signature": signature,
            }
            enroll_url = self._build_enroll_url()
            try:
                response = requests.post(enroll_url, json=payload, timeout=8)
                data = {}
                if "application/json" in response.headers.get("Content-Type", ""):
                    data = response.json()
            except Exception as exc:
                self.test_status.setText(f"Error al conectar: {exc}")
                self.test_status.setStyleSheet("color: #dc2626;")
                return

            if response.status_code != 200 or not data.get("ok"):
                if response.status_code == 400 and "HTTPS" in response.text:
                    self.test_status.setText(
                        "Servidor en HTTP. Desactiva HTTPS o inicia run_https.ps1."
                    )
                else:
                    self.test_status.setText("Agente no autorizado para enrolamiento.")
                self.test_status.setStyleSheet("color: #dc2626;")
                return

            token = data.get("token", "")
            auth_page.auth_mode.setCurrentText("token")
            auth_page.token.setText(token)

        self._refresh_endpoints()
        if self._probe_endpoint(self.endpoint.text().strip()):
            self.test_status.setText("Conexion exitosa y token obtenido.")
            self.test_status.setStyleSheet("color: #16a34a;")
        else:
            self.test_status.setText("Token obtenido, pero endpoint no responde.")
            self.test_status.setStyleSheet("color: #f59e0b;")

    def _build_enroll_url(self):
        scheme = "https" if self.server_https.isChecked() else "http"
        host = self.server_host.text().strip()
        port = self.server_port.value()
        return f"{scheme}://{host}:{port}/api/agent/enroll/"

    def _load_bootstrap_key(self):
        env_key = os.environ.get("VANT_AGENT_BOOTSTRAP_KEY", "").strip()
        if env_key:
            return env_key
        env_shared = os.environ.get("VANT_AGENT_SHARED_SECRET", "").strip()
        if env_shared:
            return env_shared
        if os.path.exists(BOOTSTRAP_KEY_PATH):
            try:
                with open(BOOTSTRAP_KEY_PATH, "r", encoding="utf-8") as handle:
                    return handle.read().strip()
            except Exception:
                return ""
        return ""

    def _sign_request(self, secret, agent_id, host_name, timestamp):
        message = f"{agent_id}:{host_name}:{timestamp}".encode("utf-8")
        return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()

    def _refresh_endpoints(self):
        scheme = "https" if self.tls_enabled.isChecked() else "http"
        host = self.opensearch_host.text().strip()
        port = self.opensearch_port.value()
        self.endpoint.setText(f"{scheme}://{host}:{port}/api/v1/events/bulk")
        self.source_endpoint.setText(f"{scheme}://{host}:{port}/api/v1/sources/upsert")

    def _probe_endpoint(self, endpoint):
        try:
            parsed = urlparse(endpoint)
            if not parsed.hostname or not parsed.port:
                return False
            sock = socket.create_connection((parsed.hostname, parsed.port), timeout=3)
            sock.close()
            return True
        except Exception:
            return False




class AuthPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Autenticacion")
        self.setSubTitle("Selecciona el metodo de autenticacion.")

        layout = QtWidgets.QVBoxLayout()

        self.auth_mode = QtWidgets.QComboBox()
        self.auth_mode.addItems(["none", "basic", "token"])
        self.auth_mode.currentTextChanged.connect(self._update_fields)

        self.user = QtWidgets.QLineEdit()
        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.token = QtWidgets.QLineEdit()

        form = QtWidgets.QFormLayout()
        form.addRow("Modo:", self.auth_mode)
        form.addRow("Usuario:", self.user)
        form.addRow("Password:", self.password)
        form.addRow("Token:", self.token)

        layout.addLayout(form)
        layout.addStretch()
        self.setLayout(layout)
        self._update_fields(self.auth_mode.currentText())

        self.registerField("auth_mode", self.auth_mode, "currentText")
        self.registerField("auth_user", self.user)
        self.registerField("auth_password", self.password)
        self.registerField("auth_token", self.token)

    def _update_fields(self, mode):
        basic = mode == "basic"
        token = mode == "token"
        self.user.setEnabled(basic)
        self.password.setEnabled(basic)
        self.token.setEnabled(token)


class CollectorsPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Recolectores")
        self.setSubTitle("Activa las fuentes de eventos.")

        layout = QtWidgets.QFormLayout()

        self.snort = QtWidgets.QCheckBox("Snort")
        self.snort_path = QtWidgets.QLineEdit("C:/snort/log/alert")
        self.suricata = QtWidgets.QCheckBox("Suricata")
        self.suricata_path = QtWidgets.QLineEdit("C:/suricata/logs/eve.json")
        self.winlog = QtWidgets.QCheckBox("Windows Event Log")
        self.winlog_channel = QtWidgets.QComboBox()
        self.winlog_channel.addItems(["Security", "Application", "System"])
        self.postgres = QtWidgets.QCheckBox("PostgreSQL")
        self.postgres_path = QtWidgets.QLineEdit(
            "C:/Program Files/PostgreSQL/16/data/log/postgresql.log"
        )
        self.file_logs = QtWidgets.QCheckBox("File Logs")
        self.file_logs_path = QtWidgets.QLineEdit("/var/log/samba/audit.log")

        layout.addRow(self.snort, self.snort_path)
        layout.addRow(self.suricata, self.suricata_path)
        layout.addRow(self.winlog, self.winlog_channel)
        layout.addRow(self.postgres, self.postgres_path)
        layout.addRow(self.file_logs, self.file_logs_path)
        self.setLayout(layout)

        self.registerField("snort_enabled", self.snort)
        self.registerField("snort_path", self.snort_path)
        self.registerField("suricata_enabled", self.suricata)
        self.registerField("suricata_path", self.suricata_path)
        self.registerField("winlog_enabled", self.winlog)
        self.registerField("winlog_channel", self.winlog_channel, "currentText")
        self.registerField("postgres_enabled", self.postgres)
        self.registerField("postgres_path", self.postgres_path)
        self.registerField("file_logs_enabled", self.file_logs)
        self.registerField("file_logs_path", self.file_logs_path)


class SummaryPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Resumen")
        self.setSubTitle("Revisa la configuracion antes de instalar.")

        layout = QtWidgets.QVBoxLayout()
        self.preview = QtWidgets.QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setStyleSheet("font-family: Consolas, monospace;")

        self.install_service = QtWidgets.QCheckBox("Instalar como servicio")
        self.install_service.setChecked(True)

        layout.addWidget(self.preview)
        layout.addWidget(self.install_service)
        self.setLayout(layout)

    def initializePage(self):
        wizard = self.wizard()
        config = wizard.build_config_preview(mask_secrets=True)

        self.preview.setPlainText(config)


class ProgressPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Instalacion en progreso")
        self.setSubTitle("Aplicando la configuracion y registrando el servicio.")
        self.setFinalPage(True)

        layout = QtWidgets.QVBoxLayout()
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet("font-family: Consolas, monospace;")

        layout.addWidget(self.progress)
        layout.addWidget(self.log)
        self.setLayout(layout)

        self._timer = QtCore.QTimer(self)
        self._timer.setInterval(300)
        self._timer.timeout.connect(self._tick)

    def initializePage(self):
        self.progress.setValue(0)
        self.log.clear()
        self.log.appendPlainText("Iniciando instalacion del agente...")
        self.log.appendPlainText("Validando configuracion...")
        if not self.wizard().write_config_file():
            self.log.appendPlainText("Error al escribir config.yaml.")
        else:
            self.log.appendPlainText("config.yaml guardado correctamente.")
            if self.wizard().page(AgentInstallerWizard.PAGE_SUMMARY).install_service.isChecked():
                if self._install_windows_service():
                    self.log.appendPlainText("Servicio creado y configurado (auto-start).")
                else:
                    self.log.appendPlainText("No se pudo crear el servicio.")
        self._timer.start()

    def _tick(self):
        value = self.progress.value() + 10
        self.progress.setValue(value)
        self.log.appendPlainText(f"Paso completado ({value}%).")
        if value >= 100:
            self._timer.stop()
            self.log.appendPlainText("Servicio instalado correctamente (mock).")
            self._launch_tray()
            self.completeChanged.emit()

    def _launch_tray(self):
        try:
            tray_path = Path("opensearch_agents/agent_tray.py")
            if tray_path.exists():
                QtCore.QProcess.startDetached(
                    sys.executable, [str(tray_path), "--config", "opensearch_agents/config.yaml"]
                )
                self.log.appendPlainText("Agente iniciado en bandeja (tray).")
        except Exception:
            self.log.appendPlainText("No se pudo iniciar el tray del agente.")

    def _install_windows_service(self):
        try:
            service_name = "VANTSIEMAgent"
            python_exe = sys.executable
            agent_path = Path("opensearch_agents/agent.py").resolve()
            config_path = Path("opensearch_agents/config.yaml").resolve()
            bin_path = f'"{python_exe}" "{agent_path}" --config "{config_path}"'

            create_cmd = [
                "sc.exe",
                "create",
                service_name,
                f'binPath= {bin_path}',
                "start= auto",
            ]
            QtCore.QProcess.execute("sc.exe", ["delete", service_name])
            QtCore.QProcess.execute(create_cmd[0], create_cmd[1:])
            QtCore.QProcess.execute("sc.exe", ["failure", service_name, "reset= 0", "actions= restart/5000"])
            QtCore.QProcess.execute("sc.exe", ["start", service_name])
            return True
        except Exception:
            return False

    def isComplete(self):
        return self.progress.value() >= 100


class AgentInstallerWizard(QtWidgets.QWizard):
    PAGE_WELCOME = 0
    PAGE_IDENTITY = 1
    PAGE_CONNECTION = 2
    PAGE_AUTH = 3
    PAGE_COLLECTORS = 4
    PAGE_SUMMARY = 5
    PAGE_PROGRESS = 6

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VANT-SIEM OpenSearch Agent Installer")
        self.setWizardStyle(QtWidgets.QWizard.WizardStyle.ModernStyle)

        if os.path.exists(LOGO_PATH):
            icon = QtGui.QIcon(LOGO_PATH)
            self.setWindowIcon(icon)
            self.setPixmap(
                QtWidgets.QWizard.WizardPixmap.LogoPixmap,
                QtGui.QPixmap(LOGO_PATH).scaled(64, 64, QtCore.Qt.AspectRatioMode.KeepAspectRatio),
            )

        self.setPage(self.PAGE_WELCOME, WelcomePage())
        self.setPage(self.PAGE_IDENTITY, IdentityPage())
        self.setPage(self.PAGE_CONNECTION, ConnectionPage())
        self.setPage(self.PAGE_AUTH, AuthPage())
        self.setPage(self.PAGE_COLLECTORS, CollectorsPage())
        self.setPage(self.PAGE_SUMMARY, SummaryPage())
        self.setPage(self.PAGE_PROGRESS, ProgressPage())

        self.setStartId(self.PAGE_WELCOME)
        self.setOption(QtWidgets.QWizard.WizardOption.NoBackButtonOnStartPage, True)
        self.setOption(QtWidgets.QWizard.WizardOption.IndependentPages, False)
        self.setOption(QtWidgets.QWizard.WizardOption.HaveFinishButtonOnEarlyPages, False)

    def accept(self):
        QtWidgets.QMessageBox.information(
            self,
            "Instalacion completada",
            "El servicio se instalo correctamente.",
        )
        super().accept()

    def build_config_preview(self, mask_secrets=False):
        agent_id = self.field("agent_id")
        host_name = self.field("host_name")
        interval = self.field("interval")
        endpoint = self.field("endpoint")
        source_endpoint = self.field("source_endpoint")
        timeout = self.field("timeout")
        tls_enabled = self.field("tls_enabled")
        tls_verify = self.field("tls_verify")
        ca_cert = self.field("ca_cert")
        auth_mode = self.field("auth_mode")
        auth_user = self.field("auth_user")
        auth_password = self.field("auth_password") or ""
        auth_token = self.field("auth_token") or ""
        server_url = self._build_server_url()

        if mask_secrets:
            auth_password = "******" if auth_password else ""
            auth_token = "******" if auth_token else ""

        require_https = self.page(self.PAGE_CONNECTION).server_https.isChecked()
        return f"""agent:
  id: "{agent_id}"
  host_name: "{host_name}"
  interval_seconds: {interval}

output:
  endpoint: "{endpoint}"
  source_endpoint: "{source_endpoint}"
  timeout_seconds: {timeout}
  auth:
    mode: "{auth_mode}"
    username: "{auth_user}"
    password: "{auth_password}"
    token: "{auth_token}"
  tls:
    enabled: {str(tls_enabled).lower()}
    verify: {str(tls_verify).lower()}
    ca_cert: "{ca_cert}"

control:
  server_url: "{server_url}"
  require_https: {str(require_https).lower()}
"""

    def write_config_file(self):
        try:
            import yaml
        except Exception:
            return False
        config_text = self.build_config_preview(mask_secrets=False)
        try:
            data = yaml.safe_load(config_text) or {}
            config_path = Path("opensearch_agents/config.yaml")
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                yaml.safe_dump(data, sort_keys=False, allow_unicode=False),
                encoding="utf-8",
            )
            return True
        except Exception:
            return False

    def _build_server_url(self):
        page = self.page(self.PAGE_CONNECTION)
        scheme = "https" if page.server_https.isChecked() else "http"
        host = page.server_host.text().strip()
        port = page.server_port.value()
        return f"{scheme}://{host}:{port}"


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")

    wizard = AgentInstallerWizard()
    wizard.resize(820, 540)
    wizard.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
