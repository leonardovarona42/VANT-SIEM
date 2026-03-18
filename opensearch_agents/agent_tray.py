import argparse
import os
import sys
import threading
import time
from pathlib import Path

import requests
from PyQt6 import QtCore, QtGui, QtWidgets

from agent import run_with_stop


_HERE = Path(__file__).resolve().parent
_CANDIDATES = [
    _HERE / "staticfiles" / "img" / "logo.png",
    _HERE.parent / "staticfiles" / "img" / "logo.png",
]
LOGO_PATH = next((p for p in _CANDIDATES if p.exists()), _CANDIDATES[0])


def load_cfg(path):
    import yaml

    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


class StopDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confirmar detencion del agente")
        self.setModal(True)

        layout = QtWidgets.QFormLayout()
        self.username = QtWidgets.QLineEdit()
        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        layout.addRow("Usuario superusuario:", self.username)
        layout.addRow("Password:", self.password)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        wrapper = QtWidgets.QVBoxLayout()
        wrapper.addLayout(layout)
        wrapper.addWidget(buttons)
        self.setLayout(wrapper)

    def get_credentials(self):
        return self.username.text().strip(), self.password.text()


class AgentTray(QtWidgets.QSystemTrayIcon):
    def __init__(self, config_path):
        super().__init__()
        self.config_path = config_path
        self.cfg = load_cfg(config_path)
        self.stop_event = threading.Event()

        icon = QtGui.QIcon(str(LOGO_PATH)) if LOGO_PATH.exists() else QtGui.QIcon()
        self.setIcon(icon)
        self.setToolTip("VANT-SIEM Agent v1.01")

        self.menu = QtWidgets.QMenu()
        self.action_show = self.menu.addAction("Mostrar estado")
        self.action_stop = self.menu.addAction("Detener agente")
        self.action_exit = self.menu.addAction("Salir")
        self.setContextMenu(self.menu)

        self.action_show.triggered.connect(self._show_status)
        self.action_stop.triggered.connect(self._stop_agent)
        self.action_exit.triggered.connect(self._exit_app)

        if self._can_start_worker():
            self.worker = threading.Thread(
                target=run_with_stop, args=(config_path, self.stop_event), daemon=True
            )
            self.worker.start()
        else:
            self.worker = None

        self.show()

    def _show_status(self):
        QtWidgets.QMessageBox.information(
            None, "VANT-SIEM Agent", "El agente esta ejecutandose."
        )

    def _exit_app(self):
        if self._authorize_stop():
            self._stop_worker()
            QtWidgets.QApplication.quit()

    def _stop_agent(self):
        if self._authorize_stop():
            self._stop_worker()
            QtWidgets.QMessageBox.information(
                None, "VANT-SIEM Agent", "Agente detenido correctamente."
            )

    def _stop_worker(self):
        if self.worker is None:
            return
        self.stop_event.set()
        time.sleep(0.5)

    def _authorize_stop(self):
        control_cfg = self.cfg.get("control", {})
        server_url = (control_cfg.get("server_url") or "").rstrip("/")
        require_https = bool(control_cfg.get("require_https", True))

        if not server_url:
            QtWidgets.QMessageBox.warning(
                None, "VANT-SIEM Agent", "Servidor de control no configurado."
            )
            return False

        if require_https and not server_url.lower().startswith("https://"):
            QtWidgets.QMessageBox.warning(
                None, "VANT-SIEM Agent", "HTTPS requerido para detener el agente."
            )
            return False

        dialog = StopDialog()
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return False

        username, password = dialog.get_credentials()
        payload = {"username": username, "password": password}
        try:
            response = requests.post(
                f"{server_url}/api/agent/authorize-stop/",
                json=payload,
                timeout=8,
            )
            data = response.json()
        except Exception as exc:
            QtWidgets.QMessageBox.warning(
                None, "VANT-SIEM Agent", f"Error de conexion: {exc}"
            )
            return False

        if response.status_code != 200 or not data.get("ok"):
            QtWidgets.QMessageBox.warning(
                None, "VANT-SIEM Agent", "Credenciales invalidas."
            )
            return False

        return True

    def _can_start_worker(self):
        agent_cfg = self.cfg.get("agent", {})
        log_file = (agent_cfg.get("log_file") or "").strip()
        if not log_file:
            return True
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8"):
                pass
            return True
        except Exception:
            QtWidgets.QMessageBox.warning(
                None,
                "VANT-SIEM Agent",
                "No hay permisos para escribir el log del agente. "
                "El tray se iniciara sin ejecutar el agente.",
            )
            return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="opensearch_agents/config.yaml")
    args = parser.parse_args()

    app = QtWidgets.QApplication(sys.argv)
    tray = AgentTray(args.config)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
