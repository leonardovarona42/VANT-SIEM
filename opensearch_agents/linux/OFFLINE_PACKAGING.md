# Linux Offline Packaging

This directory now documents the Linux agent packaging flow used for offline tests.

## Package layout

The installer expects an extracted payload named `vant-siem-agent-install/` with:

- `install.sh`
- `uninstall.sh`
- `config/agent.yaml`
- `agent/`
- `scripts/`
- `bin/`
- `desktop/`
- `systemd/`
- `docs/`
- `manifest.json`

Each distro directory under `linux/dist/<distro>/` also gets:

- `install.sh`
- `uninstall.sh`

## Install flow

1. Build the payload on a packaging host with `opensearch_agents/linux/build_linux.sh`.
   By default it discovers every distro folder that contains a `config.yaml`.
2. Copy `linux/dist/<distro>/` to the target machine or export the extracted package directory.
3. Run `linux/dist/<distro>/install.sh` or the extracted package `install.sh`.

## Overrides

- `VANT_LINUX_DISTRO` selects `debian`, `ubuntu`, or `zentyal`.
- `VANT_AGENT_PACKAGE_DIR` points the installer to a pre-extracted package directory.
- `VANT_AGENT_WIZARD=0` disables the interactive CLI wizard.

## Offline verification

The target machine should not need internet access. The installer only:

- locates a prebuilt bundle,
- optionally runs the CLI wizard from the bundle,
- copies files into `/opt/vant-siem-agent` and `/etc/vant-siem`,
- installs the tray autostart entry and `systemd` service if present.
- installs helper commands into `/opt/vant-siem-agent/bin` and links them into
  `/usr/local/bin`.
- assigns `/opt/vant-siem-agent` to the invoking `sudo` user when available,
  while keeping `/etc/vant-siem` root-managed.
