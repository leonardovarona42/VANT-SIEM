# Linux Offline Packaging

This directory now documents the Linux agent packaging flow used for offline tests.

## Package layout

The installer expects an extracted payload named `vant-siem-agent-install/` with:

- `install.sh`
- `config/agent.yaml`
- `agent/`
- `scripts/`
- `docs/`

## Install flow

1. Build the payload on a packaging host with the Linux build pipeline.
2. Copy `linux/dist/` to the target machine or export the extracted package directory.
3. Run the distro wrapper from `debian/`, `ubuntu/`, or `zentyal/`.

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
