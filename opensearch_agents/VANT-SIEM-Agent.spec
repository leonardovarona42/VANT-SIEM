# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['/home/testing/Desktop/VANT-SIEM/opensearch_agents/agent.py'],
    pathex=[],
    binaries=[],
    datas=[('config.example.yaml', '.')],
    hiddenimports=['yaml', 'requests'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pytest', 'setuptools', 'pip'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='VANT-SIEM-Agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
