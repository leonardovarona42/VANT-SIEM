$ErrorActionPreference = "Stop"

$certPath = Join-Path $PSScriptRoot "..\certs\dev-cert.pfx"
$certPassword = "vant-siem-dev"

if (-not (Test-Path $certPath)) {
    $certDir = Split-Path $certPath -Parent
    New-Item -ItemType Directory -Path $certDir -Force | Out-Null

    $cert = New-SelfSignedCertificate `
        -DnsName "localhost" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -NotAfter (Get-Date).AddYears(2)

    $securePass = ConvertTo-SecureString $certPassword -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath $certPath -Password $securePass | Out-Null
}

Write-Host "Usando certificado: $certPath"
Write-Host "Password: $certPassword"
Write-Host "Iniciando HTTPS en https://localhost:8000"

python manage.py runsslserver 0.0.0.0:8000 --certificate $certPath --key $certPath
