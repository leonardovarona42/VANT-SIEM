#!/usr/bin/env python3
"""
Script para verificar y agregar involucrados con rangos de IP específicos.
"""

import os
import sys
import django
from datetime import datetime
from django.utils import timezone

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
sys.path.insert(0, os.path.dirname(__file__))
django.setup()

from EVENT_M.models import Involucrado, Incidente, Medida

def generate_ips_in_range(base_ip, subnet_mask, count=10):
    """Genera IPs dentro de un rango de subred"""
    import ipaddress

    try:
        network = ipaddress.IPv4Network(f"{base_ip}/{subnet_mask}", strict=False)
        # Generar IPs dentro de la subred (excluyendo network y broadcast)
        ips = []
        for i in range(min(count, network.num_addresses - 2)):
            ip = network.network_address + i + 1
            ips.append(str(ip))
        return ips
    except:
        # Fallback simple si hay problemas con ipaddress
        base_parts = base_ip.split('.')
        ips = []
        for i in range(count):
            new_ip = f"{base_parts[0]}.{base_parts[1]}.{int(base_parts[2]) + i}.{int(base_parts[3]) + i}"
            ips.append(new_ip)
        return ips

def verify_and_add_involucrados():
    """Verificar y agregar involucrados con IPs específicas"""

    print(">>> VERIFICANDO INVOLUCRADOS CON RANGOS DE IP ESPECÍFICOS")
    print("=" * 60)

    # IPs específicas a verificar
    target_ips = [
        '10.212.97.69',  # IP principal mencionada
        '172.26.16.1',   # vEthernet Default Switch
        '172.27.160.1'   # vEthernet WSL
    ]

    # Rangos de red a poblar
    network_ranges = [
        {
            'base_ip': '10.212.97.69',
            'subnet': '255.255.192.0',
            'gateway': '10.212.64.1',
            'description': 'Red corporativa principal'
        },
        {
            'base_ip': '172.26.16.1',
            'subnet': '255.255.240.0',
            'gateway': None,
            'description': 'vEthernet Default Switch'
        },
        {
            'base_ip': '172.27.160.1',
            'subnet': '255.255.240.0',
            'gateway': None,
            'description': 'vEthernet WSL'
        }
    ]

    # Verificar IPs específicas
    print("\n>>> VERIFICANDO IPs ESPECIFICAS:")
    for ip in target_ips:
        involucrado = Involucrado.objects.filter(ip=ip).first()
        if involucrado:
            print(f"[OK] IP {ip} - EXISTE: {involucrado.nombres} {involucrado.apellidos} ({involucrado.usuario})")
        else:
            print(f"[NO] IP {ip} - NO EXISTE")

    # Generar datos para rangos faltantes
    nombres = ['Juan', 'María', 'Carlos', 'Ana', 'Pedro', 'Laura', 'Miguel', 'Carmen', 'José', 'Isabel', 'Luis', 'Sofia', 'Diego', 'Valentina', 'Andres']
    apellidos = ['García', 'Rodríguez', 'González', 'Fernández', 'López', 'Martínez', 'Sánchez', 'Pérez', 'Martín', 'Ruiz', 'Hernández', 'Jiménez', 'Moreno', 'Álvarez', 'Romero']
    tipos = ['Usuario', 'Administrador', 'Contratista', 'Visitante', 'Proveedor', 'Desarrollador', 'Analista']
    macs_base = ['00:1B:44:11:3A:B7', '00:1C:42:2E:5F:8A', '00:1D:60:3C:7B:9D', '00:1E:65:4A:8C:EF', '00:1F:70:5B:9D:01']

    involucrados_creados = 0

    for network in network_ranges:
        print(f"\n>>> PROCESANDO RED: {network['description']}")
        print(f"   Base IP: {network['base_ip']}")
        print(f"   Subnet: {network['subnet']}")
        if network['gateway']:
            print(f"   Gateway: {network['gateway']}")

        # Generar IPs del rango
        ips_rango = generate_ips_in_range(network['base_ip'], network['subnet'], 15)

        for i, ip in enumerate(ips_rango):
            # Verificar si ya existe
            if Involucrado.objects.filter(ip=ip).exists():
                continue

            # Crear nuevo involucrado
            nombre = nombres[i % len(nombres)]
            apellido = apellidos[i % len(apellidos)]
            usuario = f"{nombre.lower()}.{apellido.lower()}{i}"

            # Generar MAC variando el último byte
            mac_base = macs_base[i % len(macs_base)]
            mac_parts = mac_base.split(':')
            mac_parts[-1] = f"{int(mac_parts[-1], 16) + i:02X}"[:2]
            mac = ':'.join(mac_parts)

            involucrado = Involucrado.objects.create(
                nombres=nombre,
                apellidos=apellido,
                usuario=usuario,
                ip=ip,
                mac=mac,
                tipo=tipos[i % len(tipos)]
            )

            print(f"[+] Creado: {involucrado.nombres} {involucrado.apellidos} - IP: {ip} - MAC: {mac}")
            involucrados_creados += 1

    print(f"\n>>> TOTAL INVOLUCRADOS CREADOS: {involucrados_creados}")

    # Verificación final
    print("\n>>> VERIFICACIÓN FINAL:")
    total_involucrados = Involucrado.objects.count()
    print(f"Total de involucrados en BD: {total_involucrados}")

    for ip in target_ips:
        count = Involucrado.objects.filter(ip=ip).count()
        print(f"IP {ip}: {count} involucrado(s)")

    # Mostrar algunos ejemplos de cada red
    print("\n>>> EJEMPLOS POR RED:")
    for network in network_ranges:
        ips_rango = generate_ips_in_range(network['base_ip'], network['subnet'], 3)
        print(f"\n{network['description']}:")
        for ip in ips_rango:
            involucrado = Involucrado.objects.filter(ip=ip).first()
            if involucrado:
                print(f"  {ip} -> {involucrado.nombres} {involucrado.apellidos} ({involucrado.tipo})")

def main():
    try:
        verify_and_add_involucrados()
        print("\n" + "=" * 60)
        print(">>> VERIFICACIÓN COMPLETADA EXITOSAMENTE")
    except Exception as e:
        print(f"\n>>> Error durante la verificación: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()