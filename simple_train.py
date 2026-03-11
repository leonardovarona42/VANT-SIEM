#!/usr/bin/env python3
"""
Script simple para entrenar el modelo de IA de IRIS
"""
import os
import sys
import django

# Setup Django
sys.path.append('.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from IRIS.ai_incident_investigator import AIIncidentInvestigator

def main():
    print("Entrenando sistema de IA IRIS...")
    investigator = AIIncidentInvestigator()
    investigator.train_models()

    print("Entrenamiento completado!")
    print("Probando analisis...")
    incidents = investigator.analyze_recent_logs(hours_back=1)
    print(f"Incidentes creados: {incidents}")

if __name__ == "__main__":
    main()