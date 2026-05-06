from django import forms
from .models import Servicio

class ServicioForm(forms.ModelForm):
    class Meta:
        model = Servicio
        exclude = ['servicios_hijos', 'estado_monitoreo']
        widgets = {
            'descripcion': forms.Textarea(attrs={'rows': 3}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        optional_fields = [
            'servicio_padre', 'num_puertos', 'modelo', 
            'fabricante', 'numero_serie', 'firmware', 'network', 'subnet_mask',
            'gateway', 'red_tipo', 'vlan_id', 'dns_primario', 'dns_secundario',
            'dhcp_activo', 'dhcp_rango_inicio', 'dhcp_rango_fin', 'host',
            'url_servicio', 'puerto_servicio', 'api_key', 'plataforma',
            'ubicacion_fisica', 'rack', 'posicion_rack', 'edificio', 'piso',
            'coordenadas_x', 'coordenadas_y', 'coordenadas_logicas_x',
            'coordenadas_logicas_y', 'nivel_red', 'responsable',
            'protocolo_monitoreo', 'puerto_monitoreo', 'intervalo_segundos',
            'monitorear', 'activo',
        ]
        for field in optional_fields:
            if field in self.fields:
                self.fields[field].required = False
