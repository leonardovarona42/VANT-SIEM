from django.contrib import admin
from .models import (
    Categoria, Subcategoria, Servicio, Responsable, Area,
    Medida, Reporte, Incidente, MedidaIncidente,
    Involucrado, InvolucradoIncidente
)

admin.site.register(Categoria)
admin.site.register(Subcategoria)
admin.site.register(Servicio)
admin.site.register(Responsable)
admin.site.register(Area)
admin.site.register(Medida)
admin.site.register(Reporte)
admin.site.register(Incidente)
admin.site.register(MedidaIncidente)
admin.site.register(Involucrado)