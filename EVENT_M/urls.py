from django.urls import path
from .views import (
    CategoriaListView, CategoriaDetailView, CategoriaCreateView, CategoriaUpdateView, CategoriaDeleteView,
    SubcategoriaListView, SubcategoriaDetailView, SubcategoriaCreateView, SubcategoriaUpdateView, SubcategoriaDeleteView,
    ServicioListView, ServicioDetailView, ServicioCreateView, ServicioUpdateView, ServicioDeleteView,
    ResponsableListView, ResponsableDetailView, ResponsableCreateView, ResponsableUpdateView, ResponsableDeleteView,
    AreaListView, AreaDetailView, AreaCreateView, AreaUpdateView, AreaDeleteView,
    MedidaListView, MedidaDetailView, MedidaCreateView, MedidaUpdateView, MedidaDeleteView,
    ReporteListView, ReporteDetailView, ReporteCreateView, ReporteUpdateView, ReporteDeleteView,
    IncidenteListView, IncidenteDetailView, IncidenteCreateView, IncidenteUpdateView, IncidenteDeleteView,
    MedidaIncidenteListView, MedidaIncidenteDetailView, MedidaIncidenteCreateView, MedidaIncidenteUpdateView, MedidaIncidenteDeleteView,
    InvolucradoListView, InvolucradoDetailView, InvolucradoCreateView, InvolucradoUpdateView, InvolucradoDeleteView,
    InvolucradoIncidenteListView, InvolucradoIncidenteDetailView, InvolucradoIncidenteCreateView, InvolucradoIncidenteUpdateView, InvolucradoIncidenteDeleteView,
    dashboard_metrics, incidentes_timeline, reporte_externo,
)

urlpatterns = [
    # Categoria
    path('categorias/', CategoriaListView.as_view(), name='categoria-list'),
    path('categoria/<int:pk>/', CategoriaDetailView.as_view(), name='categoria-detail'),
    path('categoria/nueva/', CategoriaCreateView.as_view(), name='categoria-create'),
    path('categoria/<int:pk>/editar/', CategoriaUpdateView.as_view(), name='categoria-update'),
    path('categoria/<int:pk>/eliminar/', CategoriaDeleteView.as_view(), name='categoria-delete'),

    # Subcategoria
    path('subcategorias/', SubcategoriaListView.as_view(), name='subcategoria-list'),
    path('subcategoria/<int:pk>/', SubcategoriaDetailView.as_view(), name='subcategoria-detail'),
    path('subcategoria/nueva/', SubcategoriaCreateView.as_view(), name='subcategoria-create'),
    path('subcategoria/<int:pk>/editar/', SubcategoriaUpdateView.as_view(), name='subcategoria-update'),
    path('subcategoria/<int:pk>/eliminar/', SubcategoriaDeleteView.as_view(), name='subcategoria-delete'),

    # Servicio
    path('servicios/', ServicioListView.as_view(), name='servicio-list'),
    path('servicio/<int:pk>/', ServicioDetailView.as_view(), name='servicio-detail'),
    path('servicio/nuevo/', ServicioCreateView.as_view(), name='servicio-create'),
    path('servicio/<int:pk>/editar/', ServicioUpdateView.as_view(), name='servicio-update'),
    path('servicio/<int:pk>/eliminar/', ServicioDeleteView.as_view(), name='servicio-delete'),

    # Responsable
    path('responsables/', ResponsableListView.as_view(), name='responsable-list'),
    path('responsable/<int:pk>/', ResponsableDetailView.as_view(), name='responsable-detail'),
    path('responsable/nuevo/', ResponsableCreateView.as_view(), name='responsable-create'),
    path('responsable/<int:pk>/editar/', ResponsableUpdateView.as_view(), name='responsable-update'),
    path('responsable/<int:pk>/eliminar/', ResponsableDeleteView.as_view(), name='responsable-delete'),

    # Area
    path('areas/', AreaListView.as_view(), name='area-list'),
    path('area/<int:pk>/', AreaDetailView.as_view(), name='area-detail'),
    path('area/nueva/', AreaCreateView.as_view(), name='area-create'),
    path('area/<int:pk>/editar/', AreaUpdateView.as_view(), name='area-update'),
    path('area/<int:pk>/eliminar/', AreaDeleteView.as_view(), name='area-delete'),

    # Medida
    path('medidas/', MedidaListView.as_view(), name='medida-list'),
    path('medida/<int:pk>/', MedidaDetailView.as_view(), name='medida-detail'),
    path('medida/nueva/', MedidaCreateView.as_view(), name='medida-create'),
    path('medida/<int:pk>/editar/', MedidaUpdateView.as_view(), name='medida-update'),
    path('medida/<int:pk>/eliminar/', MedidaDeleteView.as_view(), name='medida-delete'),

    # Reporte
    path('reportes/', ReporteListView.as_view(), name='reporte-list'),
    path('reporte/<int:pk>/', ReporteDetailView.as_view(), name='reporte-detail'),
    path('reporte/nuevo/', ReporteCreateView.as_view(), name='reporte-create'),
    path('reporte/<int:pk>/editar/', ReporteUpdateView.as_view(), name='reporte-update'),
    path('reporte/<int:pk>/eliminar/', ReporteDeleteView.as_view(), name='reporte-delete'),

    # Incidente
    path('incidentes/', IncidenteListView.as_view(), name='incidente-list'),
    path('incidente/<int:pk>/', IncidenteDetailView.as_view(), name='incidente-detail'),
    path('incidente/nuevo/', IncidenteCreateView.as_view(), name='incidente-create'),
    path('incidente/<int:pk>/editar/', IncidenteUpdateView.as_view(), name='incidente-update'),
    path('incidente/<int:pk>/eliminar/', IncidenteDeleteView.as_view(), name='incidente-delete'),

    # MedidaIncidente
    path('medidas-incidente/', MedidaIncidenteListView.as_view(), name='medidaincidente-list'),
    path('medida-incidente/<int:pk>/', MedidaIncidenteDetailView.as_view(), name='medidaincidente-detail'),
    path('medida-incidente/nueva/', MedidaIncidenteCreateView.as_view(), name='medidaincidente-create'),
    path('medida-incidente/<int:pk>/editar/', MedidaIncidenteUpdateView.as_view(), name='medidaincidente-update'),
    path('medida-incidente/<int:pk>/eliminar/', MedidaIncidenteDeleteView.as_view(), name='medidaincidente-delete'),

    # Involucrado
    path('involucrados/', InvolucradoListView.as_view(), name='involucrado-list'),
    path('involucrado/<int:pk>/', InvolucradoDetailView.as_view(), name='involucrado-detail'),
    path('involucrado/nuevo/', InvolucradoCreateView.as_view(), name='involucrado-create'),
    path('involucrado/<int:pk>/editar/', InvolucradoUpdateView.as_view(), name='involucrado-update'),
    path('involucrado/<int:pk>/eliminar/', InvolucradoDeleteView.as_view(), name='involucrado-delete'),

    # InvolucradoIncidente
    path('involucrados-incidente/', InvolucradoIncidenteListView.as_view(), name='involucradoincidente-list'),
    path('involucrado-incidente/<int:pk>/', InvolucradoIncidenteDetailView.as_view(), name='involucradoincidente-detail'),
    path('involucrado-incidente/nuevo/', InvolucradoIncidenteCreateView.as_view(), name='involucradoincidente-create'),
    path('involucrado-incidente/<int:pk>/editar/', InvolucradoIncidenteUpdateView.as_view(), name='involucradoincidente-update'),
    path('involucrado-incidente/<int:pk>/eliminar/', InvolucradoIncidenteDeleteView.as_view(), name='involucradoincidente-delete'),
    
    # Métricas del Dashboard
    path('api/metrics/', dashboard_metrics, name='dashboard-metrics'),
    path('api/timeline/', incidentes_timeline, name='incidentes-timeline'),

    # Reporte Externo (público, sin autenticación)
    path('reporte_externo/', reporte_externo, name='reporte-externo'),
]