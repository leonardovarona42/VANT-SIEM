from django.urls import path, include
from soar_app import views

urlpatterns = [
    path('api/health/', views.health_check, name='health_check'),
    path('api/', include('soar_app.urls')),
]
