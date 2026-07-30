from django.urls import path, include
from intelligence_app import views

urlpatterns = [
    path('api/health/', views.health_check, name='health_check'),
    path('api/', include('intelligence_app.urls')),
]
