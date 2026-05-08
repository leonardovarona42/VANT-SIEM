from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.shortcuts import redirect
from django.conf import settings
from django.conf.urls.static import static


def root_redirect(request):
    return redirect('login')


urlpatterns = [
    path('', root_redirect),
    path('admin/', admin.site.urls),
    path('siem/login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('siem/dashboard/', include('VANT_SIEM.urls')),
    path('eventos/', include('EVENT_M.urls')),
    path('logs/', include('OPENSEARCH_LOGS.urls')),
    path('inventory/', include('INVENTORY.urls')),
    path('assets/', include('ASSETS.urls')),
    path('dlp/', include('DLP.urls')),
    path('siem/dashboard/logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

