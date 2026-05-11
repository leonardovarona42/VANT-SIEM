from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.utils import timezone
from django.core.paginator import Paginator
from .models import Notification, UserPermission, UserApprovalRequest, NotificationPreference, EmailConfiguration, NotificationSettings, NotificationChannel, NotificationTemplate, NotificationLog, NotificationQueue, LDAPConfig
from .logging_system import event_logger
from .email_service import send_user_alert
import ssl
try:
    from ldap3 import Server, Connection, ALL, Tls, SUBTREE
except Exception:
    Server = Connection = Tls = SUBTREE = None


def _ldap_authenticate(username, password):
    if not username or not password:
        return None, 'Credenciales incompletas'
    if Server is None or Connection is None:
        return None, 'LDAP no disponible (instala ldap3)'

    config = LDAPConfig.objects.filter(is_active=True).order_by('-is_default', '-updated_at').first()
    if not config:
        return None, 'LDAP deshabilitado'

    use_ssl = bool(config.use_ssl)
    tls = None
    if use_ssl or config.use_starttls:
        if config.cert_path:
            tls = Tls(ca_certs_file=config.cert_path, validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT)
        else:
            tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)

    server = Server(config.servidor, port=int(config.puerto or 389), use_ssl=use_ssl, tls=tls, get_info=ALL)

    try:
        conn = Connection(server, user=config.bind_dn or None, password=config.bind_password or None, auto_bind=False)
        conn.open()
        if config.use_starttls and not use_ssl:
            conn.start_tls()
        conn.bind()
    except Exception as exc:
        return None, f'LDAP bind fallido: {exc}'

    search_filter = (config.user_search_filter or '(uid={username})').replace('{username}', username)
    try:
        conn.search(search_base=config.user_search_base, search_filter=search_filter, search_scope=SUBTREE,
                    attributes=[config.username_attr, config.first_name_attr, config.last_name_attr, config.email_attr])
    except Exception as exc:
        return None, f'LDAP search fallido: {exc}'

    if not conn.entries:
        return None, 'Usuario LDAP no encontrado'

    entry = conn.entries[0]
    user_dn = entry.entry_dn

    try:
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=False)
        user_conn.open()
        if config.use_starttls and not use_ssl:
            user_conn.start_tls()
        user_conn.bind()
    except Exception:
        return None, 'Credenciales LDAP invalidas'

    def _get_attr(name, fallback=''):
        try:
            val = entry[name].value
            return val or fallback
        except Exception:
            return fallback

    mapped_username = _get_attr(config.username_attr, username) or username
    first_name = _get_attr(config.first_name_attr, '')
    last_name = _get_attr(config.last_name_attr, '')
    email = _get_attr(config.email_attr, '')

    user = User.objects.filter(username=mapped_username).first()
    if not user:
        if not config.auto_create_user:
            return None, 'Usuario no existe en el sistema'
        user = User.objects.create(username=mapped_username, first_name=first_name or '', last_name=last_name or '', email=email or '', is_active=True)
        user.set_unusable_password()
        user.save(update_fields=['password'])
    else:
        updated = False
        if first_name and user.first_name != first_name:
            user.first_name = first_name; updated = True
        if last_name and user.last_name != last_name:
            user.last_name = last_name; updated = True
        if email and user.email != email:
            user.email = email; updated = True
        if updated:
            user.save(update_fields=['first_name', 'last_name', 'email'])

    return user, None


@login_required
def dashboard_view(request):
    return render(request, 'dashboard.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = None
        ldap_error = None
        ldap_cfg = LDAPConfig.objects.filter(is_active=True).order_by('-is_default', '-updated_at').first()
        if ldap_cfg:
            user, ldap_error = _ldap_authenticate(username, password)
        if user is None:
            user = authenticate(request, username=username, password=password)

        if user is not None:
            if not user.is_superuser:
                has_login_perm = UserPermission.objects.filter(user=user, permission_type='CAN_LOGIN', granted=True).exists()
                if not has_login_perm:
                    messages.error(request, 'Tu cuenta no tiene permiso para autenticarse. Contacta a un administrador.')
                    return render(request, 'login.html')
            login(request, user)
            storage = messages.get_messages(request)
            for _ in storage:
                pass
            event_logger.log_event(user=user, event_type='LOGIN', description=f'Usuario {user.username} inicio sesion', details={'ip_address': request.META.get('REMOTE_ADDR')})
            return redirect('dashboard')
        else:
            event_logger.log_event(user=None, event_type='LOGIN_FAILED', description=f'Intento de login fallido para usuario: {username}', details={'ip_address': request.META.get('REMOTE_ADDR')})
            if ldap_cfg and ldap_error:
                messages.error(request, ldap_error)
            else:
                messages.error(request, 'Credenciales invalidas')

    return render(request, 'login.html')


def logout_view(request):
    user = request.user
    logout(request)
    event_logger.log_event(user=user, event_type='LOGOUT', description=f'Usuario {user.username if user.is_authenticated else "Anonymous"} cerro sesion')
    return redirect('login')


@login_required
def password_change_view(request):
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')
        user = request.user
        if not user.check_password(old_password):
            messages.error(request, 'La contrasena actual es incorrecta.')
            return render(request, 'password_change.html')
        if new_password1 != new_password2:
            messages.error(request, 'Las nuevas contrasenas no coinciden.')
            return render(request, 'password_change.html')
        try:
            from django.contrib.auth.password_validation import validate_password
            validate_password(new_password1, user=user)
        except Exception as e:
            messages.error(request, '; '.join(e.messages) if hasattr(e, 'messages') else str(e))
            return render(request, 'password_change.html')
        user.set_password(new_password1)
        user.save()
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(request, user)
        messages.success(request, 'Contrasena cambiada exitosamente.')
        return redirect('dashboard')
    return render(request, 'password_change.html')


@login_required
def user_management(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta seccion')
        return redirect('dashboard')
    users = User.objects.all().order_by('-date_joined')
    pending_requests = UserApprovalRequest.objects.filter(status='PENDING').order_by('-created_at')
    return render(request, 'user_management.html', {'users': users, 'pending_requests': pending_requests})


@login_required
def create_user_request(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        selected_permissions = request.POST.getlist('permissions')
        if User.objects.filter(username=username).exists():
            messages.error(request, 'El nombre de usuario ya existe')
            return redirect('user-management')
        if UserApprovalRequest.objects.filter(username=username, status='PENDING').exists():
            messages.error(request, 'Ya existe una solicitud pendiente para este usuario')
            return redirect('user-management')
        user_request = UserApprovalRequest.objects.create(requested_by=request.user, username=username, email=email, first_name=first_name, last_name=last_name, password=make_password(password), is_staff=False, is_superuser=False)
        user_request.details = {'requested_permissions': selected_permissions}
        user_request.save()
        event_logger.log_event(user=request.user, event_type='USER_CREATE_REQUEST', description=f'Solicitud de creacion de usuario: {username}', details={'requested_username': username, 'requested_email': email, 'requested_permissions': selected_permissions}, target_model='UserApprovalRequest', target_id=user_request.id)
        messages.success(request, f'Solicitud de creacion de usuario "{username}" enviada para aprobacion')
        return redirect('user-management')
    return render(request, 'create_user_request.html')


@login_required
def approve_user_request(request, request_id):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para realizar esta accion')
        return redirect('user-management')
    user_request = get_object_or_404(UserApprovalRequest, id=request_id, status='PENDING')
    try:
        with transaction.atomic():
            new_user = user_request.approve(request.user)
            if not new_user.is_active:
                new_user.is_active = True
                new_user.save(update_fields=['is_active'])
            NotificationPreference.objects.get_or_create(user=new_user)
            requested_permissions = user_request.details.get('requested_permissions', []) if user_request.details else []
            for perm_type in requested_permissions:
                UserPermission.objects.create(user=new_user, permission_type=perm_type, granted=True, granted_by=request.user)
            if not UserPermission.objects.filter(user=new_user, permission_type='VIEW_DASHBOARD').exists():
                UserPermission.objects.create(user=new_user, permission_type='VIEW_DASHBOARD', granted=True, granted_by=request.user)
            event_logger.log_event(user=request.user, event_type='USER_APPROVED', description=f'Usuario {new_user.username} aprobado y creado', details={'approved_username': new_user.username, 'approved_email': new_user.email, 'assigned_permissions': requested_permissions}, target_model='User', target_id=new_user.id)
            subject = f"VANT-SIEM - Cuenta de Usuario Aprobada"
            body = f"<html><body><h2>Bienvenido a VANT-SIEM!</h2><p>Hola {new_user.first_name},</p><p>Tu solicitud de cuenta de usuario ha sido <strong>aprobada</strong> por {request.user.username}.</p><p>Usuario: {new_user.username}</p><p>Ya puedes acceder al sistema con tus credenciales.</p></body></html>"
            send_user_alert(user=new_user, alert_type='USER_APPROVED', subject=subject, body=body, priority='HIGH')
            messages.success(request, f'Usuario "{new_user.username}" aprobado y creado exitosamente con {len(requested_permissions)} permisos')
    except Exception as e:
        messages.error(request, f'Error al aprobar usuario: {str(e)}')
    return redirect('user-management')


@login_required
def reject_user_request(request, request_id):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para realizar esta accion')
        return redirect('user-management')
    user_request = get_object_or_404(UserApprovalRequest, id=request_id, status='PENDING')
    reason = request.POST.get('reason', '')
    user_request.reject(request.user, reason)
    event_logger.log_event(user=request.user, event_type='USER_REJECTED', description=f'Solicitud de usuario {user_request.username} rechazada', details={'rejected_username': user_request.username, 'reason': reason}, target_model='UserApprovalRequest', target_id=user_request.id)
    messages.success(request, f'Solicitud de usuario "{user_request.username}" rechazada')
    return redirect('user-management')


@login_required
def user_permissions(request, user_id):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta seccion')
        return redirect('dashboard')
    user = get_object_or_404(User, id=user_id)
    permissions = UserPermission.objects.filter(user=user)
    existing_permissions = set(perm.permission_type for perm in permissions)
    all_permission_types = [choice[0] for choice in UserPermission.PERMISSION_TYPES]
    for perm_type in all_permission_types:
        if perm_type not in existing_permissions:
            UserPermission.objects.create(user=user, permission_type=perm_type, granted=False)
    permissions = UserPermission.objects.filter(user=user).order_by('permission_type')
    return render(request, 'user_permissions.html', {'target_user': user, 'permissions': permissions})


@login_required
@require_http_methods(["POST"])
def update_user_permission(request, user_id, permission_id):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    permission = get_object_or_404(UserPermission, id=permission_id, user_id=user_id)
    granted = request.POST.get('granted') == 'true'
    permission.granted = granted
    permission.granted_by = request.user
    permission.save()
    event_logger.log_event(user=request.user, event_type='PERMISSION_CHANGED', description=f'Permiso {permission.get_permission_type_display()} {"otorgado" if granted else "revocado"} a {permission.user.username}', details={'target_user': permission.user.username, 'permission_type': permission.permission_type, 'granted': granted}, target_model='UserPermission', target_id=permission.id)
    return JsonResponse({'success': True})


@login_required
def notifications(request):
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'notifications.html', {'notifications': notifications})


@login_required
@require_http_methods(["GET"])
def get_notifications(request):
    unread_count = Notification.objects.filter(user=request.user, is_read=False).count()
    recent_notifications = Notification.objects.filter(user=request.user).order_by('-created_at')[:5]
    notifications_data = []
    for notification in recent_notifications:
        notifications_data.append({'id': notification.id, 'title': notification.title, 'message': notification.message, 'event_type': notification.event_type, 'is_read': notification.is_read, 'created_at': notification.created_at.strftime('%d/%m/%Y %H:%M')})
    return JsonResponse({'unread_count': unread_count, 'notifications': notifications_data})


@login_required
@require_http_methods(["POST"])
def mark_notification_read(request, notification_id):
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    notification.mark_as_read()
    return JsonResponse({'success': True})


@login_required
@require_http_methods(["POST"])
def mark_all_notifications_read(request):
    Notification.objects.filter(user=request.user, is_read=False).update(is_read=True, read_at=timezone.now())
    return JsonResponse({'success': True})


@login_required
def system_logs(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta seccion')
        return redirect('dashboard')
    event_type = request.GET.get('event_type', '')
    user_id = request.GET.get('user_id', '')
    limit = int(request.GET.get('limit', 100))
    logs = event_logger.get_recent_events(limit)
    if event_type:
        logs = [log for log in logs if log['event_type'] == event_type]
    if user_id:
        logs = [log for log in logs if log['user']['id'] == int(user_id)]
    users = User.objects.all().order_by('username')
    event_types = set()
    for log in event_logger.get_recent_events(1000):
        event_types.add(log['event_type'])
    event_types = sorted(list(event_types))
    return render(request, 'system_logs.html', {'logs': logs, 'users': users, 'event_types': event_types, 'current_event_type': event_type, 'current_user_id': user_id, 'current_limit': limit})


@login_required
def logging_control(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta seccion')
        return redirect('dashboard')
    status, message = event_logger.get_logging_status(request.user)
    return render(request, 'logging_control.html', {'logging_status': status, 'status_message': message})


@login_required
@require_http_methods(["POST"])
def start_logging_system(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    success, message = event_logger.start_logging(request.user)
    return JsonResponse({'success': success, 'message': message})


@login_required
@require_http_methods(["POST"])
def stop_logging_system(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    success, message = event_logger.stop_logging(request.user)
    return JsonResponse({'success': success, 'message': message})


@login_required
@require_http_methods(["GET"])
def get_logging_status_api(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    status, message = event_logger.get_logging_status(request.user)
    return JsonResponse({'success': True, 'status': status, 'message': message})


@login_required
def email_configuration(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta seccion')
        return redirect('dashboard')
    configs = EmailConfiguration.objects.all()
    active_config = configs.filter(is_active=True).first()
    return render(request, 'email_configuration.html', {'configs': configs, 'active_config': active_config})


@login_required
def create_email_config(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para realizar esta accion')
        return redirect('email-configuration')
    if request.method == 'POST':
        name = request.POST.get('name')
        smtp_server = request.POST.get('smtp_server')
        smtp_port = int(request.POST.get('smtp_port', 587))
        use_tls = request.POST.get('use_tls') == 'on'
        use_ssl = request.POST.get('use_ssl') == 'on'
        username = request.POST.get('username')
        password = request.POST.get('password')
        from_email = request.POST.get('from_email')
        from_name = request.POST.get('from_name', 'VANT-SIEM')
        is_active = request.POST.get('is_active') == 'on'
        if is_active:
            EmailConfiguration.objects.filter(is_active=True).update(is_active=False)
        try:
            config = EmailConfiguration.objects.create(name=name, smtp_server=smtp_server, smtp_port=smtp_port, use_tls=use_tls, use_ssl=use_ssl, username=username, password=password, from_email=from_email, from_name=from_name, is_active=is_active, created_by=request.user)
            event_logger.log_event(user=request.user, event_type='EMAIL_CONFIG_CREATED', description=f'Configuracion de correo creada: {name}', details={'config_name': name, 'smtp_server': smtp_server, 'from_email': from_email, 'is_active': is_active}, target_model='EmailConfiguration', target_id=config.id)
            messages.success(request, f'Configuracion de correo "{name}" creada exitosamente')
            return redirect('email-configuration')
        except Exception as e:
            messages.error(request, f'Error al crear configuracion: {str(e)}')
    return render(request, 'create_email_config.html')


@login_required
@require_http_methods(["POST"])
def activate_email_config(request, config_id):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    config = get_object_or_404(EmailConfiguration, id=config_id)
    try:
        EmailConfiguration.objects.filter(is_active=True).update(is_active=False)
        config.is_active = True
        config.save()
        event_logger.log_event(user=request.user, event_type='EMAIL_CONFIG_ACTIVATED', description=f'Configuracion de correo activada: {config.name}', details={'config_name': config.name}, target_model='EmailConfiguration', target_id=config.id)
        return JsonResponse({'success': True, 'message': f'Configuracion "{config.name}" activada'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
def edit_email_config(request, config_id):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para realizar esta accion')
        return redirect('email-configuration')
    config = get_object_or_404(EmailConfiguration, id=config_id)
    if request.method == 'POST':
        name = request.POST.get('name')
        smtp_server = request.POST.get('smtp_server')
        smtp_port = int(request.POST.get('smtp_port', config.smtp_port or 587))
        use_tls = request.POST.get('use_tls') == 'on'
        use_ssl = request.POST.get('use_ssl') == 'on'
        username = request.POST.get('username')
        password = request.POST.get('password') or config.password
        from_email = request.POST.get('from_email')
        from_name = request.POST.get('from_name', config.from_name or 'VANT-SIEM')
        is_active = request.POST.get('is_active') == 'on'
        if is_active:
            EmailConfiguration.objects.exclude(id=config.id).filter(is_active=True).update(is_active=False)
        try:
            config.name = name
            config.smtp_server = smtp_server
            config.smtp_port = smtp_port
            config.use_tls = use_tls
            config.use_ssl = use_ssl
            config.username = username
            config.password = password
            config.from_email = from_email
            config.from_name = from_name
            config.is_active = is_active
            config.save()
            event_logger.log_event(user=request.user, event_type='EMAIL_CONFIG_UPDATED', description=f'Configuracion de correo actualizada: {name}', details={'config_name': name, 'smtp_server': smtp_server, 'from_email': from_email, 'is_active': is_active}, target_model='EmailConfiguration', target_id=config.id)
            messages.success(request, f'Configuracion de correo "{name}" actualizada exitosamente')
            return redirect('email-configuration')
        except Exception as e:
            messages.error(request, f'Error al actualizar configuracion: {str(e)}')
    return render(request, 'edit_email_config.html', {'config': config})


@login_required
@require_http_methods(["POST"])
def test_email_config(request, config_id):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    try:
        from .email_service import email_service
        success, message = email_service.test_configuration(config_id)
        return JsonResponse({'success': success, 'message': message})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_http_methods(["POST"])
def save_notification_settings(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    try:
        settings_obj, _ = NotificationSettings.objects.get_or_create(id=1)
        settings_obj.enabled = request.POST.get('enabled') == 'true'
        settings_obj.save()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_http_methods(["POST"])
def add_notification_channel(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    try:
        channel = NotificationChannel.objects.create(name=request.POST.get('name', ''), channel_type=request.POST.get('channel_type', ''), config={})
        return JsonResponse({'success': True, 'id': channel.id})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_http_methods(["POST"])
def add_notification_template(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    try:
        template = NotificationTemplate.objects.create(name=request.POST.get('name', ''), content=request.POST.get('content', ''))
        return JsonResponse({'success': True, 'id': template.id})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_http_methods(["POST"])
def delete_notification_channel(request, channel_id):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    try:
        NotificationChannel.objects.filter(id=channel_id).delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_http_methods(["POST"])
def delete_notification_template(request, template_id):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    try:
        NotificationTemplate.objects.filter(id=template_id).delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_GET
def get_notification_stats(request):
    total = Notification.objects.count()
    unread = Notification.objects.filter(is_read=False).count()
    return JsonResponse({'total': total, 'unread': unread})


@login_required
@require_http_methods(["POST"])
def test_notification_channel(request, channel_id):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    return JsonResponse({'success': True, 'message': 'Test enviado'})


@login_required
@require_http_methods(["POST"])
def toggle_notification_channel(request, channel_id):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    try:
        channel = NotificationChannel.objects.get(id=channel_id)
        channel.enabled = not channel.enabled
        channel.save()
        return JsonResponse({'success': True, 'enabled': channel.enabled})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_http_methods(["POST"])
def cleanup_notifications(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    try:
        deleted, _ = Notification.objects.filter(is_read=True, created_at__lt=timezone.now() - timezone.timedelta(days=30)).delete()
        return JsonResponse({'success': True, 'deleted': deleted})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_GET
def notification_queue_status(request):
    return JsonResponse({'pending': 0, 'processed': 0, 'failed': 0})


@login_required
def ldap_config_list(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta seccion')
        return redirect('dashboard')
    configs = LDAPConfig.objects.all()
    return render(request, 'ldap_config_list.html', {'configs': configs})


@login_required
def ldap_config_create(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta seccion')
        return redirect('dashboard')
    if request.method == 'POST':
        config = LDAPConfig.objects.create(
            nombre=request.POST.get('nombre'),
            servidor=request.POST.get('servidor'),
            puerto=request.POST.get('puerto', 389),
            use_ssl=request.POST.get('use_ssl') == 'on',
            use_starttls=request.POST.get('use_starttls') == 'on',
            cert_path=request.POST.get('cert_path') or None,
            bind_dn=request.POST.get('bind_dn') or None,
            bind_password=request.POST.get('bind_password') or None,
            user_search_base=request.POST.get('user_search_base'),
            user_search_filter=request.POST.get('user_search_filter') or '(uid={username})',
            group_search_base=request.POST.get('group_search_base') or None,
            group_search_filter=request.POST.get('group_search_filter') or '(member={user_dn})',
            username_attr=request.POST.get('username_attr') or 'uid',
            first_name_attr=request.POST.get('first_name_attr') or 'givenName',
            last_name_attr=request.POST.get('last_name_attr') or 'sn',
            email_attr=request.POST.get('email_attr') or 'mail',
            is_active=request.POST.get('is_active') == 'on',
            is_default=request.POST.get('is_default') == 'on',
            auto_create_user=request.POST.get('auto_create_user') == 'on',
        )
        messages.success(request, f'Configuracion LDAP "{config.nombre}" creada exitosamente.')
        return redirect('ldap-config-list')
    return render(request, 'ldap_config_form.html', {'action': 'create'})


@login_required
def ldap_config_edit(request, config_id):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta seccion')
        return redirect('dashboard')
    config = get_object_or_404(LDAPConfig, id=config_id)
    if request.method == 'POST':
        config.nombre = request.POST.get('nombre')
        config.servidor = request.POST.get('servidor')
        config.puerto = request.POST.get('puerto', 389)
        config.use_ssl = request.POST.get('use_ssl') == 'on'
        config.use_starttls = request.POST.get('use_starttls') == 'on'
        config.cert_path = request.POST.get('cert_path') or None
        config.bind_dn = request.POST.get('bind_dn') or None
        config.bind_password = request.POST.get('bind_password') or None
        config.user_search_base = request.POST.get('user_search_base')
        config.user_search_filter = request.POST.get('user_search_filter') or '(uid={username})'
        config.group_search_base = request.POST.get('group_search_base') or None
        config.group_search_filter = request.POST.get('group_search_filter') or '(member={user_dn})'
        config.username_attr = request.POST.get('username_attr') or 'uid'
        config.first_name_attr = request.POST.get('first_name_attr') or 'givenName'
        config.last_name_attr = request.POST.get('last_name_attr') or 'sn'
        config.email_attr = request.POST.get('email_attr') or 'mail'
        config.is_active = request.POST.get('is_active') == 'on'
        config.is_default = request.POST.get('is_default') == 'on'
        config.auto_create_user = request.POST.get('auto_create_user') == 'on'
        config.save()
        messages.success(request, f'Configuracion LDAP "{config.nombre}" actualizada exitosamente.')
        return redirect('ldap-config-list')
    return render(request, 'ldap_config_form.html', {'action': 'edit', 'config': config})


@login_required
def ldap_config_delete(request, config_id):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta seccion')
        return redirect('dashboard')
    try:
        config = LDAPConfig.objects.get(id=config_id)
        nombre = config.nombre
        config.delete()
        messages.success(request, f'Configuracion LDAP "{nombre}" eliminada exitosamente.')
    except LDAPConfig.DoesNotExist:
        messages.error(request, 'Configuracion no encontrada')
    return redirect('ldap-config-list')
