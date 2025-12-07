import logging
from django.shortcuts import render
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.contrib import messages
from django.shortcuts import redirect
from django.http import JsonResponse
from django.utils import timezone
from django.urls import reverse
from datetime import datetime, timedelta
from .models import (
    Categoria, Subcategoria, Servicio, Responsable, Area,
    Medida, Reporte, Incidente, MedidaIncidente,
    Involucrado, InvolucradoIncidente
)
from VANT_SIEM.email_service import send_system_alert
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_http_methods

logger = logging.getLogger(__name__)

# Categoria
class CategoriaListView(ListView):
    model = Categoria
    template_name = 'categoria_list.html'
    paginate_by = 10
    context_object_name = 'object_list'

    def get_queryset(self):
        queryset = super().get_queryset()
        q = self.request.GET.get('q')
        if q:
            queryset = queryset.filter(
                Q(nombre__icontains=q) |
                Q(descripcion__icontains=q) |
                Q(id__icontains=q)
            )
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['search_query'] = self.request.GET.get('q', '')
        return context

    def render_to_response(self, context, **response_kwargs):
        # Check if this is an AJAX request
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # Return JSON data for AJAX requests
            categorias_data = []
            for categoria in context['object_list']:
                categorias_data.append({
                    'id': categoria.id,
                    'nombre': categoria.nombre,
                    'descripcion': categoria.descripcion,
                    'detail_url': reverse('categoria-detail', args=[categoria.id]),
                    'update_url': reverse('categoria-update', args=[categoria.id]),
                    'delete_url': reverse('categoria-delete', args=[categoria.id])
                })

            data = {
                'categorias': categorias_data,
                'has_next': context['page_obj'].has_next(),
                'has_previous': context['page_obj'].has_previous(),
                'current_page': context['page_obj'].number,
                'total_pages': context['page_obj'].paginator.num_pages,
                'total_count': context['paginator'].count
            }
            return JsonResponse(data)
        else:
            # Return normal HTML response
            return super().render_to_response(context, **response_kwargs)

class CategoriaDetailView(DetailView):
    model = Categoria
    template_name = 'categoria_detail.html'

class CategoriaCreateView(CreateView):
    model = Categoria
    fields = '__all__'
    success_url = reverse_lazy('categoria-list')
    template_name = 'categoria_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Categoría "{self.object.nombre}" creada exitosamente.')
        return response

class CategoriaUpdateView(UpdateView):
    model = Categoria
    fields = '__all__'
    success_url = reverse_lazy('categoria-list')
    template_name = 'categoria_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Categoría "{self.object.nombre}" actualizada exitosamente.')
        return response

class CategoriaDeleteView(DeleteView):
    model = Categoria
    success_url = reverse_lazy('categoria-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Categoría'
        context['cancel_url'] = reverse_lazy('categoria-list')
        return context

    def delete(self, request, *args, **kwargs):
        categoria_nombre = self.get_object().nombre
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Categoría "{categoria_nombre}" eliminada exitosamente.')
        return response

# Subcategoria
class SubcategoriaListView(ListView):
    model = Subcategoria
    template_name = 'subcategoria_list.html'
    paginate_by = 10
    context_object_name = 'object_list'

    def get_queryset(self):
        queryset = super().get_queryset()
        q = self.request.GET.get('q')
        if q:
            queryset = queryset.filter(
                Q(nombre__icontains=q) |
                Q(descripcion__icontains=q) |
                Q(categoria__nombre__icontains=q) |
                Q(id__icontains=q) |
                Q(nivel_peligrosidad__icontains=q)
            )
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['search_query'] = self.request.GET.get('q', '')
        return context

    def render_to_response(self, context, **response_kwargs):
        # Check if this is an AJAX request
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # Return JSON data for AJAX requests
            subcategorias_data = []
            for subcategoria in context['object_list']:
                subcategorias_data.append({
                    'id': subcategoria.id,
                    'nombre': subcategoria.nombre,
                    'categoria': subcategoria.categoria.nombre,
                    'nivel_peligrosidad': subcategoria.nivel_peligrosidad,
                    'descripcion': subcategoria.descripcion,
                    'detail_url': reverse('subcategoria-detail', args=[subcategoria.id]),
                    'update_url': reverse('subcategoria-update', args=[subcategoria.id]),
                    'delete_url': reverse('subcategoria-delete', args=[subcategoria.id])
                })

            data = {
                'subcategorias': subcategorias_data,
                'has_next': context['page_obj'].has_next(),
                'has_previous': context['page_obj'].has_previous(),
                'current_page': context['page_obj'].number,
                'total_pages': context['page_obj'].paginator.num_pages,
                'total_count': context['paginator'].count
            }
            return JsonResponse(data)
        else:
            # Return normal HTML response
            return super().render_to_response(context, **response_kwargs)

class SubcategoriaDetailView(DetailView):
    model = Subcategoria
    template_name = 'subcategoria_detail.html'

class SubcategoriaCreateView(CreateView):
    model = Subcategoria
    fields = '__all__'
    success_url = reverse_lazy('subcategoria-list')
    template_name = 'subcategoria_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Subcategoría "{self.object.nombre}" creada exitosamente.')
        return response

class SubcategoriaUpdateView(UpdateView):
    model = Subcategoria
    fields = '__all__'
    success_url = reverse_lazy('subcategoria-list')
    template_name = 'subcategoria_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Subcategoría "{self.object.nombre}" actualizada exitosamente.')
        return response

class SubcategoriaDeleteView(DeleteView):
    model = Subcategoria
    success_url = reverse_lazy('subcategoria-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Subcategoría'
        context['cancel_url'] = reverse_lazy('subcategoria-list')
        return context

    def delete(self, request, *args, **kwargs):
        subcategoria_nombre = self.get_object().nombre
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Subcategoría "{subcategoria_nombre}" eliminada exitosamente.')
        return response

# Servicio
class ServicioListView(ListView):
    model = Servicio
    template_name = 'servicio_list.html'
    paginate_by = 10
    context_object_name = 'object_list'

    def get_queryset(self):
        queryset = super().get_queryset()
        q = self.request.GET.get('q')
        if q:
            queryset = queryset.filter(
                Q(nombre__icontains=q) |
                Q(descripcion__icontains=q) |
                Q(host__icontains=q) |
                Q(id__icontains=q) |
                Q(monitorear__icontains=q)
            )
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['search_query'] = self.request.GET.get('q', '')
        return context

    def render_to_response(self, context, **response_kwargs):
        # Check if this is an AJAX request
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # Return JSON data for AJAX requests
            servicios_data = []
            for servicio in context['object_list']:
                servicios_data.append({
                    'id': servicio.id,
                    'nombre': servicio.nombre,
                    'descripcion': servicio.descripcion,
                    'host': servicio.host or 'N/A',
                    'monitorear': servicio.monitorear,
                    'detail_url': reverse('servicio-detail', args=[servicio.id]),
                    'update_url': reverse('servicio-update', args=[servicio.id]),
                    'delete_url': reverse('servicio-delete', args=[servicio.id])
                })

            data = {
                'servicios': servicios_data,
                'has_next': context['page_obj'].has_next(),
                'has_previous': context['page_obj'].has_previous(),
                'current_page': context['page_obj'].number,
                'total_pages': context['page_obj'].paginator.num_pages,
                'total_count': context['paginator'].count
            }
            return JsonResponse(data)
        else:
            # Return normal HTML response
            return super().render_to_response(context, **response_kwargs)

class ServicioDetailView(DetailView):
    model = Servicio
    template_name = 'servicio_detail.html'

class ServicioCreateView(CreateView):
    model = Servicio
    fields = '__all__'
    success_url = reverse_lazy('servicio-list')
    template_name = 'servicio_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Servicio "{self.object.nombre}" creado exitosamente.')
        return response

class ServicioUpdateView(UpdateView):
    model = Servicio
    fields = '__all__'
    success_url = reverse_lazy('servicio-list')
    template_name = 'servicio_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Servicio "{self.object.nombre}" actualizado exitosamente.')
        return response

class ServicioDeleteView(DeleteView):
    model = Servicio
    success_url = reverse_lazy('servicio-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Servicio'
        context['cancel_url'] = reverse_lazy('servicio-list')
        return context

    def delete(self, request, *args, **kwargs):
        servicio_nombre = self.get_object().nombre
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Servicio "{servicio_nombre}" eliminado exitosamente.')
        return response

# Responsable
class ResponsableListView(ListView):
    model = Responsable
    template_name = 'responsable_list.html'
    paginate_by = 10
    context_object_name = 'object_list'

    def get_queryset(self):
        queryset = super().get_queryset()
        q = self.request.GET.get('q')
        if q:
            queryset = queryset.filter(
                Q(nombres__icontains=q) |
                Q(apellidos__icontains=q) |
                Q(email__icontains=q) |
                Q(telefono_particular__icontains=q) |
                Q(telefono_corp__icontains=q) |
                Q(tipo__icontains=q) |
                Q(descripcion__icontains=q) |
                Q(id__icontains=q)
            )
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['search_query'] = self.request.GET.get('q', '')
        return context

    def render_to_response(self, context, **response_kwargs):
        # Check if this is an AJAX request
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # Return JSON data for AJAX requests
            responsables_data = []
            for responsable in context['object_list']:
                responsables_data.append({
                    'id': responsable.id,
                    'nombres': responsable.nombres,
                    'apellidos': responsable.apellidos,
                    'email': responsable.email,
                    'telefono_particular': responsable.telefono_particular,
                    'telefono_corp': responsable.telefono_corp,
                    'tipo': responsable.tipo,
                    'descripcion': responsable.descripcion,
                    'detail_url': reverse('responsable-detail', args=[responsable.id]),
                    'update_url': reverse('responsable-update', args=[responsable.id]),
                    'delete_url': reverse('responsable-delete', args=[responsable.id])
                })

            data = {
                'responsables': responsables_data,
                'has_next': context['page_obj'].has_next(),
                'has_previous': context['page_obj'].has_previous(),
                'current_page': context['page_obj'].number,
                'total_pages': context['page_obj'].paginator.num_pages,
                'total_count': context['paginator'].count
            }
            return JsonResponse(data)
        else:
            # Return normal HTML response
            return super().render_to_response(context, **response_kwargs)

class ResponsableDetailView(DetailView):
    model = Responsable
    template_name = 'responsable_detail.html'

class ResponsableCreateView(CreateView):
    model = Responsable
    fields = '__all__'
    success_url = reverse_lazy('responsable-list')
    template_name = 'responsable_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        
        # Si es una petición AJAX, devolver JSON
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest' or self.request.content_type == 'application/json':
            return JsonResponse({
                'success': True,
                'responsable_id': self.object.id,
                'nombres': self.object.nombres,
                'apellidos': self.object.apellidos
            })
        
        return response
    
    def form_invalid(self, form):
        # Si es una petición AJAX, devolver JSON con errores
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest' or self.request.content_type == 'application/json':
            return JsonResponse({
                'success': False,
                'error': 'Datos inválidos',
                'errors': form.errors
            })
        
        return super().form_invalid(form)

class ResponsableUpdateView(UpdateView):
    model = Responsable
    fields = '__all__'
    success_url = reverse_lazy('responsable-list')
    template_name = 'responsable_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Responsable "{self.object.nombres} {self.object.apellidos}" actualizado exitosamente.')
        return response

class ResponsableDeleteView(DeleteView):
    model = Responsable
    success_url = reverse_lazy('responsable-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Responsable'
        context['cancel_url'] = reverse_lazy('responsable-list')
        return context

    def delete(self, request, *args, **kwargs):
        responsable_nombre = f"{self.get_object().nombres} {self.get_object().apellidos}"
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Responsable "{responsable_nombre}" eliminado exitosamente.')
        return response

# Area
class AreaListView(ListView):
    model = Area
    template_name = 'area_list.html'
    paginate_by = 10
    context_object_name = 'object_list'

    def get_queryset(self):
        queryset = super().get_queryset()
        q = self.request.GET.get('q')
        if q:
            queryset = queryset.filter(
                Q(nombre__icontains=q) |
                Q(acronimo__icontains=q) |
                Q(cuadro_centro__nombres__icontains=q) |
                Q(cuadro_centro__apellidos__icontains=q) |
                Q(rsi__nombres__icontains=q) |
                Q(rsi__apellidos__icontains=q) |
                Q(admin__nombres__icontains=q) |
                Q(admin__apellidos__icontains=q) |
                Q(id__icontains=q)
            )
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['search_query'] = self.request.GET.get('q', '')
        return context

    def render_to_response(self, context, **response_kwargs):
        # Check if this is an AJAX request
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # Return JSON data for AJAX requests
            areas_data = []
            for area in context['object_list']:
                areas_data.append({
                    'id': area.id,
                    'nombre': area.nombre,
                    'acronimo': area.acronimo,
                    'cuadro_centro': f"{area.cuadro_centro.nombres} {area.cuadro_centro.apellidos}",
                    'rsi': f"{area.rsi.nombres} {area.rsi.apellidos}",
                    'admin': f"{area.admin.nombres} {area.admin.apellidos}",
                    'detail_url': reverse('area-detail', args=[area.id]),
                    'update_url': reverse('area-update', args=[area.id]),
                    'delete_url': reverse('area-delete', args=[area.id])
                })

            data = {
                'areas': areas_data,
                'has_next': context['page_obj'].has_next(),
                'has_previous': context['page_obj'].has_previous(),
                'current_page': context['page_obj'].number,
                'total_pages': context['page_obj'].paginator.num_pages,
                'total_count': context['paginator'].count
            }
            return JsonResponse(data)
        else:
            # Return normal HTML response
            return super().render_to_response(context, **response_kwargs)

class AreaDetailView(DetailView):
    model = Area
    template_name = 'area_detail.html'

class AreaCreateView(CreateView):
    model = Area
    fields = '__all__'
    success_url = reverse_lazy('area-list')
    template_name = 'area_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Área "{self.object.nombre}" creada exitosamente.')
        return response

class AreaUpdateView(UpdateView):
    model = Area
    fields = '__all__'
    success_url = reverse_lazy('area-list')
    template_name = 'area_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Área "{self.object.nombre}" actualizada exitosamente.')
        return response

class AreaDeleteView(DeleteView):
    model = Area
    success_url = reverse_lazy('area-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Área'
        context['cancel_url'] = reverse_lazy('area-list')
        return context

    def delete(self, request, *args, **kwargs):
        area_nombre = self.get_object().nombre
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Área "{area_nombre}" eliminada exitosamente.')
        return response

# Medida
class MedidaListView(ListView):
    model = Medida
    template_name = 'medida_list.html'

class MedidaDetailView(DetailView):
    model = Medida
    template_name = 'medida_detail.html'

class MedidaCreateView(CreateView):
    model = Medida
    fields = '__all__'
    success_url = reverse_lazy('medida-list')
    template_name = 'medida_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        
        # Si es una petición AJAX, devolver JSON
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest' or self.request.content_type == 'application/json':
            return JsonResponse({
                'success': True,
                'medida_id': self.object.id,
                'nombre': self.object.nombre
            })
        
        messages.success(self.request, f'Medida "{self.object.nombre}" creada exitosamente.')
        return response
    
    def form_invalid(self, form):
        # Si es una petición AJAX, devolver JSON con errores
        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest' or self.request.content_type == 'application/json':
            return JsonResponse({
                'success': False,
                'error': 'Datos inválidos',
                'errors': form.errors
            })
        
        return super().form_invalid(form)

class MedidaUpdateView(UpdateView):
    model = Medida
    fields = '__all__'
    success_url = reverse_lazy('medida-list')
    template_name = 'medida_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Medida "{self.object.nombre}" actualizada exitosamente.')
        return response

class MedidaDeleteView(DeleteView):
    model = Medida
    success_url = reverse_lazy('medida-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Medida'
        context['cancel_url'] = reverse_lazy('medida-list')
        return context

    def delete(self, request, *args, **kwargs):
        medida_nombre = self.get_object().nombre
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Medida "{medida_nombre}" eliminada exitosamente.')
        return response

# Reporte
class ReporteListView(ListView):
    model = Reporte
    template_name = 'reportes_list.html'
    context_object_name = 'object_list'
    paginate_by = 10

    def get_queryset(self):
        queryset = super().get_queryset()
        q = self.request.GET.get('q')
        if q:
            queryset = queryset.filter(
                Q(nombre_informante__icontains=q) |
                Q(email_informante__icontains=q) |
                Q(area__nombre__icontains=q) |
                Q(estado_solucion__icontains=q)
            )
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Totales por estado
        totales = (
            Reporte.objects.values('estado_solucion')
            .annotate(total=Count('id'))
        )
        # Diccionario estado: total
        context['totales'] = {t['estado_solucion']: t['total'] for t in totales}
        return context

class ReporteDetailView(DetailView):
    model = Reporte
    template_name = 'reporte_detail.html'

class ReporteCreateView(CreateView):
    model = Reporte
    fields = '__all__'
    success_url = reverse_lazy('reporte-list')
    template_name = 'reporte_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['areas'] = Area.objects.all()
        context['reporte_estado_choices'] = Reporte.ESTADO_SOLUCION_CHOICES
        return context
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Reporte de "{self.object.nombre_informante}" creado exitosamente.')
        try:
            subject = "VANT-SIEM - Nuevo Reporte Creado"
            body = f"""
            <html>
            <body>
                <h3>Nuevo Reporte de Incidente</h3>
                <p><strong>Informante:</strong> {self.object.nombre_informante}</p>
                <p><strong>Área:</strong> {self.object.area.nombre}</p>
                <p><strong>Estado:</strong> {self.object.estado_solucion}</p>
                <p><strong>Fecha:</strong> {self.object.fecha_hora.strftime('%d/%m/%Y %H:%M')}</p>
                <p><strong>Descripción:</strong><br/>{self.object.descripcion}</p>
            </body>
            </html>
            """
            send_system_alert('REPORT_CREATED', subject, body, priority='HIGH')
        except Exception:
            pass
        return response

class ReporteUpdateView(UpdateView):
    model = Reporte
    fields = '__all__'
    success_url = reverse_lazy('reporte-list')
    template_name = 'reporte_form.html'  # Usa el mismo template que el CreateView

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['areas'] = Area.objects.all()
        context['reporte_estado_choices'] = Reporte.ESTADO_SOLUCION_CHOICES
        return context
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Reporte de "{self.object.nombre_informante}" actualizado exitosamente.')
        try:
            subject = "VANT-SIEM - Reporte Actualizado"
            body = f"""
            <html>
            <body>
                <h3>Reporte Actualizado</h3>
                <p><strong>Informante:</strong> {self.object.nombre_informante}</p>
                <p><strong>Área:</strong> {self.object.area.nombre}</p>
                <p><strong>Estado:</strong> {self.object.estado_solucion}</p>
                <p><strong>Fecha:</strong> {timezone.now().strftime('%d/%m/%Y %H:%M')}</p>
                <p><strong>Descripción:</strong><br/>{self.object.descripcion}</p>
            </body>
            </html>
            """
            send_system_alert('REPORT_UPDATED', subject, body, priority='MEDIUM')
        except Exception:
            pass
        return response

class ReporteDeleteView(DeleteView):
    model = Reporte
    success_url = reverse_lazy('reporte-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Reporte'
        context['cancel_url'] = reverse_lazy('reporte-list')
        return context

    def delete(self, request, *args, **kwargs):
        reporte_informante = self.get_object().nombre_informante
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Reporte de "{reporte_informante}" eliminado exitosamente.')
        return response

# Incidente
class IncidenteListView(ListView):
    model = Incidente
    template_name = 'incidentes_list.html'
    paginate_by = 10
    context_object_name = 'object_list'

    def get_queryset(self):
        queryset = super().get_queryset()
        q = self.request.GET.get('q')
        if q:
            queryset = queryset.filter(
                Q(nombre_incidente__icontains=q) |
                Q(descripcion__icontains=q) |
                Q(codigo_incidente__icontains=q) |
                Q(reporte__nombre_informante__icontains=q) |
                Q(reporte__email_informante__icontains=q) |
                Q(reporte__descripcion__icontains=q) |
                Q(servicios__nombre__icontains=q) |
                Q(areas__nombre__icontains=q) |
                Q(subcategorias__nombre__icontains=q) |
                Q(estado_solucion__icontains=q) |
                Q(notificado_osri__icontains=q)
            ).distinct()
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['search_query'] = self.request.GET.get('q', '')
        return context

    def render_to_response(self, context, **response_kwargs):
        # Check if this is an AJAX request
        is_ajax = self.request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        print(f"DEBUG: is_ajax={is_ajax}, headers={dict(self.request.headers)}, GET={dict(self.request.GET)}")
        if is_ajax:
            print(f"DEBUG: Returning JSON for query: {self.request.GET.get('q', 'empty')}")
            # Return JSON data for AJAX requests
            incidents_data = []
            for incident in context['object_list']:
                incidents_data.append({
                    'id': incident.id,
                    'nombre_incidente': incident.nombre_incidente,
                    'descripcion': incident.descripcion,
                    'reporte': f"{incident.reporte.nombre_informante} - {incident.reporte.descripcion[:30]}...",
                    'servicios': ', '.join([s.nombre for s in incident.servicios.all()]),
                    'areas': ', '.join([a.nombre for a in incident.areas.all()]),
                    'subcategorias': ', '.join([s.nombre for s in incident.subcategorias.all()]),
                    'estado_solucion': incident.get_estado_solucion_display(),
                    'estado_class': 'bg-secondary' if incident.estado_solucion == 'nuevo' else 'bg-warning' if incident.estado_solucion == 'abierto' else 'bg-info' if incident.estado_solucion == 'investigacion' else 'bg-danger' if incident.estado_solucion == 'mitigacion' else 'bg-success',
                    'notificado_osri': incident.get_notificado_osri_display(),
                    'notificado_class': 'bg-success' if incident.notificado_osri == 'si' else 'bg-secondary',
                    'fecha_hora': incident.fecha_hora.strftime('%d/%m/%Y %H:%M'),
                    'evidencia_url': incident.evidencia.url if incident.evidencia else None,
                    'detail_url': reverse('incidente-detail', args=[incident.id]),
                    'update_url': reverse('incidente-update', args=[incident.id]),
                    'delete_url': reverse('incidente-delete', args=[incident.id])
                })

            data = {
                'incidents': incidents_data,
                'has_next': context['page_obj'].has_next(),
                'has_previous': context['page_obj'].has_previous(),
                'current_page': context['page_obj'].number,
                'total_pages': context['page_obj'].paginator.num_pages,
                'total_count': context['paginator'].count
            }
            return JsonResponse(data)
        else:
            # Return normal HTML response
            return super().render_to_response(context, **response_kwargs)

class IncidenteDetailView(DetailView):
    model = Incidente
    template_name = 'incidente_detail.html'

class IncidenteCreateView(CreateView):
    model = Incidente
    fields = '__all__'
    template_name = 'incidente_form.html'
    success_url = reverse_lazy('incidente-list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Permitir prefijar un reporte aunque no esté en estado 'Nuevo'
        reporte_pref = self.request.GET.get('reporte')
        if reporte_pref:
            try:
                rp = Reporte.objects.get(pk=int(reporte_pref))
                context['reportes'] = Reporte.objects.filter(estado_solucion='Nuevo') | Reporte.objects.filter(pk=rp.pk)
                context['reporte_prefijado'] = rp.pk
            except Exception:
                context['reportes'] = Reporte.objects.filter(estado_solucion='Nuevo')
        else:
            context['reportes'] = Reporte.objects.filter(estado_solucion='Nuevo')
        context['servicios'] = Servicio.objects.all()
        context['areas'] = Area.objects.all()
        context['subcategorias'] = Subcategoria.objects.all()
        context['incidente_estado_choices'] = Incidente.ESTADO_SOLUCION_CHOICES
        context['notificado_osri_choices'] = Incidente.NOTIFICADO_OSRI_CHOICES
        
        # Para creación, no hay valores seleccionados
        context['selected_servicios'] = []
        context['selected_areas'] = []
        context['selected_subcategorias'] = []
        
        return context
    
    def form_valid(self, form):
        response = super().form_valid(form)
        reporte = self.object.reporte
        reporte.estado_solucion = 'Atendido'
        reporte.save()

        self.object.servicios.set(self.request.POST.getlist('servicios'))
        self.object.areas.set(self.request.POST.getlist('areas'))
        self.object.subcategorias.set(self.request.POST.getlist('subcategorias'))

        messages.success(self.request, f'Incidente "{self.object.nombre_incidente}" creado exitosamente.')

        # Enviar alerta por correo electrónico
        try:
            subject = "VANT-SIEM - Nuevo Incidente Creado"
            body = f"""
            <html>
            <body>
                <h3>Nuevo Incidente Creado</h3>
                <p><strong>Nombre del Incidente:</strong> {self.object.nombre_incidente}</p>
                <p><strong>Código del Incidente:</strong> {self.object.codigo_incidente}</p>
                <p><strong>Reporte Asociado:</strong> {reporte.nombre_informante} ({reporte.email_informante})</p>
                <p><strong>Área:</strong> {', '.join([area.nombre for area in self.object.areas.all()])}</p>
                <p><strong>Servicios Afectados:</strong> {', '.join([servicio.nombre for servicio in self.object.servicios.all()])}</p>
                <p><strong>Subcategorías:</strong> {', '.join([sub.nombre for sub in self.object.subcategorias.all()])}</p>
                <p><strong>Fecha de Creación:</strong> {self.object.fecha_hora.strftime('%d/%m/%Y %H:%M')}</p>
                <p><strong>Descripción:</strong><br/>{self.object.descripcion}</p>
                <p><strong>Estado:</strong> {self.object.get_estado_solucion_display()}</p>
            </body>
            </html>
            """
            send_system_alert('INCIDENT_CREATED', subject, body, priority='CRITICAL')
        except Exception as e:
            # No fallar la creación del incidente si el email falla
            logger.warning(f"Error enviando alerta de incidente creado: {e}")

        return response

class IncidenteUpdateView(UpdateView):
    model = Incidente
    fields = ['nombre_incidente', 'descripcion', 'servicios', 'areas', 'subcategorias', 'evidencia', 'estado_solucion', 'notificado_osri']
    template_name = 'incidente_form.html'
    success_url = reverse_lazy('incidente-list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['reportes'] = Reporte.objects.all()
        context['servicios'] = Servicio.objects.all()
        context['areas'] = Area.objects.all()
        context['subcategorias'] = Subcategoria.objects.all()
        context['incidente_estado_choices'] = Incidente.ESTADO_SOLUCION_CHOICES
        context['notificado_osri_choices'] = Incidente.NOTIFICADO_OSRI_CHOICES
        
        # Obtener los IDs de las relaciones ManyToMany para el template
        if self.object:
            context['selected_servicios'] = list(self.object.servicios.values_list('id', flat=True))
            context['selected_areas'] = list(self.object.areas.values_list('id', flat=True))
            context['selected_subcategorias'] = list(self.object.subcategorias.values_list('id', flat=True))
        
        return context
    
    def form_valid(self, form):
        response = super().form_valid(form)

        # Manejar campos ManyToMany
        self.object.servicios.set(self.request.POST.getlist('servicios'))
        self.object.areas.set(self.request.POST.getlist('areas'))
        self.object.subcategorias.set(self.request.POST.getlist('subcategorias'))

        messages.success(self.request, f'Incidente "{self.object.nombre_incidente}" actualizado exitosamente.')

        # Enviar alerta por correo electrónico si el estado cambió
        try:
            subject = "VANT-SIEM - Incidente Actualizado"
            body = f"""
            <html>
            <body>
                <h3>Incidente Actualizado</h3>
                <p><strong>Nombre del Incidente:</strong> {self.object.nombre_incidente}</p>
                <p><strong>Código del Incidente:</strong> {self.object.codigo_incidente}</p>
                <p><strong>Estado:</strong> {self.object.get_estado_solucion_display()}</p>
                <p><strong>Área:</strong> {', '.join([area.nombre for area in self.object.areas.all()])}</p>
                <p><strong>Servicios Afectados:</strong> {', '.join([servicio.nombre for servicio in self.object.servicios.all()])}</p>
                <p><strong>Fecha de Actualización:</strong> {timezone.now().strftime('%d/%m/%Y %H:%M')}</p>
                <p><strong>Descripción:</strong><br/>{self.object.descripcion}</p>
            </body>
            </html>
            """
            send_system_alert('INCIDENT_UPDATED', subject, body, priority='HIGH')
        except Exception as e:
            # No fallar la actualización del incidente si el email falla
            logger.warning(f"Error enviando alerta de incidente actualizado: {e}")

        return response

class IncidenteDeleteView(DeleteView):
    model = Incidente
    success_url = reverse_lazy('incidente-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Incidente'
        context['cancel_url'] = reverse_lazy('incidente-list')
        return context

    def delete(self, request, *args, **kwargs):
        incidente_nombre = self.get_object().nombre_incidente
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Incidente "{incidente_nombre}" eliminado exitosamente.')
        return response

# MedidaIncidente
class MedidaIncidenteListView(ListView):
    model = MedidaIncidente
    template_name = 'medidaincidente_list.html'

class MedidaIncidenteDetailView(DetailView):
    model = MedidaIncidente
    template_name = 'medidaincidente_detail.html'

class MedidaIncidenteCreateView(CreateView):
    model = MedidaIncidente
    fields = '__all__'
    success_url = reverse_lazy('medidaincidente-list')
    template_name = 'medidaincidente_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Medida de incidente "{self.object.medida.nombre}" creada exitosamente.')
        return response

class MedidaIncidenteUpdateView(UpdateView):
    model = MedidaIncidente
    fields = '__all__'
    success_url = reverse_lazy('medidaincidente-list')
    template_name = 'medidaincidente_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Medida de incidente "{self.object.medida.nombre}" actualizada exitosamente.')
        return response

class MedidaIncidenteDeleteView(DeleteView):
    model = MedidaIncidente
    success_url = reverse_lazy('medidaincidente-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Medida de Incidente'
        context['cancel_url'] = reverse_lazy('medidaincidente-list')
        return context

    def delete(self, request, *args, **kwargs):
        medida_nombre = self.get_object().medida.nombre
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Medida de incidente "{medida_nombre}" eliminada exitosamente.')
        return response

# Involucrado
class InvolucradoListView(ListView):
    model = Involucrado
    template_name = 'involucrado_list.html'

class InvolucradoDetailView(DetailView):
    model = Involucrado
    template_name = 'involucrado_detail.html'

class InvolucradoCreateView(CreateView):
    model = Involucrado
    fields = '__all__'
    success_url = reverse_lazy('involucrado-list')
    template_name = 'involucrado_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Involucrado "{self.object.nombres} {self.object.apellidos}" creado exitosamente.')
        return response

class InvolucradoUpdateView(UpdateView):
    model = Involucrado
    fields = '__all__'
    success_url = reverse_lazy('involucrado-list')
    template_name = 'involucrado_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Involucrado "{self.object.nombres} {self.object.apellidos}" actualizado exitosamente.')
        return response

class InvolucradoDeleteView(DeleteView):
    model = Involucrado
    success_url = reverse_lazy('involucrado-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Involucrado'
        context['cancel_url'] = reverse_lazy('involucrado-list')
        return context

    def delete(self, request, *args, **kwargs):
        involucrado_nombre = f"{self.get_object().nombres} {self.get_object().apellidos}"
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Involucrado "{involucrado_nombre}" eliminado exitosamente.')
        return response

# InvolucradoIncidente
class InvolucradoIncidenteListView(ListView):
    model = InvolucradoIncidente
    template_name = 'involucradoincidente_list.html'

class InvolucradoIncidenteDetailView(DetailView):
    model = InvolucradoIncidente
    template_name = 'involucradoincidente_detail.html'

class InvolucradoIncidenteCreateView(CreateView):
    model = InvolucradoIncidente
    fields = '__all__'
    success_url = reverse_lazy('involucradoincidente-list')
    template_name = 'involucradoincidente_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Involucrado en incidente "{self.object.involucrado.nombres} {self.object.involucrado.apellidos}" creado exitosamente.')
        return response

class InvolucradoIncidenteUpdateView(UpdateView):
    model = InvolucradoIncidente
    fields = '__all__'
    success_url = reverse_lazy('involucradoincidente-list')
    template_name = 'involucradoincidente_form.html'
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, f'Involucrado en incidente "{self.object.involucrado.nombres} {self.object.involucrado.apellidos}" actualizado exitosamente.')
        return response

class InvolucradoIncidenteDeleteView(DeleteView):
    model = InvolucradoIncidente
    success_url = reverse_lazy('involucradoincidente-list')
    template_name = 'generic_confirm_delete.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['object_name'] = 'Involucrado en Incidente'
        context['cancel_url'] = reverse_lazy('involucradoincidente-list')
        return context

    def delete(self, request, *args, **kwargs):
        involucrado_nombre = f"{self.get_object().involucrado.nombres} {self.get_object().involucrado.apellidos}"
        response = super().delete(request, *args, **kwargs)
        messages.success(request, f'Involucrado en incidente "{involucrado_nombre}" eliminado exitosamente.')
        return response

# Vista para reportes externos (sin autenticación requerida)
@csrf_exempt
@require_http_methods(["GET", "POST"])
def reporte_externo(request):
    """Vista pública para que usuarios externos reporten incidentes"""

    if request.method == 'POST':
        try:
            # Crear reporte sin autenticación
            nombre_informante = request.POST.get('nombre_informante', '').strip()
            email_informante = request.POST.get('email_informante', '').strip()
            area_id = request.POST.get('area')
            descripcion = request.POST.get('descripcion', '').strip()

            # Validaciones básicas
            if not nombre_informante or not email_informante or not area_id or not descripcion:
                return render(request, 'reporte_externo.html', {
                    'error': 'Todos los campos son obligatorios.',
                    'areas': Area.objects.all(),
                    'form_data': request.POST
                })

            # Verificar que el área existe
            try:
                area = Area.objects.get(pk=area_id)
            except Area.DoesNotExist:
                return render(request, 'reporte_externo.html', {
                    'error': 'Área seleccionada no válida.',
                    'areas': Area.objects.all(),
                    'form_data': request.POST
                })

            # Crear el reporte
            reporte = Reporte.objects.create(
                nombre_informante=nombre_informante,
                email_informante=email_informante,
                area=area,
                descripcion=descripcion,
                estado_solucion='Nuevo'
            )

            # Enviar notificación por email
            try:
                subject = "VANT-SIEM - Nuevo Reporte Externo"
                body = f"""
                <html>
                <body>
                    <h3>Nuevo Reporte Externo de Incidente</h3>
                    <p><strong>Informante:</strong> {reporte.nombre_informante}</p>
                    <p><strong>Email:</strong> {reporte.email_informante}</p>
                    <p><strong>Área:</strong> {reporte.area.nombre}</p>
                    <p><strong>Fecha:</strong> {reporte.fecha_hora.strftime('%d/%m/%Y %H:%M')}</p>
                    <p><strong>Descripción:</strong><br/>{reporte.descripcion}</p>
                    <hr>
                    <p><em>Reporte enviado desde formulario público</em></p>
                </body>
                </html>
                """
                send_system_alert('REPORT_CREATED', subject, body, priority='HIGH')
            except Exception:
                pass  # No fallar si el email no se puede enviar

            return render(request, 'reporte_externo.html', {
                'success': True,
                'reporte_id': reporte.id,
                'mensaje': f'Su reporte ha sido enviado exitosamente. ID del reporte: {reporte.id}'
            })

        except Exception as e:
            return render(request, 'reporte_externo.html', {
                'error': 'Error al procesar el reporte. Por favor, inténtelo nuevamente.',
                'areas': Area.objects.all(),
                'form_data': request.POST
            })

    # GET request - mostrar formulario
    return render(request, 'reporte_externo.html', {
        'areas': Area.objects.all()
    })

# Vistas para métricas del dashboard SIEM
def dashboard_metrics(request):
    """Vista para obtener métricas generales del dashboard"""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)
    
    # Métricas principales
    total_reportes = Reporte.objects.count()
    total_incidentes = Incidente.objects.count()
    total_involucrados = Involucrado.objects.count()
    total_areas = Area.objects.count()
    
    # Reportes por estado
    reportes_por_estado = list(Reporte.objects.values('estado_solucion').annotate(
        total=Count('id')
    ).values('estado_solucion', 'total'))
    
    # Incidentes por estado
    incidentes_por_estado = list(Incidente.objects.values('estado_solucion').annotate(
        total=Count('id')
    ).values('estado_solucion', 'total'))
    
    # Reportes de las últimas 24 horas
    reportes_24h = Reporte.objects.filter(fecha_hora__gte=last_24h).count()
    incidentes_24h = Incidente.objects.filter(fecha_hora__gte=last_24h).count()
    
    # Reportes por día (últimos 7 días)
    reportes_por_dia = []
    for i in range(7):
        fecha = now - timedelta(days=i)
        inicio_dia = fecha.replace(hour=0, minute=0, second=0, microsecond=0)
        fin_dia = inicio_dia + timedelta(days=1)
        
        count = Reporte.objects.filter(
            fecha_hora__gte=inicio_dia,
            fecha_hora__lt=fin_dia
        ).count()
        
        reportes_por_dia.append({
            'fecha': inicio_dia.strftime('%Y-%m-%d'),
            'dia': inicio_dia.strftime('%a'),
            'total': count
        })
    
    reportes_por_dia.reverse()  # Ordenar cronológicamente
    
    # Incidentes por área
    incidentes_por_area = list(Incidente.objects.values('areas__nombre').annotate(
        total=Count('id')
    ).filter(total__gt=0).values('areas__nombre', 'total'))
    
    # Nivel de peligrosidad de subcategorías
    peligrosidad_stats = list(Subcategoria.objects.aggregate(
        promedio_peligrosidad=Count('nivel_peligrosidad'),
        max_peligrosidad=Count('nivel_peligrosidad'),
        min_peligrosidad=Count('nivel_peligrosidad')
    ))
    
    # Medidas de incidente por estado
    medidas_cumplidas = MedidaIncidente.objects.filter(estado_cumplimiento=True).count()
    medidas_pendientes = MedidaIncidente.objects.filter(estado_cumplimiento=False).count()
    
    return JsonResponse({
        'success': True,
        'metricas': {
            'totales': {
                'reportes': total_reportes,
                'incidentes': total_incidentes,
                'involucrados': total_involucrados,
                'areas': total_areas
            },
            'ultimas_24h': {
                'reportes': reportes_24h,
                'incidentes': incidentes_24h
            },
            'reportes_por_estado': reportes_por_estado,
            'incidentes_por_estado': incidentes_por_estado,
            'reportes_por_dia': reportes_por_dia,
            'incidentes_por_area': incidentes_por_area,
            'medidas': {
                'cumplidas': medidas_cumplidas,
                'pendientes': medidas_pendientes
            }
        }
    })

def incidentes_timeline(request):
    """Vista para obtener timeline de incidentes"""
    now = timezone.now()
    last_30d = now - timedelta(days=30)
    
    # Incidentes por día (últimos 30 días)
    timeline_data = []
    for i in range(30):
        fecha = now - timedelta(days=i)
        inicio_dia = fecha.replace(hour=0, minute=0, second=0, microsecond=0)
        fin_dia = inicio_dia + timedelta(days=1)
        
        incidentes = Incidente.objects.filter(
            fecha_hora__gte=inicio_dia,
            fecha_hora__lt=fin_dia
        )
        
        timeline_data.append({
            'fecha': inicio_dia.strftime('%Y-%m-%d'),
            'dia': inicio_dia.strftime('%a'),
            'nuevos': incidentes.filter(estado_solucion='nuevo').count(),
            'abiertos': incidentes.filter(estado_solucion='abierto').count(),
            'investigacion': incidentes.filter(estado_solucion='investigacion').count(),
            'mitigacion': incidentes.filter(estado_solucion='mitigacion').count(),
            'cerrados': incidentes.filter(estado_solucion='cerrado').count(),
            'total': incidentes.count()
        })
    
    timeline_data.reverse()
    
    return JsonResponse({
        'success': True,
        'timeline': timeline_data
    })
