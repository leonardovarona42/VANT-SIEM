from django import template

register = template.Library()

@register.filter
def replace(value, arg):
    """
    Reemplaza todas las ocurrencias de un string por otro
    Uso: {{ value|replace:"old":"new" }}
    """
    if not value or not arg:
        return value
    
    # Separar el argumento por ":"
    parts = arg.split(':')
    if len(parts) != 2:
        return value
    
    old, new = parts
    return value.replace(old, new)

@register.filter
def format_event_type(value):
    """
    Formatea el tipo de evento para mostrar
    Convierte USER_CREATE_REQUEST a "User Create Request"
    """
    if not value:
        return value
    
    return value.replace('_', ' ').title()
