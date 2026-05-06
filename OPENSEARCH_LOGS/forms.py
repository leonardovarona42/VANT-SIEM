from django import forms
from .models import LogSource, LogRetentionPolicy


class LogSourceForm(forms.ModelForm):
    class Meta:
        model = LogSource
        fields = ['source_id', 'source_type', 'vendor', 'model', 'host_name', 'host_ip', 'protocol', 'port', 'api_key', 'enabled', 'meta']
        widgets = {
            'meta': forms.Textarea(attrs={'rows': 3, 'placeholder': '{"custom_key": "value"}'}),
        }


class LogRetentionPolicyForm(forms.ModelForm):
    class Meta:
        model = LogRetentionPolicy
        fields = ['source_type', 'retention_days', 'auto_delete']
