from django import forms
from .models import DlpPolicy, DlpRule

INPUT_CLASSES = (
    "w-full px-3 py-2 rounded-lg text-sm "
    "bg-surface-800 dark:bg-surface-800 text-white "
    "border border-surface-600 dark:border-surface-600 "
    "focus:border-amber-500 focus:ring-1 focus:ring-amber-500 focus:outline-none "
    "placeholder-surface-400"
)
SELECT_CLASSES = INPUT_CLASSES
TEXTAREA_CLASSES = INPUT_CLASSES


class DlpPolicyForm(forms.ModelForm):
    class Meta:
        model = DlpPolicy
        fields = ["code", "name", "description", "is_active", "severity",
                   "target_os", "scan_mode", "scan_paths", "monitored_extensions",
                   "max_file_size_mb", "max_scan_seconds", "realtime_enabled"]
        widgets = {
            "code": forms.TextInput(attrs={"class": INPUT_CLASSES, "placeholder": "ej: DLP-001"}),
            "name": forms.TextInput(attrs={"class": INPUT_CLASSES, "placeholder": "Nombre de la politica"}),
            "description": forms.Textarea(attrs={"class": TEXTAREA_CLASSES, "rows": 3, "placeholder": "Descripcion de la politica"}),
            "is_active": forms.CheckboxInput(attrs={"class": "w-4 h-4 rounded bg-surface-800 border-surface-600 text-amber-500 focus:ring-amber-500"}),
            "severity": forms.Select(attrs={"class": SELECT_CLASSES}),
            "target_os": forms.Select(attrs={"class": SELECT_CLASSES}),
            "scan_mode": forms.Select(attrs={"class": SELECT_CLASSES}),
            "scan_paths": forms.Textarea(attrs={"class": TEXTAREA_CLASSES, "rows": 3, "placeholder": "Una ruta por linea (solo si modo = rutas especificas)"}),
            "monitored_extensions": forms.Textarea(attrs={"class": TEXTAREA_CLASSES, "rows": 2, "placeholder": "Una extension por linea"}),
            "max_file_size_mb": forms.NumberInput(attrs={"class": INPUT_CLASSES, "placeholder": "50"}),
            "max_scan_seconds": forms.NumberInput(attrs={"class": INPUT_CLASSES, "placeholder": "0 = sin limite"}),
            "realtime_enabled": forms.CheckboxInput(attrs={"class": "w-4 h-4 rounded bg-surface-800 border-surface-600 text-amber-500 focus:ring-amber-500"}),
        }

    def clean_scan_paths(self):
        val = self.cleaned_data.get("scan_paths", [])
        if isinstance(val, str):
            return [p.strip() for p in val.splitlines() if p.strip()]
        return val

    def clean_monitored_extensions(self):
        val = self.cleaned_data.get("monitored_extensions", [])
        if isinstance(val, str):
            return [e.strip() for e in val.splitlines() if e.strip()]
        return val


class DlpRuleForm(forms.ModelForm):
    class Meta:
        model = DlpRule
        fields = ["policy", "name", "pattern", "match_type", "classification", "severity", "tags", "is_active"]
        widgets = {
            "policy": forms.Select(attrs={"class": SELECT_CLASSES}),
            "name": forms.TextInput(attrs={"class": INPUT_CLASSES, "placeholder": "Nombre de la regla"}),
            "pattern": forms.TextInput(attrs={"class": INPUT_CLASSES, "placeholder": "regex o texto literal"}),
            "match_type": forms.Select(attrs={"class": SELECT_CLASSES}),
            "classification": forms.Select(attrs={"class": SELECT_CLASSES}),
            "severity": forms.Select(attrs={"class": SELECT_CLASSES}),
            "tags": forms.TextInput(attrs={"class": INPUT_CLASSES, "placeholder": "tag1, tag2"}),
            "is_active": forms.CheckboxInput(attrs={"class": "w-4 h-4 rounded bg-surface-800 border-surface-600 text-amber-500 focus:ring-amber-500"}),
        }

    def clean_tags(self):
        val = self.cleaned_data.get("tags", [])
        if isinstance(val, str):
            return [t.strip() for t in val.split(",") if t.strip()]
        return val
