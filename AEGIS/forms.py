from django import forms
from .models import DlpPolicy, DlpRule


class DlpPolicyForm(forms.ModelForm):
    class Meta:
        model = DlpPolicy
        fields = ["code", "name", "description", "is_active", "severity",
                   "scan_paths", "monitored_extensions", "max_file_size_mb",
                   "max_scan_seconds", "target_os"]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 3}),
            "scan_paths": forms.Textarea(attrs={"rows": 3, "placeholder": "One path per line"}),
            "monitored_extensions": forms.Textarea(attrs={"rows": 2, "placeholder": "One extension per line"}),
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
            "tags": forms.TextInput(attrs={"placeholder": "tag1, tag2"}),
        }

    def clean_tags(self):
        val = self.cleaned_data.get("tags", [])
        if isinstance(val, str):
            return [t.strip() for t in val.split(",") if t.strip()]
        return val
