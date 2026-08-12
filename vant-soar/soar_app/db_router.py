class LogsRouter:
    route_app_labels = {"soar_app", "auth", "contenttypes"}

    def db_for_read(self, model, **hints):
        if model._meta.app_label == "soar_app":
            if model._meta.db_table == "logs_events_raw":
                return "vant_logs"
            if model._meta.db_table in ("soc_servicio_ips", "soc_servicios"):
                return "vant_soc"
            return "default"
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label == "soar_app":
            return "default"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label == "soar_app":
            if db in ("vant_logs", "vant_soc"):
                return False
            return True
        return None
