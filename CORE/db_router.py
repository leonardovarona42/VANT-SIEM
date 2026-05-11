import os

LOGS_APP_LABELS = ('OPENSEARCH_LOGS',)
LOGS_DB_NAME = os.getenv('LOGS_DB_NAME', 'vant_logs')

INVENTORY_APP_LABELS = ('INVENTORY',)
INVENTORY_DB_NAME = os.getenv('INVENTORY_DB_NAME', 'vant_inventory')

DLP_APP_LABELS = ('AEGIS',)
DLP_DB_NAME = os.getenv('DLP_DB_NAME', 'vant_dlp')


class LogsRouter:
    def _db_exists(self, db_alias):
        if db_alias == 'default':
            return True
        from django.conf import settings
        dbs = settings.DATABASES
        return db_alias in dbs

    def db_for_read(self, model, **hints):
        if model._meta.app_label in LOGS_APP_LABELS:
            if self._db_exists('vant_logs'):
                return 'vant_logs'
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label in LOGS_APP_LABELS:
            if self._db_exists('vant_logs'):
                return 'vant_logs'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._meta.app_label in LOGS_APP_LABELS or obj2._meta.app_label in LOGS_APP_LABELS:
            return obj1._meta.app_label == obj2._meta.app_label
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in LOGS_APP_LABELS:
            if self._db_exists('vant_logs'):
                return db == 'vant_logs'
            return db == 'default'
        if db == 'vant_logs':
            return False
        return None


class InventoryRouter:
    def _db_exists(self, db_alias):
        if db_alias == 'default':
            return True
        from django.conf import settings
        dbs = settings.DATABASES
        return db_alias in dbs

    def db_for_read(self, model, **hints):
        if model._meta.app_label in INVENTORY_APP_LABELS:
            if self._db_exists('vant_inventory'):
                return 'vant_inventory'
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label in INVENTORY_APP_LABELS:
            if self._db_exists('vant_inventory'):
                return 'vant_inventory'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._meta.app_label in INVENTORY_APP_LABELS or obj2._meta.app_label in INVENTORY_APP_LABELS:
            return obj1._meta.app_label == obj2._meta.app_label
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in INVENTORY_APP_LABELS:
            if self._db_exists('vant_inventory'):
                return db == 'vant_inventory'
            return db == 'default'
        if db == 'vant_inventory':
            return False
        return None


class DlpRouter:
    def _db_exists(self, db_alias):
        if db_alias == 'default':
            return True
        from django.conf import settings
        dbs = settings.DATABASES
        return db_alias in dbs

    def db_for_read(self, model, **hints):
        if model._meta.app_label in DLP_APP_LABELS:
            if self._db_exists('vant_dlp'):
                return 'vant_dlp'
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label in DLP_APP_LABELS:
            if self._db_exists('vant_dlp'):
                return 'vant_dlp'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._meta.app_label in DLP_APP_LABELS or obj2._meta.app_label in DLP_APP_LABELS:
            return obj1._meta.app_label == obj2._meta.app_label
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in DLP_APP_LABELS:
            if self._db_exists('vant_dlp'):
                return db == 'vant_dlp'
            return db == 'default'
        if db == 'vant_dlp':
            return False
        return None
