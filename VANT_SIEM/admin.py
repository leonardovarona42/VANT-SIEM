from django.contrib import admin

from .models import (
    NetworkChangeEvent,
    NetworkIPAddress,
    NetworkSite,
    NetworkSubnet,
    NetworkVLAN,
)


@admin.register(NetworkSite)
class NetworkSiteAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "location", "updated_at")
    search_fields = ("code", "name", "location")


@admin.register(NetworkVLAN)
class NetworkVLANAdmin(admin.ModelAdmin):
    list_display = ("vlan_id", "name", "site", "vrf", "updated_at")
    list_filter = ("site",)
    search_fields = ("name", "vrf")


@admin.register(NetworkSubnet)
class NetworkSubnetAdmin(admin.ModelAdmin):
    list_display = ("name", "cidr", "site", "vlan", "status", "updated_at")
    list_filter = ("site", "status")
    search_fields = ("name", "cidr", "gateway_ip")


@admin.register(NetworkIPAddress)
class NetworkIPAddressAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "hostname", "subnet", "status", "assigned_to", "last_seen")
    list_filter = ("status", "subnet__site")
    search_fields = ("ip_address", "hostname", "dns_name", "mac_address", "assigned_to")


@admin.register(NetworkChangeEvent)
class NetworkChangeEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "summary", "actor", "created_at")
    list_filter = ("event_type",)
    search_fields = ("summary",)
