from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from intelligence_app.services import lookup_ip, lookup_mac, lookup_virustotal, fetch_abuseipdb_blacklist, fetch_abuseipdb_bulk_check, fetch_abuseipdb_reports

WELL_KNOWN_IPS = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "208.67.222.222",
    "208.67.220.220",
    "185.228.168.168",
    "76.76.19.19",
    "94.140.14.14",
]

COMMON_MACS = [
    "FC:FB:FB:01:FA:21",
    "00:11:22:33:44:55",
    "00:1A:2B:3C:4D:5E",
    "3C:5A:B4:00:00:01",
    "BC:5F:F4:00:00:01",
]

VT_INDICATORS = [
    ("ip", "8.8.8.8"),
    ("ip", "1.1.1.1"),
    ("domain", "google.com"),
    ("domain", "cloudflare.com"),
]


class Command(BaseCommand):
    help = "Pre-popula datos de inteligencia de amenazas desde AbuseIPDB, MAC Vendors y VirusTotal"

    def add_arguments(self, parser):
        parser.add_argument("--ips", nargs="*", default=None, help="IPs adicionales para AbuseIPDB")
        parser.add_argument("--macs", nargs="*", default=None, help="MACs adicionales para MAC Vendors")
        parser.add_argument("--skip-vt", action="store_true", help="Saltar VirusTotal")
        parser.add_argument("--skip-mac", action="store_true", help="Saltar MAC Vendors")
        parser.add_argument("--skip-ip", action="store_true", help="Saltar AbuseIPDB")
        parser.add_argument("--blacklist", action="store_true", help="Descargar blacklist de AbuseIPDB")
        parser.add_argument("--blacklist-confidence", type=int, default=75, help="Confianza minima para blacklist (default 75)")
        parser.add_argument("--blacklist-limit", type=int, default=10000, help="Max entradas de blacklist (default 10000)")
        parser.add_argument("--bulk-check", type=int, default=0, help="Cantidad de IPs de la blacklist a re-enriquecer con bulk-check")
        parser.add_argument("--bulk-check-ips", nargs="*", default=None, help="IPs especificas para bulk-check")
        parser.add_argument("--reports", type=int, default=0, help="Cantidad de IPs de la blacklist a enriquecer con reports detallados")
        parser.add_argument("--reports-ips", nargs="*", default=None, help="IPs especificas para reports detallados")

    def handle(self, *args, **options):
        t0 = timezone.now()
        ip_ok = ip_fail = mac_ok = mac_fail = vt_ok = vt_fail = 0

        # AbuseIPDB
        if not options.get("skip_ip"):
            ips = WELL_KNOWN_IPS + (options.get("ips") or [])
            self.stdout.write(f"Enriqueciendo {len(ips)} IPs via AbuseIPDB...")
            for ip in ips:
                result = lookup_ip(ip, force=True)
                if result:
                    ip_ok += 1
                    self.stdout.write(f"  OK  {ip} score={result.abuse_confidence_score}")
                else:
                    ip_fail += 1
                    self.stdout.write(f"  FAIL {ip}")

        # MAC Vendors
        if not options.get("skip_mac"):
            macs = COMMON_MACS + (options.get("macs") or [])
            self.stdout.write(f"\nEnriqueciendo {len(macs)} MACs via MAC Vendors...")
            for mac in macs:
                result = lookup_mac(mac, force=True)
                if result:
                    mac_ok += 1
                    self.stdout.write(f"  OK  {mac} vendor={result.vendor or '(vacio)'}")
                else:
                    mac_fail += 1
                    self.stdout.write(f"  FAIL {mac}")

        # VirusTotal
        if not options.get("skip_vt"):
            self.stdout.write(f"\nEnriqueciendo {len(VT_INDICATORS)} indicadores via VirusTotal...")
            for typ, val in VT_INDICATORS:
                result = lookup_virustotal(val, typ, force=True)
                if result:
                    vt_ok += 1
                    self.stdout.write(f"  OK  {typ}={val} malicious={result.malicious}")
                else:
                    vt_fail += 1
                    self.stdout.write(f"  FAIL {typ}={val}")

        # Blacklist
        blacklist_count = 0
        if options.get("blacklist"):
            self.stdout.write(f"\nDescargando blacklist de AbuseIPDB (confidence>={options['blacklist_confidence']}, limit={options['blacklist_limit']})...")
            blacklist_count = fetch_abuseipdb_blacklist(
                confidence_minimum=options["blacklist_confidence"],
                limit=options["blacklist_limit"],
            )
            self.stdout.write(f"  Blacklist: {blacklist_count} entradas almacenadas")

        # Bulk-check
        bulk_count = 0
        if options.get("bulk_check"):
            from intelligence_app.models import IntelligenceIpReport
            qs = IntelligenceIpReport.objects.values_list("ip_address", flat=True)
            if options["bulk_check_ips"]:
                ips = options["bulk_check_ips"]
            else:
                ips = list(qs[:options["bulk_check"]])
            self.stdout.write(f"\nBulk-check de {len(ips)} IPs via AbuseIPDB...")
            bulk_count = fetch_abuseipdb_bulk_check(ips)
            self.stdout.write(f"  Bulk-check: {bulk_count} entradas actualizadas")

        # Reports detallados
        reports_ok = 0
        if options.get("reports"):
            from intelligence_app.models import IntelligenceIpReport
            if options["reports_ips"]:
                rep_ips = options["reports_ips"]
            else:
                rep_ips = list(IntelligenceIpReport.objects.values_list("ip_address", flat=True)[:options["reports"]])
            self.stdout.write(f"\nDescargando reports detallados para {len(rep_ips)} IPs...")
            for ip in rep_ips:
                result = fetch_abuseipdb_reports(ip)
                if result:
                    reports_ok += 1
                    self.stdout.write(f"  OK  {ip} reports={result.total_reports}")
                else:
                    self.stdout.write(f"  FAIL {ip}")
            self.stdout.write(f"  Reports: {reports_ok} OK")

        elapsed = (timezone.now() - t0).total_seconds()
        self.stdout.write(f"\n--- Resumen ({elapsed:.1f}s) ---")
        self.stdout.write(f"AbuseIPDB: {ip_ok} OK, {ip_fail} FAIL")
        self.stdout.write(f"MAC Vendors: {mac_ok} OK, {mac_fail} FAIL")
        self.stdout.write(f"VirusTotal: {vt_ok} OK, {vt_fail} FAIL")
        if blacklist_count:
            self.stdout.write(f"Blacklist: {blacklist_count} entradas")
        if bulk_count:
            self.stdout.write(f"Bulk-check: {bulk_count} entradas")
        if reports_ok:
            self.stdout.write(f"Reports: {reports_ok} IPs con reports detallados")
        self.stdout.write("Completado.")
