"""
Azathoth TI - AbuseIPDB Collector
Recopila IPs maliciosas desde AbuseIPDB.
"""

import asyncio
from typing import List, Dict, Any
from datetime import datetime, timedelta
from .base import BaseCollector
from ..models import IOC, IOCType, IOCStatus


class AbuseIPDBCollector(BaseCollector):
    """Collector para AbuseIPDB."""
    
    name = "abuseipdb"
    ioc_types = [IOCType.IP]
    base_url = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: str, confidence_limit: int = 100):
        """Inicializar collector."""
        super().__init__(api_key=api_key)
        self.confidence_limit = confidence_limit
    
    async def collect(self) -> List[IOC]:
        """Recopilar IPs desde AbuseIPDB."""
        if not self.api_key:
            self.last_error = "API key no proporcionada"
            return []
        
        iocs = []
        
        # Obtados recientemente
        for days_backener IPs report in [1, 7, 30]:
            reported_ips = await self._get_reported_ips(days_back)
            iocs.extend(reported_ips)
        
        # Obtener IPs blacklist
        blacklist_ips = await self._get_blacklist()
        iocs.extend(blacklist_ips)
        
        self.ioc_count = len(iocs)
        return iocs
    
    async def _get_reported_ips(self, days_back: int) -> List[IOC]:
        """Obtener IPs reportados en los últimos N días."""
        url = f"{self.base_url}/reports"
        
        params = {
            "filter[confidenceMinimum]": self.confidence_limit,
            "filter[dateLte]": datetime.now().isoformat(),
            "filter[dateGte]": (datetime.now() - timedelta(days=days_back)).isoformat(),
            "page": 1,
            "perPage": 10000
        }
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        iocs = []
        
        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    reports = data.get("data", [])
                    
                    for report in reports:
                        ip = report.get("ipAddress")
                        if not ip:
                            continue
                        
                        # Filtrar IPs privadas
                        if self._is_private_ip(ip):
                            continue
                        
                        # Determinar tags
                        tags = self._extract_tags(report)
                        
                        # Calcular score basado en reportes
                        abuse_count = report.get("numReports", 0)
                        score = min(100, abuse_count)
                        
                        ioc = IOC(
                            type=IOCType.IP,
                            value=ip,
                            source="abuseipdb",
                            tags=tags,
                            score=score,
                            confidence=report.get("confidenceLevel", 50) / 100,
                            metadata={
                                "abuse_count": abuse_count,
                                "num_distinct_users": report.get("numDistinctUsers", 0),
                                "last_reported": report.get("lastReportedAt"),
                                "categories": report.get("categories", [])
                            },
                            description=f"IP reportada {abuse_count} veces"
                        )
                        iocs.append(ioc)
        
        except Exception as e:
            self.last_error = str(e)
        
        return iocs
    
    async def _get_blacklist(self) -> List[IOC]:
        """Obtener blacklist de IPs."""
        url = f"{self.base_url}/blacklist"
        
        params = {
            "confidenceMinimum": self.confidence_limit,
            "limit": 10000
        }
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        iocs = []
        
        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    entries = data.get("data", [])
                    
                    for entry in entries:
                        ip = entry.get("ipAddress")
                        if not ip or self._is_private_ip(ip):
                            continue
                        
                        ioc = IOC(
                            type=IOCType.IP,
                            value=ip,
                            source="abuseipdb:blacklist",
                            score=entry.get("abuseConfidenceScore", 0),
                            confidence=entry.get("abuseConfidenceScore", 0) / 100,
                            metadata={
                                "num_reports": entry.get("numReports", 0),
                                "isp": entry.get("isp"),
                                "domain": entry.get("domain"),
                                "country_code": entry.get("countryCode"),
                                "ip_version": entry.get("ipVersion")
                            }
                        )
                        iocs.append(ioc)
        
        except Exception as e:
            self.last_error = str(e)
        
        return iocs
    
    def _extract_tags(self, report: Dict) -> List[str]:
        """Extraer tags desde reporte."""
        # Categories de AbuseIPDB
        category_map = {
            1: "dns_compromise",
            2: "dns_poisoning",
            3: "fraud_orders",
            4: "ddos_attack",
            5: "ftp_brute_force",
            6: "ping_of_death",
            7: "phishing",
            8: "fraud_frivolous",
            9: "spam",
            10: "bot",
            11: "hacking",
            12: "sql_injection",
            13: "spoofing",
            14: "fraud",
            15: "web_spam",
            16: "smtp_spam",
            17: "ssh",
            18: "unauthorized_access",
            19: "malware",
            20: "copyright",
            21: "proxy",
            22: "vpn",
            23: "port_scan",
            24: "vulnerability_scan",
            25: "web_attack",
            26: "email_spam"
        }
        
        tags = []
        categories = report.get("categories", [])
        
        for cat_id in categories:
            if cat_id in category_map:
                tags.append(category_map[cat_id])
        
        return tags
    
    def _is_private_ip(self, ip: str) -> bool:
        """Verificar si es IP privada."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            private_ranges = [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
                ipaddress.ip_network("127.0.0.0/8"),
                ipaddress.ip_network("169.254.0.0/16")
            ]
            return any(ip_obj in r for r in private_ranges)
        except:
            return True
