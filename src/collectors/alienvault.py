"""
Azathoth TI - AlienVault OTX Collector
Recopila IOCs desde AlienVault Open Threat Exchange.
"""

import asyncio
from typing import List, Dict, Any
from .base import BaseCollector, IOCExtractor
from ..models import IOC, IOCType


class AlienVaultCollector(BaseCollector):
    """Collector para AlienVault OTX."""
    
    name = "alienvault"
    ioc_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH_SHA256]
    base_url = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: str, pulse_limit: int = 10):
        """Inicializar collector."""
        super().__init__(api_key=api_key)
        self.pulse_limit = pulse_limit
    
    async def collect(self) -> List[IOC]:
        """Recopilar IOCs desde AlienVault OTX."""
        if not self.api_key:
            self.last_error = "API key no proporcionada"
            return []
        
        iocs = []
        
        # Obtener pulses recientes
        pulses = await self._get_recent_pulses()
        
        for pulse in pulses:
            pulse_iocs = self._extract_from_pulse(pulse)
            iocs.extend(pulse_iocs)
        
        self.ioc_count = len(iocs)
        return iocs
    
    async def _get_recent_pulses(self) -> List[Dict]:
        """Obtener pulses recientes."""
        url = f"{self.base_url}/pulses/subscribed?limit={self.pulse_limit}"
        headers = {"X-OTX-API-KEY": self.api_key}
        
        data = await self._fetch_json(url, headers)
        
        if data and "results" in data:
            return data["results"]
        return []
    
    def _extract_from_pulse(self, pulse: Dict) -> List[IOC]:
        """Extraer IOCs desde un pulse."""
        iocs = []
        source = f"alienvault:{pulse.get('id', 'unknown')}"
        
        # Extraer IPs
        if "indicators" in pulse:
            for indicator in pulse["indicators"]:
                ioc = self._parse_indicator(indicator, source)
                if ioc:
                    iocs.append(ioc)
        
        return iocs
    
    def _parse_indicator(self, indicator: Dict, source: str) -> IOC:
        """Parsear un indicador a IOC."""
        indicator_type = indicator.get("type", "").lower()
        value = indicator.get("indicator", "")
        
        if not value:
            return None
        
        # Mapear tipo
        type_map = {
            "IPv4": IOCType.IP,
            "IPv6": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "url": IOCType.URL,
            "FileHash-SHA256": IOCType.HASH_SHA256,
            "FileHash-SHA1": IOCType.HASH_SHA1,
            "FileHash-MD5": IOCType.HASH_MD5,
            "email": IOCType.EMAIL,
            "CVE": IOCType.CVE
        }
        
        ioc_type = type_map.get(indicator_type)
        
        if not ioc_type:
            return None
        
        # Extraer tags
        tags = []
        if "tags" in indicator:
            tags = [t.lower() for t in indicator["tags"]]
        
        return IOC(
            type=ioc_type,
            value=value,
            source=source,
            tags=tags,
            description=pulse.get("name", ""),
            references=[f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}"]
        )
