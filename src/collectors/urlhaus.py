"""
Azathoth TI - URLhaus Collector
Recopila URLs maliciosas desde URLhaus.
"""

import asyncio
from typing import List, Dict, Any
from .base import BaseCollector
from ..models import IOC, IOCType


class URLhausCollector(BaseCollector):
    """Collector para URLhaus."""
    
    name = "urlhaus"
    ioc_types = [IOCType.URL, IOCType.HASH_SHA256]
    base_url = "https://urlhaus-api.abuse.ch/v1"
    
    async def collect(self) -> List[IOC]:
        """Recopilar URLs desde URLhaus."""
        iocs = []
        
        # Obtener recientes
        recent = await self._get_recent()
        iocs.extend(recent)
        
        # Obtener online URLs
        online = await self._get_online()
        iocs.extend(online)
        
        self.ioc_count = len(iocs)
        return iocs
    
    async def _get_recent(self) -> List[IOC]:
        """Obtener URLs recientes."""
        url = f"{self.base_url}/recent/limit/1000"
        
        data = await self._fetch_json(url)
        
        if not data or data.get("query_status") != "ok":
            return []
        
        iocs = []
        urls = data.get("urls", [])
        
        for entry in urls:
            url_value = entry.get("url")
            if not url_value:
                continue
            
            # Solo URLs confirmadas como maliciosas
            threat = entry.get("threat", "")
            if threat not in ["malware_download", "malware_configuration"]:
                continue
            
            tags = entry.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]
            
            ioc = IOC(
                type=IOCType.URL,
                value=url_value,
                source="urlhaus",
                tags=tags,
                status=IOCStatus.ACTIVE if entry.get("url_status") == "online" else IOCStatus.INACTIVE,
                metadata={
                    "threat": threat,
                    "url_status": entry.get("url_status"),
                    "first_seen": entry.get("date_added"),
                    "last_online": entry.get("last_online"),
                    " Lazar urlhaus_reference": entry.get("reference"),
                },
                description=f"URL maliciosa - {threat}"
            )
            iocs.append(ioc)
        
        return iocs
    
    async def _get_online(self) -> List[IOC]:
        """Obtener URLs online."""
        url = f"{self.base_url}/online"
        
        data = await self._fetch_json(url)
        
        if not data or data.get("query_status") != "ok":
            return []
        
        iocs = []
        urls = data.get("urls", [])
        
        for entry in urls:
            url_value = entry.get("url")
            if not url_value:
                continue
            
            ioc = IOC(
                type=IOCType.URL,
                value=url_value,
                source="urlhaus:online",
                tags=entry.get("tags", []),
                metadata={
                    "threat": entry.get("threat"),
                    "date_added": entry.get("date_added")
                }
            )
            iocs.append(ioc)
        
        return iocs


class ThreatFoxCollector(BaseCollector):
    """Collector para ThreatFox."""
    
    name = "threatfox"
    ioc_types = [IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]
    base_url = "https://threatfox-api.abuse.ch"
    
    async def collect(self) -> List[IOC]:
        """Recopilar IOCs desde ThreatFox."""
        iocs = []
        
        # Obtener IOCs del día
        daily = await self._get_daily_iocs()
        iocs.extend(daily)
        
        self.ioc_count = len(iocs)
        return iocs
    
    async def _get_daily_iocs(self) -> List[IOC]:
        """Obtener IOCs del día."""
        url = f"{self.base_url}/api/v1/iocs/date/1d/"
        
        data = await self._fetch_json(url)
        
        if not data or data.get("query_status") != "ok":
            return []
        
        iocs = []
        entries = data.get("data", [])
        
        for entry in entries:
            ioc_type = entry.get("ioc_type", "").lower()
            ioc_value = entry.get("ioc", "")
            
            if not ioc_value:
                continue
            
            # Mapear tipo
            type_map = {
                "ip": IOCType.IP,
                "domain": IOCType.DOMAIN,
                "url": IOCType.URL,
                "md5_hash": IOCType.HASH_MD5,
                "sha1_hash": IOCType.HASH_SHA1,
                "sha256_hash": IOCType.HASH_SHA256
            }
            
            ioc_type_enum = type_map.get(ioc_type)
            if not ioc_type_enum:
                continue
            
            # Extraer tags
            tags = entry.get("threat", []).split(",") if entry.get("threat") else []
            tags = [t.strip().lower() for t in tags if t.strip()]
            
            ioc = IOC(
                type=ioc_type_enum,
                value=ioc_value,
                source="threatfox",
                tags=tags,
                confidence=entry.get("confidence_level", 50) / 100,
                metadata={
                    "malware": entry.get("malware_alias"),
                    "malware_printable": entry.get("malware_printable"),
                    "confidence_level": entry.get("confidence_level"),
                    "first_seen": entry.get("date_added"),
                    "ioc_type": ioc_type
                },
                description=entry.get("malware_printable", "")
            )
            iocs.append(ioc)
        
        return iocs
