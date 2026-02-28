"""
Azathoth TI - Base Collector
Clase base para todos los collectors de feeds.
"""

import asyncio
import aiohttp
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime
from ..models import IOC, IOCType, IOCStatus


class BaseCollector(ABC):
    """Clase base para collectors de feeds."""
    
    name: str = "base"
    ioc_types: List[IOCType] = []
    feed_url: str = ""
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """Inicializar collector."""
        self.api_key = api_key
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self.last_fetch: Optional[datetime] = None
        self.ioc_count = 0
        self.error_count = 0
        self.last_error: Optional[str] = None
    
    async def __aenter__(self):
        """Contexto async."""
        await self._create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Salir del contexto."""
        await self._close_session()
    
    async def _create_session(self):
        """Crear sesión HTTP."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
    
    async def _close_session(self):
        """Cerrar sesión HTTP."""
        if self.session:
            await self.session.close()
    
    async def _fetch(self, url: str, headers: Optional[Dict[str, str]] = None) -> Optional[str]:
        """Hacer request HTTP."""
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    self.error_count += 1
                    self.last_error = f"HTTP {response.status}"
                    return None
        except Exception as e:
            self.error_count += 1
            self.last_error = str(e)
            return None
    
    async def _fetch_json(self, url: str, headers: Optional[Dict[str, str]] = None) -> Optional[Dict]:
        """Hacer request HTTP y parsear JSON."""
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    self.error_count += 1
                    self.last_error = f"HTTP {response.status}"
                    return None
        except Exception as e:
            self.error_count += 1
            self.last_error = str(e)
            return None
    
    @abstractmethod
    async def collect(self) -> List[IOC]:
        """Recopilar IOCs del feed. Debe ser implementado por subclases."""
        pass
    
    async def collect_with_retry(self, max_retries: int = 3) -> List[IOC]:
        """Recopilar con reintentos."""
        for attempt in range(max_retries):
            try:
                iocs = await self.collect()
                self.last_fetch = datetime.now()
                self.ioc_count = len(iocs)
                return iocs
            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    self.error_count += 1
                    self.last_error = str(e)
        return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas del collector."""
        return {
            "name": self.name,
            "last_fetch": self.last_fetch.isoformat() if self.last_fetch else None,
            "ioc_count": self.ioc_count,
            "error_count": self.error_count,
            "last_error": self.last_error
        }


class IOCExtractor:
    """Extractor de IOCs desde texto/JSON."""
    
    @staticmethod
    def extract_ips(data: Any, key_path: Optional[str] = None) -> List[str]:
        """Extraer IPs desde datos."""
        import re
        ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        ips = []
        
        # Si es string, buscar en texto
        if isinstance(data, str):
            ips.extend(ip_pattern.findall(data))
        
        # Si es dict, buscar recursively
        elif isinstance(data, dict):
            for key, value in data.items():
                if key_path and key != key_path:
                    continue
                if isinstance(value, str):
                    ips.extend(ip_pattern.findall(value))
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            ips.extend(ip_pattern.findall(item))
        
        # Si es lista
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    ips.extend(ip_pattern.findall(item))
        
        # Deduplicar y filtrar privadas
        from ipaddress import ip_address, ip_network
        
        def is_private(ip_str: str) -> bool:
            try:
                ip = ip_address(ip_str)
                private_ranges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 
                                '127.0.0.0/8', '169.254.0.0/16']
                for range_str in private_ranges:
                    if ip in ip_network(range_str, strict=False):
                        return True
            except:
                pass
            return False
        
        return list(set(ip for ip in ips if not is_private(ip)))
    
    @staticmethod
    def extract_domains(data: Any) -> List[str]:
        """Extraer dominios desde datos."""
        import re
        domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        
        domains = []
        
        if isinstance(data, str):
            domains.extend(domain_pattern.findall(data))
        elif isinstance(data, dict):
            for value in data.values():
                if isinstance(value, str):
                    domains.extend(domain_pattern.findall(value))
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            domains.extend(domain_pattern.findall(item))
        
        return list(set(domains))
    
    @staticmethod
    def extract_urls(data: Any) -> List[str]:
        """Extraer URLs desde datos."""
        import re
        url_pattern = re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s\]">]*'
        )
        
        urls = []
        
        if isinstance(data, str):
            urls.extend(url_pattern.findall(data))
        
        return list(set(urls))
    
    @staticmethod
    def extract_hashes(data: Any, hash_type: str = "sha256") -> List[str]:
        """Extraer hashes desde datos."""
        import re
        
        patterns = {
            "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
            "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
            "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b')
        }
        
        pattern = patterns.get(hash_type.lower(), patterns["sha256"])
        hashes = []
        
        if isinstance(data, str):
            hashes.extend(pattern.findall(data))
        
        return list(set(hashes))
