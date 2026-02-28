"""
Azathoth TI - IOC Normalizer
Normaliza IOCs de diferentes fuentes a formato estándar.
"""

import re
import ipaddress
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from ..models import IOC, IOCType, IOCStatus


class IOCNormalizer:
    """Normalizador de IOCs a formato estándar."""
    
    # Patrones regex para detección de tipos
    IPV4_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    IPV6_PATTERN = re.compile(
        r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
        r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    )
    
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:[a-zA-Z]{2,})\b'
    )
    
    URL_PATTERN = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    )
    
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
    
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    
    def __init__(self):
        """Inicializar normalizador."""
        self.private_ip_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12', 
            '192.168.0.0/16',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '224.0.0.0/4',
            '240.0.0.0/4'
        ]
    
    def detect_type(self, value: str) -> Optional[IOCType]:
        """Detectar tipo de IOC."""
        value = value.strip()
        
        # Detectar hash primero (más específico)
        if self.SHA256_PATTERN.match(value):
            return IOCType.HASH_SHA256
        if self.SHA1_PATTERN.match(value):
            return IOCType.HASH_SHA1
        if self.MD5_PATTERN.match(value):
            return IOCType.HASH_MD5
        
        # Detectar CVE
        if self.CVE_PATTERN.match(value):
            return IOCType.CVE
        
        # Detectar IP
        if self._is_ip(value):
            return IOCType.IP
        
        # Detectar URL
        if self._is_url(value):
            return IOCType.URL
        
        # Detectar dominio
        if self._is_domain(value):
            return IOCType.DOMAIN
        
        return None
    
    def _is_ip(self, value: str) -> bool:
        """Verificar si es una dirección IP."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def _is_private_ip(self, value: str) -> bool:
        """Verificar si es IP privada."""
        try:
            ip = ipaddress.ip_address(value)
            for range_str in self.private_ip_ranges:
                network = ipaddress.ip_network(range_str, strict=False)
                if ip in network:
                    return True
        except ValueError:
            pass
        return False
    
    def _is_url(self, value: str) -> bool:
        """Verificar si es URL."""
        if not value.startswith(('http://', 'https://')):
            return False
        try:
            result = urlparse(value)
            return bool(result.netloc)
        except Exception:
            return False
    
    def _is_domain(self, value: str) -> bool:
        """Verificar si es dominio."""
        # Excluir IPs
        if self._is_ip(value):
            return False
        
        # Excluir URLs
        if self._is_url(value):
            return False
        
        # Verificar formato de dominio
        if self.DOMAIN_PATTERN.match(value):
            # Excluir dominios muy cortos (podrían ser palabras normales)
            parts = value.split('.')
            if len(parts) >= 2 and len(parts[-1]) >= 2:
                return True
        return False
    
    def normalize(self, value: str, source: str) -> Optional[IOC]:
        """Normalizar un valor a IOC."""
        value = value.strip()
        
        # Detectar tipo
        ioc_type = self.detect_type(value)
        if not ioc_type:
            return None
        
        # Validar y limpiar el valor
        normalized_value = self._normalize_value(value, ioc_type)
        if not normalized_value:
            return None
        
        # Crear IOC
        return IOC(
            type=ioc_type,
            value=normalized_value,
            source=source,
            status=IOCStatus.ACTIVE
        )
    
    def _normalize_value(self, value: str, ioc_type: IOCType) -> Optional[str]:
        """Normalizar el valor según el tipo."""
        value = value.strip()
        
        if ioc_type == IOCType.IP:
            try:
                ip = ipaddress.ip_address(value)
                # Ignorar IPs privadas
                if self._is_private_ip(str(ip)):
                    return None
                return str(ip)
            except ValueError:
                return None
        
        if ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            return value.lower()
        
        if ioc_type == IOCType.URL:
            try:
                parsed = urlparse(value)
                # Remover parámetros sensibles
                netloc = parsed.netloc.split('@')[-1] if '@' in parsed.netloc else parsed.netloc
                return f"{parsed.scheme}://{netloc}{parsed.path}"
            except Exception:
                return None
        
        if ioc_type == IOCType.CVE:
            return value.upper()
        
        return value
    
    def normalize_batch(self, values: List[str], source: str) -> List[IOC]:
        """Normalizar múltiples valores."""
        iocs = []
        for value in values:
            ioc = self.normalize(value, source)
            if ioc:
                iocs.append(ioc)
        return iocs
    
    def extract_iocs_from_text(self, text: str, source: str = "text") -> List[IOC]:
        """Extraer IOCs de texto."""
        iocs = []
        
        # Extraer IPs
        for match in self.IPV4_PATTERN.finditer(text):
            ioc = self.normalize(match.group(), source)
            if ioc:
                iocs.append(ioc)
        
        # Extraer URLs
        for match in self.URL_PATTERN.finditer(text):
            ioc = self.normalize(match.group(), source)
            if ioc:
                iocs.append(ioc)
        
        # Extraer dominios
        for match in self.DOMAIN_PATTERN.finditer(text):
            # Evitar falsos positivos con palabras comunes
            if not self._is_private_ip(match.group()):
                ioc = self.normalize(match.group(), source)
                if ioc:
                    iocs.append(ioc)
        
        # Extraer hashes
        for pattern, ioc_type in [
            (self.SHA256_PATTERN, IOCType.HASH_SHA256),
            (self.SHA1_PATTERN, IOCType.HASH_SHA1),
            (self.MD5_PATTERN, IOCType.HASH_MD5)
        ]:
            for match in pattern.finditer(text):
                ioc = self.normalize(match.group(), source)
                if ioc:
                    iocs.append(ioc)
        
        # Extraer CVEs
        for match in self.CVE_PATTERN.finditer(text):
            ioc = self.normalize(match.group(), source)
            if ioc:
                iocs.append(ioc)
        
        return iocs


# Singleton instance
normalizer = IOCNormalizer()
