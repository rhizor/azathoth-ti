"""
Azathoth TI - Data Models
Modelos de datos para la plataforma de Threat Intelligence.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import hashlib


class IOCType(Enum):
    """Tipos de Indicadores de Compromiso."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"


class IOCStatus(Enum):
    """Estado del IOC."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    FALSE_POSITIVE = "false_positive"
    EXPIRED = "expired"


class IOCTags(Enum):
    """Etiquetas predefinidas para IOCs."""
    MALWARE = "malware"
    PHISHING = "phishing"
    C2 = "c2"
    BOTNET = "botnet"
    SPAM = "spam"
    SCAN = "scan"
    EXPLOIT = "exploit"
    RANSOMWARE = "ransomware"
    STEALER = "stealer"
    TROJAN = "trojan"


@dataclass
class IOC:
    """Modelo de Indicador de Compromiso."""
    type: IOCType
    value: str
    source: str
    id: Optional[str] = None
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    status: IOCStatus = IOCStatus.ACTIVE
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.5
    score: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    description: Optional[str] = None
    references: List[str] = field(default_factory=list)
    enrichment_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Calcular hash único del IOC."""
        if self.id is None:
            self.id = self._compute_hash()
    
    def _compute_hash(self) -> str:
        """Computar hash único del IOC."""
        hash_input = f"{self.type.value}:{self.value}".encode()
        return hashlib.sha256(hash_input).hexdigest()[:16]
    
    @property
    def display_name(self) -> str:
        """Nombre para mostrar."""
        return f"{self.type.value.upper()}:{self.value}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertir a diccionario."""
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "source": self.source,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "status": self.status.value,
            "tags": self.tags,
            "confidence": self.confidence,
            "score": self.score,
            "metadata": self.metadata,
            "description": self.description,
            "references": self.references,
            "enrichment_data": self.enrichment_data
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IOC':
        """Crear IOC desde diccionario."""
        return cls(
            type=IOCType(data.get("type", "ip")),
            value=data["value"],
            source=data["source"],
            first_seen=datetime.fromisoformat(data.get("first_seen", datetime.now().isoformat())),
            last_seen=datetime.fromisoformat(data.get("last_seen", datetime.now().isoformat())),
            status=IOCStatus(data.get("status", "active")),
            tags=data.get("tags", []),
            confidence=data.get("confidence", 0.5),
            score=data.get("score", 0),
            metadata=data.get("metadata", {}),
            description=data.get("description"),
            references=data.get("references", []),
            enrichment_data=data.get("enrichment_data", {})
        )


@dataclass
class Feed:
    """Modelo de Feed de Threat Intelligence."""
    name: str
    url: str
    type: IOCType
    enabled: bool = True
    api_key: Optional[str] = None
    last_fetch: Optional[datetime] = None
    fetch_interval: int = 3600  # segundos
    ioc_count: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertir a diccionario."""
        return {
            "name": self.name,
            "url": self.url,
            "type": self.type.value,
            "enabled": self.enabled,
            "last_fetch": self.last_fetch.isoformat() if self.last_fetch else None,
            "fetch_interval": self.fetch_interval,
            "ioc_count": self.ioc_count,
            "error_count": self.error_count,
            "last_error": self.last_error
        }


@dataclass
class Stats:
    """Estadísticas de la plataforma."""
    total_iocs: int = 0
    active_iocs: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    by_source: Dict[str, int] = field(default_factory=dict)
    by_tag: Dict[str, int] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertir a diccionario."""
        return {
            "total_iocs": self.total_iocs,
            "active_iocs": self.active_iocs,
            "by_type": self.by_type,
            "by_source": self.by_source,
            "by_tag": self.by_tag,
            "last_updated": self.last_updated.isoformat()
        }
