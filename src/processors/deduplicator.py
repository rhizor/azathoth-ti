"""
Azathoth TI - Deduplicator
Desduplica IOCs basándose en hash único.
"""

from typing import List, Dict, Set
from datetime import datetime, timedelta
from collections import defaultdict
from ..models import IOC, IOCType, IOCStatus


class Deduplicator:
    """Desduplicador de IOCs."""
    
    def __init__(self, similarity_threshold: float = 0.9):
        """Inicializar deduplicador."""
        self.similarity_threshold = similarity_threshold
        self._seen_hashes: Set[str] = set()
        self._seen_values: Dict[str, Set[str]] = defaultdict(set)
    
    def deduplicate(self, iocs: List[IOC]) -> List[IOC]:
        """Desduplicar lista de IOCs."""
        unique_iocs = []
        duplicates = []
        
        for ioc in iocs:
            if self._is_duplicate(ioc):
                duplicates.append(ioc)
            else:
                unique_iocs.append(ioc)
                self._add_to_seen(ioc)
        
        return unique_iocs
    
    def _is_duplicate(self, ioc: IOC) -> bool:
        """Verificar si IOC es duplicado."""
        # Por tipo + valor
        key = f"{ioc.type.value}:{ioc.value.lower()}"
        
        if key in self._seen_values[ioc.type.value]:
            return True
        
        return False
    
    def _add_to_seen(self, ioc: IOC):
        """Agregar IOC al set de vistos."""
        key = f"{ioc.type.value}:{ioc.value.lower()}"
        self._seen_values[ioc.type.value].add(key)
        self._seen_hashes.add(ioc.id)
    
    def merge_iocs(self, existing: IOC, new: IOC) -> IOC:
        """Combinar dos IOCs del mismo valor."""
        # Mantener la primera fecha de aparición
        first_seen = min(existing.first_seen, new.first_seen)
        # Usar la fecha más reciente de última vista
        last_seen = max(existing.last_seen, new.last_seen)
        
        # Combinar tags (sin duplicados)
        all_tags = list(set(existing.tags + new.tags))
        
        # Combinar referencias
        all_refs = list(set(existing.references + new.references))
        
        # Combinar metadata
        combined_metadata = {**existing.metadata, **new.metadata}
        
        # Usar la descripción más larga
        description = existing.description if len(existing.description or "") > len(new.description or "") else new.description
        
        # Mayor confianza y score
        confidence = max(existing.confidence, new.confidence)
        score = max(existing.score, new.score)
        
        # Combinar enrichment data
        enrichment = {**existing.enrichment_data, **new.enrichment_data}
        
        # Combinar fuentes
        sources = list(set(existing.source.split(',') + new.source.split(',')))
        
        return IOC(
            id=existing.id,
            type=existing.type,
            value=existing.value,
            source=','.join(sources),
            first_seen=first_seen,
            last_seen=last_seen,
            status=IOCStatus.ACTIVE,
            tags=all_tags,
            confidence=confidence,
            score=score,
            metadata=combined_metadata,
            description=description,
            references=all_refs,
            enrichment_data=enrichment
        )
    
    def find_similar(self, ioc: IOC, ioc_list: List[IOC]) -> List[IOC]:
        """Encontrar IOCs similares (mismo tipo, valor similar)."""
        similar = []
        
        for other in ioc_list:
            if other.id == ioc.id:
                continue
            
            if other.type != ioc.type:
                continue
            
            # Calcular similitud
            if self._calculate_similarity(ioc.value, other.value) >= self.similarity_threshold:
                similar.append(other)
        
        return similar
    
    def _calculate_similarity(self, value1: str, value2: str) -> float:
        """Calcular similitud entre dos valores."""
        value1 = value1.lower()
        value2 = value2.lower()
        
        if value1 == value2:
            return 1.0
        
        # Similitud simple basada en comunes caracteres
        common = sum(1 for a, b in zip(value1, value2) if a == b)
        max_len = max(len(value1), len(value2))
        
        if max_len == 0:
            return 0.0
        
        return common / max_len
    
    def deduplicate_with_merge(self, iocs: List[IOC], existing_iocs: Dict[str, IOC] = None) -> List[IOC]:
        """Desduplicar y combinar con IOCs existentes."""
        existing_iocs = existing_iocs or {}
        result = []
        merged = set()
        
        for ioc in iocs:
            key = f"{ioc.type.value}:{ioc.value.lower()}"
            
            if key in existing_iocs:
                # Combinar con existente
                merged_ioc = self.merge_iocs(existing_iocs[key], ioc)
                result.append(merged_ioc)
                merged.add(key)
            else:
                result.append(ioc)
                self._add_to_seen(ioc)
        
        # Agregar existentes que no fueron mergeados
        for key, ioc in existing_iocs.items():
            if key not in merged:
                result.append(ioc)
        
        return result
    
    def get_duplicate_count(self, iocs: List[IOC]) -> int:
        """Contar duplicados en una lista."""
        seen = set()
        duplicates = 0
        
        for ioc in iocs:
            key = f"{ioc.type.value}:{ioc.value.lower()}"
            if key in seen:
                duplicates += 1
            else:
                seen.add(key)
        
        return duplicates
    
    def reset(self):
        """Resetear el estado del deduplicador."""
        self._seen_hashes.clear()
        self._seen_values.clear()


# Singleton instance
deduplicator = Deduplicator()
