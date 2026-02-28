"""
Azathoth TI - Storage Layer
Almacenamiento de IOCs en SQLite.
"""

import sqlite3
import json
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path
from ..models import IOC, IOCType, IOCStatus, Feed, Stats


class Database:
    """Base de datos SQLite para IOCs."""
    
    def __init__(self, db_path: str = "data/azathoth.db"):
        """Inicializar base de datos."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Inicializar schema de base de datos."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT NOT NULL,
                    tags TEXT,
                    confidence REAL,
                    score INTEGER,
                    metadata TEXT,
                    description TEXT,
                    ioc_references TEXT,
                    enrichment_data TEXT,
                    UNIQUE(type, value)
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source)
            """)
            
            # Tabla de feeds
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feeds (
                    name TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    type TEXT NOT NULL,
                    enabled INTEGER,
                    last_fetch TEXT,
                    fetch_interval INTEGER,
                    ioc_count INTEGER,
                    error_count INTEGER,
                    last_error TEXT
                )
            """)
            
            # Tabla de configuración
            conn.execute("""
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            
            conn.commit()
    
    def _row_to_ioc(self, row: sqlite3.Row) -> IOC:
        """Convertir fila a IOC."""
        return IOC(
            id=row["id"],
            type=IOCType(row["type"]),
            value=row["value"],
            source=row["source"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            status=IOCStatus(row["status"]),
            tags=json.loads(row["tags"]) if row["tags"] else [],
            confidence=row["confidence"],
            score=row["score"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            description=row["description"],
            references=json.loads(row["ioc_references"]) if row["ioc_references"] else [],
            enrichment_data=json.loads(row["enrichment_data"]) if row["enrichment_data"] else {}
        )
    
    def insert_ioc(self, ioc: IOC) -> bool:
        """Insertar o actualizar IOC."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO iocs (
                    id, type, value, source, first_seen, last_seen,
                    status, tags, confidence, score, metadata,
                    description, ioc_references, enrichment_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ioc.id,
                ioc.type.value,
                ioc.value,
                ioc.source,
                ioc.first_seen.isoformat(),
                ioc.last_seen.isoformat(),
                ioc.status.value,
                json.dumps(ioc.tags),
                ioc.confidence,
                ioc.score,
                json.dumps(ioc.metadata),
                ioc.description,
                json.dumps(ioc.references),
                json.dumps(ioc.enrichment_data)
            ))
            conn.commit()
        return True
    
    def insert_iocs(self, iocs: List[IOC]) -> int:
        """Insertar múltiples IOCs."""
        count = 0
        with sqlite3.connect(self.db_path) as conn:
            for ioc in iocs:
                try:
                    conn.execute("""
                        INSERT OR REPLACE INTO iocs (
                            id, type, value, source, first_seen, last_seen,
                            status, tags, confidence, score, metadata,
                            description, ioc_references, enrichment_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ioc.id,
                        ioc.type.value,
                        ioc.value,
                        ioc.source,
                        ioc.first_seen.isoformat(),
                        ioc.last_seen.isoformat(),
                        ioc.status.value,
                        json.dumps(ioc.tags),
                        ioc.confidence,
                        ioc.score,
                        json.dumps(ioc.metadata),
                        ioc.description,
                        json.dumps(ioc.references),
                        json.dumps(ioc.enrichment_data)
                    ))
                    count += 1
                except sqlite3.IntegrityError:
                    pass
            conn.commit()
        return count
    
    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        """Obtener IOC por ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM iocs WHERE id = ?",
                (ioc_id,)
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_ioc(row)
        return None
    
    def get_ioc_by_value(self, ioc_type: IOCType, value: str) -> Optional[IOC]:
        """Obtener IOC por tipo y valor."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM iocs WHERE type = ? AND value = ?",
                (ioc_type.value, value)
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_ioc(row)
        return None
    
    def search_iocs(
        self,
        ioc_type: Optional[IOCType] = None,
        value: Optional[str] = None,
        source: Optional[str] = None,
        status: Optional[IOCStatus] = None,
        tags: Optional[List[str]] = None,
        min_score: Optional[int] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[IOC]:
        """Buscar IOCs con filtros."""
        query = "SELECT * FROM iocs WHERE 1=1"
        params = []
        
        if ioc_type:
            query += " AND type = ?"
            params.append(ioc_type.value)
        
        if value:
            query += " AND value LIKE ?"
            params.append(f"%{value}%")
        
        if source:
            query += " AND source LIKE ?"
            params.append(f"%{source}%")
        
        if status:
            query += " AND status = ?"
            params.append(status.value)
        
        if min_score is not None:
            query += " AND score >= ?"
            params.append(min_score)
        
        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [self._row_to_ioc(row) for row in cursor.fetchall()]
    
    def get_stats(self) -> Stats:
        """Obtener estadísticas."""
        with sqlite3.connect(self.db_path) as conn:
            # Total
            total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            
            # Activos
            active = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE status = ?",
                (IOCStatus.ACTIVE.value,)
            ).fetchone()[0]
            
            # Por tipo
            by_type = {}
            for row in conn.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type"):
                by_type[row[0]] = row[1]
            
            # Por fuente
            by_source = {}
            for row in conn.execute("SELECT source, COUNT(*) FROM iocs GROUP BY source"):
                by_source[row[0]] = row[1]
            
            # Por tag
            by_tag = {}
            
            return Stats(
                total_iocs=total,
                active_iocs=active,
                by_type=by_type,
                by_source=by_source,
                by_tag=by_tag,
                last_updated=datetime.now()
            )
    
    def delete_ioc(self, ioc_id: str) -> bool:
        """Eliminar IOC."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def clear_expired(self, days: int = 30) -> int:
        """Eliminar IOCs expirados."""
        from datetime import timedelta
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM iocs WHERE status = ? AND last_seen < ?",
                (IOCStatus.EXPIRED.value, cutoff)
            )
            conn.commit()
            return cursor.rowcount
    
    def export_json(self, filepath: str, ioc_type: Optional[IOCType] = None):
        """Exportar IOCs a JSON."""
        iocs = self.search_iocs(ioc_type=ioc_type, limit=100000)
        
        with open(filepath, "w") as f:
            json.dump([ioc.to_dict() for ioc in iocs], f, indent=2)
    
    def export_csv(self, filepath: str, ioc_type: Optional[IOCType] = None):
        """Exportar IOCs a CSV."""
        iocs = self.search_iocs(ioc_type=ioc_type, limit=100000)
        
        import csv
        
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "type", "value", "source", "first_seen", "last_seen", "status", "tags", "score"])
            
            for ioc in iocs:
                writer.writerow([
                    ioc.id,
                    ioc.type.value,
                    ioc.value,
                    ioc.source,
                    ioc.first_seen.isoformat(),
                    ioc.last_seen.isoformat(),
                    ioc.status.value,
                    ",".join(ioc.tags),
                    ioc.score
                ])


# Singleton instance
db = Database()
