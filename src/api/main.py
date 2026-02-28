"""
Azathoth TI - REST API
API REST para acceder a IOCs.
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import uvicorn

from ..models import IOC, IOCType, IOCStatus
from ..storage.database import Database

# Modelos Pydantic
class IOCResponse(BaseModel):
    id: str
    type: str
    value: str
    source: str
    first_seen: str
    last_seen: str
    status: str
    tags: List[str]
    confidence: float
    score: int
    description: Optional[str] = None
    references: List[str]
    metadata: dict
    enrichment_data: dict

class IOCCreate(BaseModel):
    type: str
    value: str
    source: str
    tags: List[str] = []
    score: int = 0
    description: Optional[str] = None

class StatsResponse(BaseModel):
    total_iocs: int
    active_iocs: int
    by_type: dict
    by_source: dict
    by_tag: dict
    last_updated: str

class SearchQuery(BaseModel):
    type: Optional[str] = None
    value: Optional[str] = None
    source: Optional[str] = None
    status: Optional[str] = None
    min_score: Optional[int] = None
    limit: int = 100
    offset: int = 0

# Inicializar app
app = FastAPI(
    title="Azathoth TI API",
    description="Threat Intelligence Platform API",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instancia de base de datos
db = Database()


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "Azathoth TI",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": "connected"
    }


@app.get("/iocs", response_model=List[IOCResponse])
async def list_iocs(
    type: Optional[str] = Query(None, description="Filter by IOC type"),
    value: Optional[str] = Query(None, description="Search in value"),
    source: Optional[str] = Query(None, description="Filter by source"),
    status: Optional[str] = Query(None, description="Filter by status"),
    min_score: Optional[int] = Query(None, description="Minimum score"),
    limit: int = Query(100, le=1000, description="Max results"),
    offset: int = Query(0, description="Offset")
):
    """Listar IOCs con filtros."""
    ioc_type = IOCType(type) if type else None
    ioc_status = IOCStatus(status) if status else None
    
    iocs = db.search_iocs(
        ioc_type=ioc_type,
        value=value,
        source=source,
        status=ioc_status,
        min_score=min_score,
        limit=limit,
        offset=offset
    )
    
    return [IOCResponse(**ioc.to_dict()) for ioc in iocs]


@app.get("/iocs/{ioc_id}", response_model=IOCResponse)
async def get_ioc(ioc_id: str):
    """Obtener IOC por ID."""
    ioc = db.get_ioc(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return IOCResponse(**ioc.to_dict())


@app.post("/iocs", response_model=IOCResponse)
async def create_ioc(ioc_data: IOCCreate):
    """Crear nuevo IOC."""
    ioc_type = IOCType(ioc_data.type)
    
    ioc = IOC(
        type=ioc_type,
        value=ioc_data.value,
        source=ioc_data.source,
        tags=ioc_data.tags,
        score=ioc_data.score,
        description=ioc_data.description
    )
    
    db.insert_ioc(ioc)
    return IOCResponse(**ioc.to_dict())


@app.delete("/iocs/{ioc_id}")
async def delete_ioc(ioc_id: str):
    """Eliminar IOC."""
    success = db.delete_ioc(ioc_id)
    if not success:
        raise HTTPException(status_code=404, detail="IOC not found")
    return {"status": "deleted", "id": ioc_id}


@app.get("/iocs/search/{value}", response_model=List[IOCResponse])
async def search_iocs(value: str):
    """Buscar IOCs por valor."""
    iocs = db.search_iocs(value=value, limit=100)
    return [IOCResponse(**ioc.to_dict()) for ioc in iocs]


@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Obtener estadísticas."""
    stats = db.get_stats()
    return StatsResponse(**stats.to_dict())


@app.get("/export/json")
async def export_json(
    type: Optional[str] = Query(None, description="Filter by type"),
    output: str = Query("iocs.json", description="Output filename")
):
    """Exportar IOCs a JSON."""
    ioc_type = IOCType(type) if type else None
    db.export_json(output, ioc_type)
    return {"status": "exported", "file": output}


@app.get("/export/csv")
async def export_csv(
    type: Optional[str] = Query(None, description="Filter by type"),
    output: str = Query("iocs.csv", description="Output filename")
):
    """Exportar IOCs a CSV."""
    ioc_type = IOCType(type) if type else None
    db.export_csv(output, ioc_type)
    return {"status": "exported", "file": output}


def run_server(host: str = "0.0.0.0", port: int = 8000, debug: bool = False):
    """Iniciar servidor."""
    uvicorn.run(app, host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_server()
