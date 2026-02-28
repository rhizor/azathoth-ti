# Azathoth TI - Guía de Uso

## Comandos Básicos

### Recopilar IOCs

```bash
# Recopilar de todos los feeds disponibles
python3 -m src collect

# Recopilar solo de AlienVault
python3 -m src collect --feeds alienvault

# Recopilar con enriquecimiento (futuro)
python3 -m src collect --enrich

# Requiere API key configurada
export ALIENVAULT_API_KEY="tu_api_key"
python3 -m src collect
```

### Buscar IOCs

```bash
# Buscar por valor específico
python3 -m src search --value "ejemplo.com"

# Buscar por tipo
python3 -m src search --type ip

# Buscar por tipo y valor
python3 -m src search --type domain --value "malicious.com"
```

### Estadísticas

```bash
# Ver estadísticas de la base de datos
python3 -m src stats
```

### Exportar

```bash
# Exportar a JSON
python3 -m src export --format json --output iocs

# Exportar a CSV
python3 -m src export --format csv --output iocs

# Exportar solo un tipo
python3 -m src export --format json --output dominios --type domain
```

## Servidor API

### Iniciar Servidor

```bash
# Puerto por defecto (8000)
python3 -m src server

# Puerto específico
python3 -m src server --port 9000

# Con modo debug
python3 -m src server --debug
```

### Endpoints de la API

```
GET  /                    # Info del servidor
GET  /health             # Health check
GET  /iocs               # Listar IOCs
GET  /iocs/{id}          # Ver IOC específico
GET  /iocs/search/{value} # Buscar por valor
GET  /stats              # Estadísticas
GET  /export/json        # Exportar JSON
GET  /export/csv         # Exportar CSV
```

### Ejemplos con cURL

```bash
# Health check
curl http://localhost:8000/health

# Listar IOCs
curl http://localhost:8000/iocs?limit=10

# Buscar IOCs
curl "http://localhost:8000/iocs?type=domain&value=ejemplo"

# Estadísticas
curl http://localhost:8000/stats
```

## Configuración

### Base de datos personalizada

```bash
# Usar base de datos diferente
python3 -m src --db /path/to/database.db collect
python3 -m src --db /path/to/database.db stats
```

### Python API

```python
import asyncio
from src.collectors.alienvault import AlienVaultCollector
from src.storage.database import Database

async def ejemplo():
    # Conectar a base de datos
    db = Database()
    
    # Recopilar IOCs
    collector = AlienVaultCollector("tu_api_key")
    async with collector:
        iocs = await collector.collect()
        
        # Guardar en DB
        db.insert_iocs(iocs)
        
    # Buscar
    resultados = db.search_iocs(ioc_type=IOCType.DOMAIN)
    
    # Estadísticas
    stats = db.get_stats()

asyncio.run(ejemplo())
```

## Fuentes de IOCs

### AlienVault OTX (requiere API key)

- **API Key**: https://otx.alienvault.com/api
- **Características**: Dominios, URLs, hashes, IPs
- **Límite**:取决于 suscripción

### AbuseIPDB (requiere API key)

- **API Key**: https://www.abuseipdb.com/account/api
- **Características**: IPs maliciosas
- **Gratis**: 10,000 queries/mes

### URLhaus (sin API key)

- **URL**: https://urlhaus-api.abuse.ch/
- **Características**: URLs maliciosas
- **Nota**: Requiere API key para algunos endpoints

### ThreatFox (sin API key)

- **URL**: https://threatfox-api.abuse.ch/
- **Características**: IOCs de malware
- **Nota**: API en desarrollo

## Formato de IOCs

### Estructura

```json
{
  "id": "a1b2c3d4e5f6",
  "type": "domain",
  "value": "malicious.com",
  "source": "alienvault:pulse_id",
  "first_seen": "2024-01-01T00:00:00",
  "last_seen": "2024-01-15T00:00:00",
  "status": "active",
  "tags": ["malware", "phishing"],
  "confidence": 0.8,
  "score": 75,
  "description": "Pulse name",
  "references": ["https://otx.alienvault.com/pulse/..."],
  "metadata": {},
  "enrichment_data": {}
}
```

### Tipos de IOCs

| Tipo | Descripción | Ejemplo |
|------|-------------|---------|
| `ip` | Dirección IP | 192.168.1.1 |
| `domain` | Dominio | malicious.com |
| `url` | URL | https://evil.com/payload |
| `hash_md5` | Hash MD5 | d41d8cd98f00b204e9800998ecf8427e |
| `hash_sha1` | Hash SHA1 | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| `hash_sha256` | Hash SHA256 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| `email` | Email | attacker@evil.com |
| `cve` | CVE | CVE-2024-0001 |

## Integración con SIEM

### Elasticsearch

```python
from src.utils.siem import SIEMExporter

exporter = SIEMExporter()
exporter.send_to_elasticsearch(
    iocs=list_of_iocs,
    host="https://elasticsearch:9200",
    index="threat-intel",
    api_key="tu_api_key"
)
```

### Splunk

```python
exporter.send_to_splunk(
    iocs=list_of_iocs,
    host="https://splunk:8088",
    token="tu_hec_token"
)
```

## Mejores Prácticas

1. **Configura API keys**: Obtén keys de AlienVault y/o AbuseIPDB
2. **Programa recollecciones**: Usa cron para ejecutar `python3 -m src collect` regularmente
3. **Exporta regularmente**: Haz backup de la base de datos
4. **Monitorea**: Revisa estadísticas periódicamente
5. **Filtra por score**: Usa `--min-score` para filtrar IOCs de alta confianza
