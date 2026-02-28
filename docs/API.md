# Azathoth TI - API REST

## Iniciar Servidor

```bash
# Puerto por defecto
python3 -m src server

# Puerto específico
python3 -m src server --port 8000

# Con debug
python3 -m src server --debug
```

La API estará disponible en: `http://localhost:8000`

## Documentación Interactiva

Cuando el servidor está corriendo, visita:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Endpoints

### Health Check

```http
GET /health
```

Respuesta:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Listar IOCs

```http
GET /iocs
```

Parámetros query:
| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `type` | string | Filtrar por tipo (ip, domain, url, etc.) |
| `value` | string | Buscar en valor |
| `source` | string | Filtrar por fuente |
| `status` | string | Filtrar por estado |
| `min_score` | int | Score mínimo |
| `limit` | int | Límite de resultados (default: 100) |
| `offset` | int | Offset para paginación |

Ejemplo:
```bash
curl "http://localhost:8000/iocs?type=domain&limit=10"
```

### Obtener IOC por ID

```http
GET /iocs/{id}
```

Ejemplo:
```bash
curl http://localhost:8000/iocs/a1b2c3d4e5f6
```

### Buscar IOCs

```http
GET /iocs/search/{value}
```

Ejemplo:
```bash
curl "http://localhost:8000/iocs/search/ejemplo.com"
```

### Crear IOC

```http
POST /iocs
```

Body:
```json
{
  "type": "domain",
  "value": "malicious.com",
  "source": "manual",
  "tags": ["malware"],
  "score": 80,
  "description": "Malicious domain"
}
```

### Eliminar IOC

```http
DELETE /iocs/{id}
```

### Estadísticas

```http
GET /stats
```

Respuesta:
```json
{
  "total_iocs": 1000,
  "active_iocs": 800,
  "by_type": {
    "domain": 500,
    "ip": 300,
    "url": 200
  },
  "by_source": {
    "alienvault": 800,
    "abuseipdb": 200
  },
  "last_updated": "2024-01-01T00:00:00Z"
}
```

### Exportar a JSON

```http
GET /export/json
```

Parámetros:
| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `type` | string | Filtrar por tipo |

Ejemplo:
```bash
curl "http://localhost:8000/export/json?type=domain" -o dominios.json
```

### Exportar a CSV

```http
GET /export/csv
```

Ejemplo:
```bash
curl "http://localhost:8000/export/csv" -o iocs.csv
```

## Ejemplos de Uso

### Python

```python
import requests

base_url = "http://localhost:8000"

# Health check
response = requests.get(f"{base_url}/health")
print(response.json())

# Listar IOCs
response = requests.get(f"{base_url}/iocs", params={"type": "domain", "limit": 10})
iocs = response.json()

# Buscar
response = requests.get(f"{base_url}/iocs/search/malicious.com")
print(response.json())

# Crear IOC
new_ioc = {
    "type": "ip",
    "value": "192.168.1.100",
    "source": "manual",
    "tags": ["test"],
    "score": 50
}
response = requests.post(f"{base_url}/iocs", json=new_ioc)

# Obtener stats
response = requests.get(f"{base_url}/stats")
print(response.json())
```

### cURL

```bash
# Health check
curl http://localhost:8000/health

# Listar IOCs
curl "http://localhost:8000/iocs?limit=5"

# Buscar
curl "http://localhost:8000/iocs/search/ejemplo.com"

# Stats
curl http://localhost:8000/stats

# Exportar
curl "http://localhost:8000/export/json" -o iocs.json
```

### JavaScript

```javascript
const baseUrl = 'http://localhost:8000';

// Health check
fetch(`${baseUrl}/health`)
  .then(res => res.json())
  .then(data => console.log(data));

// Listar IOCs
fetch(`${baseUrl}/iocs?type=domain&limit=10`)
  .then(res => res.json())
  .then(iocs => console.log(iocs));

// Crear IOC
fetch(`${baseUrl}/iocs`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    type: 'ip',
    value: '10.0.0.1',
    source: 'manual',
    score: 50
  })
});
```

## Códigos de Estado

| Código | Descripción |
|--------|-------------|
| 200 | OK |
| 201 | Creado |
| 404 | No encontrado |
| 422 | Error de validación |
| 500 | Error del servidor |

## Rate Limiting

Por defecto, no hay rate limiting. Para producción, configura un proxy como nginx.
