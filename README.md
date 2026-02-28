# Azathoth TI 🌀

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.104+-green.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

> Plataforma de Threat Intelligence (TIP) que recopila, normaliza y correlaciona Indicadores de Compromiso (IOCs) de fuentes públicas.

## 📖 Descripción

**Azathoth TI** es una plataforma de inteligencia de amenazas que automatiza la recopilación de IOCs de múltiples fuentes públicas, los normaliza, desduplica y los almacena para su integración con SIEM. Permite a los analistas enfocarse en investigar y responder en lugar de recopilar datos manualmente.

> *"The oldest and strongest kind of fear is fear of the unknown"* — H.P. Lovecraft, Lovecraft

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AZATHOTH TI ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                    │
│  │   FEEDS     │   │   FEEDS     │   │   FEEDS     │                    │
│  │  AlienVault │   │   AbuseIPDB │   │   ThreatFox │                    │
│  │   OTX      │   │             │   │             │                    │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘                    │
│         │                  │                  │                             │
│         └──────────────────┼──────────────────┘                             │
│                            ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    COLLECTOR LAYER                                  │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │    │
│  │  │   Fetch    │  │   Parse    │  │   Validate │             │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘             │    │
│  └──────────────────────────┬──────────────────────────────────────────┘    │
│                             ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                  PROCESSOR LAYER                                     │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │    │
│  │  │  Normalize │  │ Deduplicate│  │   Enrich   │  │  Correlate│ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘ │    │
│  └──────────────────────────┬──────────────────────────────────────────┘    │
│                             ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    STORAGE LAYER                                    │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │    │
│  │  │  SQLite    │  │   Redis    │  │   JSON     │              │    │
│  │  │ (Primary)  │  │  (Cache)   │  │  (Export)  │              │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │    │
│  └──────────────────────────┬──────────────────────────────────────────┘    │
│                             ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      API LAYER                                      │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │    │
│  │  │  REST API  │  │  GraphQL   │  │   Web UI   │              │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## ⚡ Características

- **Recopilación Automatizada**: Obtiene IOCs de múltiples fuentes públicas
- **Normalización**: Convierte IOCs a formato estándar (STIX-like)
- **Desduplicación**: Elimina IOCs duplicados automáticamente
- **Enriquecimiento**: Agrega contexto adicional (geolocalización, reputación)
- **Correlación**: Relaciona IOCs con eventos del SIEM
- **API REST**: Acceso programático a los datos
- **Export**: Formatos JSON, CSV, STIX

## 🚀 Instalación

### Requisitos

- Python 3.10+
- Redis (opcional, para cache)

### Instalación con Entorno Virtual

```bash
# Clonar repositorio
git clone https://github.com/rhizor/azathoth-ti.git
cd azathoth-ti

# Crear entorno virtual
python3 -m venv venv

# Activar
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Copiar configuración
cp config.example.yaml config.yaml

# Editar configuración
nano config.yaml

# Iniciar servidor
python -m src.api.main
```

## 📦 Uso

### Iniciar Servidor API

```bash
# Servidor por defecto
python -m src.api.main

# Puerto específico
python -m src.api.main --port 9000

# Con debug
python -m src.api.main --debug
```

### Recopilar IOCs

```bash
# Recopilar de todas las fuentes
python -m src.collectors.run --all

# Recopilar de fuente específica
python -m src.collectors.run --feed alienvault

# Recopilar con enriquecimiento
python -m src.collectors.run --all --enrich
```

### Buscar IOCs

```bash
# Buscar por tipo
python -m src.cli search --type ip --value 192.168.1.1

# Buscar por dominio
python -m src.cli search --type domain --value malicious.com

# Buscar por hash
python -m src.cli search --type hash abc123...
```

## 📡 Fuentes de IOCs Soportadas

| Fuente | Tipo | Estado |
|--------|------|--------|
| AlienVault OTX | IP, Domain, Hash, URL | ✅ |
| AbuseIPDB | IP | ✅ |
| ThreatFox | Malware IOCs | ✅ |
| URLhaus | URLs maliciosas | ✅ |
| CyberCrime Tracker | URLs/IPs maliciosas | ✅ |

## 🔌 Integración con SIEM

### Enviar a Elasticsearch

```bash
python -m src.export elasticsearch --index iocs --host localhost:9200
```

### Exportar a JSON

```bash
python -m src.export json --output iocs.json
```

### Formato STIX

```bash
python -m src.export stix --output iocs.stix
```

## ⚙️ Configuración

```yaml
# config.yaml
database:
  type: sqlite
  path: data/azathoth.db

redis:
  host: localhost
  port: 6379

collectors:
  alienvault:
    enabled: true
    api_key: YOUR_API_KEY
  abuseipdb:
    enabled: true
    api_key: YOUR_API_KEY

enrichment:
  enabled: true
  providers:
    - virustotal
    - shodan

api:
  host: 0.0.0.0
  port: 8000
```

## 📁 Estructura del Proyecto

```
azathoth-ti/
├── src/
│   ├── api/              # API REST
│   ├── collectors/      # Recopiladores de feeds
│   ├── processors/      # Normalizadores, deduplicadores
│   ├── storage/         # Acceso a base de datos
│   ├── utils/          # Utilidades
│   └── cli.py          # Interfaz CLI
├── configs/             # Archivos de configuración
├── feeds/              # Configuraciones de feeds
├── tests/              # Tests unitarios
├── docs/              # Documentación
│   ├── INSTALL.md     # Guía de instalación
│   ├── USAGE.md      # Guía de uso
│   └── API.md        # Documentación API REST
└── requirements.txt
```

## 📚 Documentación

Consulta la documentación detallada en la carpeta `docs/`:

- **[INSTALL.md](docs/INSTALL.md)** - Guía completa de instalación
- **[USAGE.md](docs/USAGE.md)** - Guía detallada de uso con ejemplos
- **[API.md](docs/API.md)** - Documentación de la REST API

## 🧪 Testing

```bash
# Ejecutar tests
pytest

# Con coverage
pytest --cov=src

# Tests específicos
pytest tests/test_collectors.py -v
```

## 📡 API Endpoints

```
GET  /health                 # Health check
GET  /iocs                   # Listar IOCs
POST /iocs                   # Crear IOC
GET  /iocs/{id}             # Ver IOC específico
GET  /iocs/search           # Buscar IOCs
GET  /feeds                 # Listar feeds
POST /feeds/collect          # Forzar recolección
GET  /stats                 # Estadísticas
GET  /export/json           # Exportar JSON
GET  /export/csv           # Exportar CSV
```

## 🤝 Contribuir

1. Fork el proyecto
2. Crear rama (`git checkout -b feature/nueva-caracteristica`)
3. Commitear cambios
4. Pushear y crear Pull Request

## 📜 Licencia

MIT License

---

<p align="center">
  <i>"That is not dead which can eternal lie, and with strange aeons even death may die."</i>
  <br>— H.P. Lovecraft, The Nameless City
</p>
