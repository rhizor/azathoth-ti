# Azathoth-TI - Repository Analysis Report

## Repository Overview

- **Name:** Azathoth TI - Threat Intelligence Platform
- **Language:** Python 3.10+
- **Type:** FastAPI-based Threat Intelligence Platform (TIP)
- **License:** MIT

## Repository Structure

```
azathoth-ti/
├── src/
│   ├── __init__.py
│   ├── __main__.py          # CLI entry point
│   ├── api/
│   │   ├── __init__.py
│   │   └── main.py         # FastAPI application
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── alienvault.py
│   │   ├── abuseipdb.py
│   │   ├── urlhaus.py
│   │   └── base.py
│   ├── processors/
│   │   ├── __init__.py
│   │   ├── deduplicator.py
│   │   └── normalizer.py
│   ├── storage/
│   │   ├── __init__.py
│   │   └── database.py      # SQLite with aiosqlite
│   ├── models.py            # Pydantic models
│   ├── cli.py               # CLI interface
│   └── utils/
│       └── siem.py          # SIEM integration
├── data/
├── docs/
├── requirements.txt
└── README.md
```

## How the Application Runs

```bash
# API Server
python -m src

# CLI
python -m src --help

# With uvicorn directly
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

## Dependencies

```
aiohttp>=3.9.0
fastapi>=0.104.0
uvicorn>=0.24.0
pydantic>=2.5.0
aiosqlite>=0.19.0
redis>=5.0.0           # Optional
elasticsearch>=8.0.0  # Optional
requests>=2.31.0      # Optional
python-dotenv>=1.0.0
pyyaml>=6.0.0
```

## Architecture

- **Pattern:** Layered architecture with FastAPI
- **Components:**
  - **Collectors:** Fetch IOCs from external sources (AlienVault OTX, AbuseIPDB, URLhaus)
  - **Processors:** Normalize and deduplicate IOCs
  - **Storage:** SQLite database with async support
  - **API:** REST endpoints for querying IOCs
  - **CLI:** Command-line interface for operations

## Existing Tests

**None.** No test directory exists.

## Recommended Testing Strategy

1. **Unit tests** for:
   - IOC normalization logic
   - Deduplication algorithms
   - Pydantic model validation
   - Data parsing from collectors

2. **Integration tests** for:
   - Database operations (with test SQLite)
   - API endpoints (using TestClient)

3. **Mock external APIs** - Cannot call real threat feeds in tests

## Potential Reliability Issues

- **External API dependencies:** Collectors rely on external threat feeds (can fail/be rate-limited)
- **Database:** SQLite not suitable for high-concurrency production
- **No authentication** in current API implementation
- **Redis optional** but may cause issues if code assumes it's available

## Environment Variables

```
# Optional
REDIS_URL=redis://localhost:6379
DATABASE_URL=sqlite+aiosqlite:///./threats.db
API_KEY=<optional>
```

## Testing Approach for Docker

The Docker test environment will:
1. Install all dependencies (including test dependencies)
2. Create an isolated test database
3. Run pytest with mocked external API calls

This approach ensures deterministic, reproducible tests.
