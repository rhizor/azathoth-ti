# Azathoth TI - Threat Intelligence Platform

## Project Overview

This repository contains a software component designed to support reliable and maintainable enterprise system operations. The project focuses on clear architecture, deterministic behavior, and reproducible environments to ensure consistent execution across development and operational environments.

The repository has been structured to support automated testing and containerized execution.

## Architecture

High-level architecture:
- **Application Core:** Python-based Threat Intelligence Platform (FastAPI)
- **Supporting Modules:** IOC collectors, processors, storage (SQLite)
- **Test Suite:** Pytest-based automated tests
- **Containerized Runtime Environment:** Docker-based reproducible testing

The design prioritizes modularity and maintainability, allowing the project to evolve without compromising stability.

## Installation

Clone the repository:
```bash
git clone https://github.com/rhizor/azathoth-ti.git
cd azathoth-ti
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

Start the API server:
```bash
python -m src
```

Or with uvicorn:
```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

## Automated Testing

Run the automated test suite locally:
```bash
pytest
```

The tests verify core functionality, validation logic, and error handling.

## Running Tests with Docker

The repository provides a reproducible Docker environment for executing tests.

Build the container:
```bash
docker build -t azathoth-ti-test .
```

Run tests inside the container:
```bash
docker run --rm azathoth-ti-test
```

This ensures the project behaves consistently across environments.

## Reliability and Error Handling

The project includes automated tests designed to validate:
- Core application logic (IOC normalization, deduplication)
- Input validation (IP, domain, URL, hash formats)
- Error handling
- Boundary conditions

This helps ensure predictable system behavior and reduces operational risk.

## AI-Assisted Development Pipeline

This repository supports an automated quality pipeline using AI agents. The pipeline performs:
- Repository analysis
- Automated test execution
- Stacktrace analysis
- Automated fix generation
- Documentation improvements
- Pull request generation

This approach enables continuous improvement of code quality.

## Roadmap

Future improvements may include:
- Extended test coverage for all collectors
- Integration tests for API endpoints
- Performance benchmarks for IOC processing
- Improved observability
