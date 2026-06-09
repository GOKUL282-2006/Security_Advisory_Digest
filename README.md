# Security Advisory Digest

Security Advisory Digest scans a software inventory, matches known advisories from multiple feeds, and generates an AI-assisted Markdown digest.

## Project Overview

The project supports:

- GitHub Security Advisory API ingestion.
- OSV API ingestion.
- NVD API ingestion.
- A unified advisory model for NVD, GitHub, and OSV.
- SQLite advisory storage with deduplication by advisory ID.
- Semantic advisory search with ChromaDB and `all-MiniLM-L6-v2`.
- An agent loop that reads inventory, finds related advisories, evaluates version relevance, and emits findings.
- Ollama-powered digest generation using `llama3`.
- FastAPI and Streamlit interfaces.
- FastMCP tools for inventory, advisory search, and digest generation.

## Architecture Diagram

```text
Inventory YAML
    |
    v
Inventory Parser ---> Advisor Agent ---> Findings ---> Ollama Report Generator
                         |
                         v
             SQLite Advisory Repository
                         ^
                         |
       GitHub / OSV / NVD Normalized Advisory Schema
                         |
                         v
                 ChromaDB RAG Engine

FastAPI exposes upload, scan, report, health.
Streamlit consumes FastAPI.
FastMCP exposes get_inventory, search_advisories, generate_digest.
```

## Setup

Use Python 3.11 or newer.

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

If `requirements.txt` is not present yet, install:

```bash
pip install fastapi uvicorn streamlit requests pyyaml pytest chromadb sentence-transformers fastmcp python-multipart
```

## Installation

Seed the sample advisories into SQLite before running the demo.

```bash
python seed_advisories.py
```

## Running Locally

```bash
uvicorn app:app --reload
```

Swagger documentation is available at:

```text
http://localhost:8000/docs
```

## Running Ollama

```bash
ollama pull llama3
ollama serve
```

The report generator calls:

```text
http://localhost:11434/api/generate
```

## Running Streamlit

```bash
streamlit run streamlit_app.py
```

## Running Tests

```bash
pytest --cov=. --cov-report=term-missing
```

## Demo Scenario

Use `data/stack.yaml` and `data/sample_advisories.json`. The sample inventory includes `openssl`, `log4j`, and `requests`, and the sample advisory data includes matching advisories for those products.

## MCP Demo

```bash
python mcp_server.py
```

Available tools:

- `get_inventory(path="data/stack.yaml")`
- `search_advisories(product="openssl")`
- `generate_digest(inventory_path="data/stack.yaml")`

## Limitations

- Version relevance is heuristic and should be replaced with ecosystem-specific version range evaluation.
- NVD fetching is implemented with a dedicated client, but live API use still needs network access and optional API-key configuration.
- RAG tests should use fakes in CI unless ChromaDB and sentence-transformers are installed.
- Ollama must be running locally for live report generation.

## Future Enhancements

- Add a dedicated NVD API client.
- Add EPSS and KEV prioritization.
- Implement ecosystem-specific semantic version comparison.
- Add authentication and multi-tenant storage for production deployments.
- Add scheduled advisory ingestion jobs.
