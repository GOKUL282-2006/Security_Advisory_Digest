# AI Usage Note

## AI tools used

Codex was used to scaffold and implement the advisory clients, unified model, repository, RAG engine, agent workflow, API, frontend, tests, documentation, and audit report.

## Tasks AI assisted with

- Designing a unified advisory schema for NVD, GitHub Advisory, and OSV sources.
- Implementing API clients and normalizers.
- Building SQLite persistence and deduplication.
- Creating an agent loop for inventory matching and finding generation.
- Drafting Ollama prompt templates and Markdown report generation.
- Creating FastAPI, Streamlit, MCP, tests, sample data, and README content.

## Incorrect AI outputs encountered

No generated code should be assumed correct without execution. Because command execution was unavailable during implementation, dependency compatibility and test execution still require local verification.

## How outputs were verified

The implementation was reviewed for consistent schemas, dependency injection points, deterministic tests using fakes, and sample-data alignment. Full verification should be completed with `pytest`, API startup, Streamlit startup, and MCP startup.

## Best prompts used

- "Normalize all advisory feeds into one schema and keep client-specific legacy output available where required."
- "Use dependency injection so network and model calls can be tested with fakes."
- "Create demo data that produces meaningful matches for the inventory."
