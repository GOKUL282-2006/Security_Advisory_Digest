from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse

from advisory_repository import AdvisoryRepository
from advisor_agent import AdvisorAgent
from report_generator import ReportGenerator

app = FastAPI(
    title="Security Advisory Digest API",
    description="Inventory scanning, advisory matching, and AI digest generation.",
    version="1.0.0",
)

STATE: dict[str, object] = {"inventory_path": None, "findings": [], "report": ""}


def get_repository() -> AdvisoryRepository:
    return AdvisoryRepository()


def get_agent(repository: AdvisoryRepository = Depends(get_repository)) -> AdvisorAgent:
    return AdvisorAgent(repository)


def get_report_generator() -> ReportGenerator:
    return ReportGenerator()


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/inventory/upload", tags=["inventory"])
async def upload_inventory(file: UploadFile = File(...)) -> dict[str, str]:
    uploads = Path("uploads")
    uploads.mkdir(exist_ok=True)
    filename = Path(file.filename or "inventory.yaml").name
    if Path(filename).suffix.lower() not in {".yaml", ".yml"}:
        raise HTTPException(status_code=400, detail="Inventory must be a .yaml or .yml file")
    target = uploads / filename
    target.write_bytes(await file.read())
    STATE["inventory_path"] = str(target)
    return {"message": "inventory uploaded", "path": str(target)}


@app.post("/scan", tags=["scan"])
def scan(agent: AdvisorAgent = Depends(get_agent)) -> list[dict[str, object]]:
    inventory_path = STATE.get("inventory_path") or "data/stack.yaml"
    if not Path(str(inventory_path)).exists():
        raise HTTPException(status_code=400, detail="No inventory uploaded and data/stack.yaml is missing")
    try:
        findings = agent.run(str(inventory_path))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    STATE["findings"] = findings
    return findings


@app.get("/report", response_class=PlainTextResponse, tags=["report"])
def report(generator: ReportGenerator = Depends(get_report_generator)) -> str:
    findings = STATE.get("findings")
    if not findings:
        raise HTTPException(status_code=400, detail="Run /scan before requesting a report")
    markdown = generator.generate(findings)  # type: ignore[arg-type]
    STATE["report"] = markdown
    return markdown
