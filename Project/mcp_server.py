from __future__ import annotations

from fastmcp import FastMCP

from advisory_repository import AdvisoryRepository
from advisor_agent import AdvisorAgent
from inventory_parser import parse_inventory
from report_generator import ReportGenerator

mcp = FastMCP("security-advisory-digest")


@mcp.tool()
def get_inventory(path: str = "data/stack.yaml") -> list[dict[str, str | None]]:
    return [item.to_dict() for item in parse_inventory(path)]


@mcp.tool()
def search_advisories(product: str) -> list[dict[str, object]]:
    return [advisory.to_dict() for advisory in AdvisoryRepository().query(product=product)]


@mcp.tool()
def generate_digest(inventory_path: str = "data/stack.yaml") -> str:
    findings = AdvisorAgent(AdvisoryRepository()).run(inventory_path)
    return ReportGenerator().generate(findings)


if __name__ == "__main__":
    mcp.run()
