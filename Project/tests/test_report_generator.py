from report_generator import OllamaReportGenerator
from requests import ConnectionError


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"response": "# Security Advisory Digest\n\n## Critical Issues\nOne issue."}


class FakeHttp:
    def post(self, url, **kwargs):
        return FakeResponse()


def test_report_generator_uses_ollama_response():
    report = OllamaReportGenerator(http_client=FakeHttp()).generate(
        [{"product": "openssl", "affected": True, "severity": "critical"}]
    )

    assert report.startswith("# Security Advisory Digest")


class FailingHttp:
    def post(self, url, **kwargs):
        raise ConnectionError("Ollama is not running")


def test_report_generator_falls_back_when_ollama_unavailable():
    report = OllamaReportGenerator(http_client=FailingHttp()).generate(
        [{"product": "openssl", "affected": True, "severity": "critical"}]
    )

    assert report.startswith("# Security Advisory Digest")
    assert "1 finding(s)" in report
