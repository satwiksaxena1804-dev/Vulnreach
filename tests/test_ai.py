from __future__ import annotations

import json

import pytest
from support import DEMO_ADVISORIES, DEMO_APP

from vulnreach.ai.explain import LlmConfig, explain_finding, template_explanation
from vulnreach.api import ScanConfig, analyze_project
from vulnreach.report.json_report import build_report


@pytest.fixture
def finding() -> dict:
    result = analyze_project(
        ScanConfig(
            root=DEMO_APP,
            offline=True,
            advisory_dirs=(DEMO_ADVISORIES,),
            no_cache=True,
        )
    )
    report = build_report(result)
    return next(item for item in report["findings"] if item["verdict"] == "reachable")


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def test_template_explanation_contains_path(finding):
    explanation = template_explanation(finding)
    assert "confidence" in explanation.summary
    assert any("app.fetch_status" in item for item in explanation.evidence)
    assert explanation.next_steps


def test_missing_llm_config_falls_back(monkeypatch, finding):
    for variable in (
        "VULNREACH_LLM_BASE_URL",
        "VULNREACH_LLM_MODEL",
        "VULNREACH_LLM_API_KEY",
    ):
        monkeypatch.delenv(variable, raising=False)
    explanation = explain_finding(finding, use_ai=True)
    assert explanation.ai_generated is False
    assert explanation.notice is not None
    assert "not all set" in explanation.notice


def test_model_explanation_does_not_change_verdict(monkeypatch, finding):
    monkeypatch.setenv("VULNREACH_LLM_BASE_URL", "https://model.test/v1")
    monkeypatch.setenv("VULNREACH_LLM_MODEL", "open-weight-test")
    monkeypatch.setenv("VULNREACH_LLM_API_KEY", "secret")
    content = json.dumps(
        {
            "summary": "The application calls the vulnerable fetch function.",
            "evidence": ["app.fetch_status calls fetch"],
            "next_steps": ["Upgrade the package"],
            "verdict": "not_reachable",
        }
    )
    payload = {"choices": [{"message": {"content": content}}]}

    def fake_urlopen(request, timeout=0):
        assert request.full_url == "https://model.test/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer secret"
        return FakeResponse(payload)

    monkeypatch.setattr("vulnreach.ai.explain.urllib.request.urlopen", fake_urlopen)
    explanation = explain_finding(finding, use_ai=True)
    assert explanation.ai_generated is True
    assert explanation.model == "open-weight-test"
    assert explanation.verdict == finding["verdict"] == "reachable"
    assert explanation.summary.startswith("The application calls")


def test_invalid_model_output_falls_back(monkeypatch, finding):
    monkeypatch.setenv("VULNREACH_LLM_BASE_URL", "https://model.test/v1")
    monkeypatch.setenv("VULNREACH_LLM_MODEL", "open-weight-test")
    monkeypatch.setenv("VULNREACH_LLM_API_KEY", "secret")
    payload = {"choices": [{"message": {"content": "I think it is fine."}}]}

    monkeypatch.setattr(
        "vulnreach.ai.explain.urllib.request.urlopen",
        lambda *args, **kwargs: FakeResponse(payload),
    )
    explanation = explain_finding(finding, use_ai=True)
    assert explanation.ai_generated is False
    assert "AI explanation unavailable" in explanation.notice


def test_llm_config_from_env(monkeypatch):
    monkeypatch.setenv("VULNREACH_LLM_BASE_URL", "https://model.test/v1")
    monkeypatch.setenv("VULNREACH_LLM_MODEL", "m")
    monkeypatch.setenv("VULNREACH_LLM_API_KEY", "k")
    config = LlmConfig.from_env()
    assert config is not None
    assert config.model == "m"
