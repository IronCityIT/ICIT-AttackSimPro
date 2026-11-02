"""tools/asp_consensus.py: normalization, engine pairing, white-label, honesty."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import asp_consensus as ac  # noqa: E402

VENDOR_WORDS = ("openrouter", "groq", "gemini", "claude", "anthropic", "llama", "gpt-", "mistral", "qwen", "deepseek")
TOOL_WORDS = ("zap", "nuclei", "metasploit", "projectdiscovery")

WEB_REPORT = {
    "@programName": "ZAP",
    "site": [
        {
            "@name": "https://www.example.test",
            "alerts": [
                {
                    "pluginid": "10038",
                    "alertRef": "10038-1",
                    "name": "Content Security Policy (CSP) Header Not Set",
                    "riskcode": "2",
                    "confidence": "3",
                    "desc": "<p>Content Security Policy (CSP) is an added layer of security. ZAP found it missing.</p>",
                    "solution": "<p>Ensure that your web server sets the Content-Security-Policy header.</p>",
                    "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP\nhttps://owasp.org/x",
                    "cweid": "693",
                    "count": "4",
                    "instances": [{"uri": "https://www.example.test/"}, {"uri": "https://www.example.test/a"}],
                },
                {
                    "pluginid": "10109",
                    "alertRef": "10109",
                    "name": "Modern Web Application",
                    "riskcode": "0",
                    "desc": "<p>The application appears to be a modern web application.</p>",
                    "solution": "<p>This is an informational alert and so no changes are required.</p>",
                    "cweid": "-1",
                    "instances": [],
                },
                {
                    "pluginid": "10020",
                    "alertRef": "10020-1",
                    "name": "Missing Anti-clickjacking Header",
                    "riskcode": "2",
                    "desc": "<p>The response does not protect against clickjacking.</p>",
                    "solution": "<p>Use X-Frame-Options or CSP frame-ancestors.</p>",
                    "cweid": "1021",
                    "instances": [{"uri": "https://www.example.test/"}],
                },
            ],
        }
    ],
}


def engine_entry(successful: int = 13, total: int = 15, severity: str = "MEDIUM", tag: str = "csp") -> dict:
    """The shape consensus-engine's ConsensusResult serialises to (asdict)."""
    return {
        "consensus_severity": severity,
        "confidence_percent": 81.4,
        "exploitability": "MEDIUM",
        "impact": "HIGH",
        "false_positive_likelihood": "LOW",
        "internet_exposed": True,
        "compliance_impact": {
            "frameworks": ["SOC2", "PCI-DSS", "NIST"],
            "control_domains": ["Application Security"],
            "control_mappings": {"SOC2": ["CC6.6"], "PCI-DSS": ["6.4.3"]},
            "audit_risk": "MEDIUM",
            "breach_notification_risk": False,
        },
        "aggregated_remediation": [
            f"Deploy a {tag} Content-Security-Policy starting in report-only mode using default-src 'self'",
            f"deploy a {tag} content-security-policy starting in report-only mode using default-src 'self'.",
            "Verify with OWASP ZAP and remove inline scripts so the policy can be enforced",
        ],
        "verification_steps": ["Request the page and confirm the Content-Security-Policy header is present"],
        "total_models": total,
        "successful_models": successful,
        "failed_models": total - successful,
        "severity_distribution": {severity: successful},
        "weighted_scores": {severity: 70.0},
        "model_responses": [
            {"model_name": "claude-3-haiku", "provider": "OpenRouter", "success": False},
            {"model_name": "gemini-flash", "provider": "Google", "success": False},
            {"model_name": "gpt-oss-120b", "provider": "Groq", "success": True},
        ],
    }


@pytest.fixture
def bundle() -> dict:
    findings = ac.normalize_web(WEB_REPORT, "https://www.example.test")
    return {"findings": findings, "engine_ids": [f["id"] for f in ac.for_engine(findings)]}


def _csp(findings: list[dict]) -> dict:
    return next(f for f in findings if "Content Security Policy" in f["name"])


# --- normalization ----------------------------------------------------------


def test_web_report_normalizes_to_plain_whitelabelled_findings():
    findings = ac.normalize_web(WEB_REPORT, "https://www.example.test")
    assert len(findings) == 3
    csp = _csp(findings)
    assert csp["severity"] == "medium"
    assert csp["cwe"] == "CWE-693"
    assert csp["instances"] == 4
    assert "<p>" not in csp["description"] and "<p>" not in csp["solution"]
    assert "Content-Security-Policy header" in csp["solution"]
    blob = json.dumps(findings).lower()
    assert not any(w in blob for w in TOOL_WORDS)


def test_informational_findings_are_not_sent_to_the_engine(bundle):
    names = {f["id"]: f["name"] for f in bundle["findings"]}
    sent = [names[i] for i in bundle["engine_ids"]]
    assert "Modern Web Application" not in sent
    assert len(sent) == 2


def test_engine_selection_is_worst_first_and_capped():
    many = [{"id": str(i), "severity": "low"} for i in range(30)] + [{"id": "x", "severity": "critical"}]
    selected = ac.for_engine(many)
    assert selected[0]["id"] == "x"
    assert len(selected) == ac.ENGINE_MAX_FINDINGS


def test_engine_payload_carries_no_scanner_identity(bundle):
    findings = {f["id"]: f for f in bundle["findings"]}
    payload = ac.engine_payload([findings[i] for i in bundle["engine_ids"]])
    assert set(payload[0]) == {"title", "severity", "description", "solution", "url", "evidence", "cwe", "category"}
    assert not any(w in json.dumps(payload).lower() for w in TOOL_WORDS)


def test_tls_report_findings():
    report = {
        "headers": {"missing_headers": "Content-Security-Policy,X-XSS-Protection,"},
        "tls": {"tls_versions": " tls1_1 tls1_2 tls1_3", "days_until_expiry": "12", "certificate_expiry": "Nov 14"},
    }
    findings = {f["id"]: f for f in ac.normalize_tls(report, "https://www.example.test")}
    assert findings["hdr-content-security-policy"]["severity"] == "medium"
    assert findings["hdr-x-xss-protection"]["severity"] == "info"
    assert findings["tls-legacy-protocols"]["severity"] == "medium"
    assert findings["tls-certificate-expiry"]["severity"] == "high"
    sent = {f["id"] for f in ac.for_engine(list(findings.values()))}
    assert "hdr-x-xss-protection" not in sent


def test_template_findings_dedupe_and_strip_tool_metadata():
    row = {
        "template-id": "exposed-panel",
        "info": {
            "name": "Exposed panel",
            "severity": "high",
            "author": ["someone"],
            "description": "Nuclei found it",
            "remediation": "Restrict access",
            "classification": {"cwe-id": ["cwe-200"]},
        },
        "matched-at": "https://www.example.test/admin",
        "curl-command": "curl -X GET https://www.example.test/admin",
    }
    findings = ac.normalize_template([row, row], "https://www.example.test")
    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-200"
    blob = json.dumps(findings).lower()
    assert "curl-command" not in blob and "nuclei" not in blob and "author" not in blob


# --- enrichment -------------------------------------------------------------


def test_success_attaches_real_remediation_per_finding(bundle):
    entries = [engine_entry(tag="first"), engine_entry(successful=9, tag="second")]
    findings, consensus = ac.enrich(bundle, entries, "success")
    assert consensus["status"] == "success"
    assert consensus["findings_analysed"] == 2
    assert consensus["models_succeeded"] == 22 and consensus["models_total"] == 30
    first = next(f for f in findings if f["id"] == bundle["engine_ids"][0])
    analysis = first["ai_analysis"]
    assert first["ai_status"] == "analysed"
    assert analysis["remediation_steps"][0].startswith("Deploy a first Content-Security-Policy")
    assert len(analysis["remediation_steps"]) == 2, "near-duplicate steps are collapsed"
    assert analysis["impact"] == "high" and analysis["frameworks"] == ["SOC2", "PCI-DSS", "NIST"]
    assert analysis["models_succeeded"] == 13 and analysis["models_total"] == 15
    info = next(f for f in findings if f["name"] == "Modern Web Application")
    assert info["ai_status"] == "unavailable" and "ai_analysis" not in info


def test_no_provider_model_or_tool_name_survives(bundle):
    findings, consensus = ac.enrich(bundle, [engine_entry(), engine_entry()], "success")
    blob = json.dumps({"findings": findings, "consensus": consensus}).lower()
    assert "model_responses" not in blob and "provider" not in blob
    assert not any(w in blob for w in VENDOR_WORDS)
    assert not any(w in blob for w in TOOL_WORDS)


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", ""])
def test_failed_analysis_is_unavailable_never_a_verdict(bundle, result):
    findings, consensus = ac.enrich(bundle, [engine_entry(), engine_entry()], result)
    assert consensus["status"] == "unavailable"
    assert consensus["findings_analysed"] == 0
    assert all("ai_analysis" not in f and f["ai_status"] == "unavailable" for f in findings)


def test_count_mismatch_attaches_nothing(bundle):
    findings, consensus = ac.enrich(bundle, [engine_entry()], "success")
    assert consensus["status"] == "unavailable"
    assert "not attached" in consensus["reason"]
    assert all("ai_analysis" not in f for f in findings)


def test_zero_successful_models_is_not_an_analysis(bundle):
    findings, consensus = ac.enrich(bundle, [engine_entry(successful=0), engine_entry(successful=0)], "success")
    assert consensus["status"] == "unavailable"
    assert all("ai_analysis" not in f for f in findings)


def test_nothing_actionable_is_not_required():
    findings, consensus = ac.enrich({"findings": [], "engine_ids": []}, [], "skipped")
    assert consensus["status"] == "not_required"


def test_single_object_engine_output_is_read(tmp_path):
    (tmp_path / "result.json").write_text(json.dumps(engine_entry()))
    assert len(ac.read_consensus(tmp_path)) == 1
    (tmp_path / "result.json").write_text("not json")
    assert ac.read_consensus(tmp_path) == []
    assert ac.read_consensus(tmp_path / "missing") == []


# --- CLI end to end ---------------------------------------------------------


def test_cli_normalize_then_enrich_produces_a_valid_payload(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps(WEB_REPORT))
    tool = str(ROOT / "tools" / "asp_consensus.py")
    subprocess.run(
        [
            sys.executable,
            tool,
            "normalize",
            "--kind",
            "web",
            "--input",
            str(report),
            "--target",
            "https://www.example.test",
            "-o",
            str(tmp_path / "bundle.json"),
            "--engine-out",
            str(tmp_path / "engine.json"),
        ],
        check=True,
    )
    engine_in = json.loads((tmp_path / "engine.json").read_text())
    consensus_dir = tmp_path / "consensus"
    consensus_dir.mkdir()
    (consensus_dir / "result.json").write_text(json.dumps([engine_entry() for _ in engine_in]))
    subprocess.run(
        [
            sys.executable,
            tool,
            "enrich",
            "--bundle",
            str(tmp_path / "bundle.json"),
            "--consensus-dir",
            str(consensus_dir),
            "--job-result",
            "success",
            "--scan-id",
            "s1",
            "--client-id",
            "ironcity",
            "--scan-type",
            "web-exposure-passive",
            "--target",
            "https://www.example.test",
            "--timestamp",
            "2026-11-02T00:00:00Z",
            "-o",
            str(tmp_path / "payload.json"),
        ],
        check=True,
    )
    raw = (tmp_path / "payload.json").read_bytes()
    assert raw[:1] == b"{" and raw[-2:] == b"}\n"
    payload = json.loads(raw)
    assert payload["consensus"]["status"] == "success"
    assert payload["summary"]["medium_count"] == 2 and payload["summary"]["info_count"] == 1
    assert _csp(payload["findings"])["ai_analysis"]["remediation_steps"]


def test_missing_report_is_zero_findings(tmp_path):
    assert ac.load_report("web", tmp_path / "absent.json", "https://x") == []
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert ac.load_report("template", empty, "https://x") == []
