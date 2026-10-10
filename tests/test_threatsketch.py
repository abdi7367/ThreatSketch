"""Tests for the deterministic parts: scanner, JSON extraction, grounding validator, pipeline."""
import json
import os
import sys
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import scanner  # noqa: E402
import threatmodel as tm  # noqa: E402

FLASK = os.path.join(ROOT, "examples", "sample_flask_app")
EXPRESS = os.path.join(ROOT, "examples", "sample_express_app")


class FakeClient:
    """Stands in for the OpenAI client and replays canned replies."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls += 1
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=reply))])


def threat(evidence="app.py", category="Spoofing", **extra):
    base = {"category": category, "component": "Login", "evidence": evidence,
            "description": "Weak login check.", "mitigation": "Add rate limiting.", "severity": "High"}
    base.update(extra)
    return base


def test_scan_flask_app():
    facts = scanner.scan_repo(FLASK)
    assert set(facts["files"]) == {"app.py", "auth.py", "requirements.txt"}
    assert facts["entry_points"] == ["app.py"]
    assert {r["path"] for r in facts["routes"]} == {"/login", "/notes", "/admin/export"}
    assert {e["name"] for e in facts["env_vars"]} == {"SECRET_KEY", "DATABASE_PATH", "ADMIN_PASSWORD_HASH"}
    assert {"file": "app.py", "line": 18, "method": "POST", "path": "/login"} in facts["routes"]
    assert "auth.py" in facts["auth_files"]
    assert facts["dependencies"]["requirements.txt"] == ["flask==3.0.3", "gunicorn==22.0.0"]
    assert {"file": "app.py", "pattern": "debug mode enabled"} in facts["patterns"]


def test_scan_express_app():
    facts = scanner.scan_repo(EXPRESS)
    assert "server.js" in facts["entry_points"]
    paths = {(r["file"], r["path"]) for r in facts["routes"]}
    assert ("server.js", "/api/login") in paths and ("routes/users.js", "/:id") in paths
    assert {e["name"] for e in facts["env_vars"]} == {"JWT_SECRET", "PORT"}
    assert "express@^4.19.2" in facts["dependencies"]["package.json"]


def test_scan_skips_vendored_dirs_and_never_reads_secrets(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "index.js").write_text("app.get('/hidden')")
    (tmp_path / ".env").write_text("API_KEY=supersecretvalue")
    (tmp_path / "main.py").write_text("print('hi')")
    facts = scanner.scan_repo(str(tmp_path))
    assert facts["files"] == [".env", "main.py"]
    assert facts["sensitive_files"] == [".env"]
    assert "supersecretvalue" not in scanner.build_prompt_facts(facts)


def test_scan_truncates_at_limit_and_prompt_stays_small(tmp_path):
    for i in range(scanner.MAX_FILES + 50):
        (tmp_path / f"module_with_a_long_name_{i:04d}.py").write_text("x = 1")
    facts = scanner.scan_repo(str(tmp_path))
    assert facts["file_count"] == scanner.MAX_FILES and facts["truncated"]
    assert len(scanner.build_prompt_facts(facts)) <= scanner.MAX_PROMPT_CHARS


def test_extract_json_handles_think_tags_and_fences():
    raw = '<think>maybe {"a": broken</think>\n```json\n{"threats": [], "summary": "a } brace"}\n```'
    assert tm.extract_json(raw) == {"threats": [], "summary": "a } brace"}
    assert tm.extract_json('reasoning {oops</think>{"threats": []}') == {"threats": []}
    with pytest.raises(ValueError):
        tm.extract_json("Sorry, I cannot help.")
    with pytest.raises(ValueError):
        tm.extract_json('{"threats": [')


def test_validate_drops_ungrounded_threats():
    files = ["app.py", "auth.py"]
    data = {"threats": [
        threat("app.py"),
        threat("./auth.py:12", category="information disclosure", description="Hash leak."),
        threat("config/secrets.py", description="Invented file."),
        threat("app.py", category="Hacking", description="Bad category."),
        threat("", description="No evidence."),
        threat("app.py"),  # duplicate
        "not a dict",
        threat("app.py", description="No fix.", mitigation=""),
    ]}
    kept, dropped = tm.validate(data, files)
    assert [(t["category"], t["evidence"]) for t in kept] == [
        ("Spoofing", "app.py"), ("Information Disclosure", "auth.py")]
    assert len(dropped) == 6
    reasons = " | ".join(d["reason"] for d in dropped)
    assert "does not exist in the repo: config/secrets.py" in reasons
    assert "not a STRIDE name" in reasons and "duplicate" in reasons


def test_validate_rejects_path_tricks():
    kept, dropped = tm.validate({"threats": [threat("../app.py"), threat("APP.PY"), threat("/etc/passwd")]}, ["app.py"])
    assert kept == [] and len(dropped) == 3


def test_generate_end_to_end_with_retry():
    good = json.dumps({
        "summary": "A small Flask notes app.", "components": ["Login", "Notes API"],
        "threats": [threat("app.py"), threat("auth.py", "Tampering", severity="medium"),
                    threat("ghost.py", "Repudiation"), threat("requirements.txt", "Denial of Service", severity="???")],
    })
    client = FakeClient(["I think the answer is...", "<think>hmm</think>" + good])
    result = tm.generate(FLASK, client=client, model="fake-model")
    assert (result.raw_count, len(result.kept), len(result.dropped), result.attempts) == (4, 3, 1, 2)
    assert [t["severity"] for t in result.kept] == ["High", "Medium", "Unrated"]
    assert "| 1 | Spoofing | Login | `app.py` |" in result.threat_model_md
    assert "ghost.py" in result.threat_model_md  # listed under dropped, with the reason
    assert tm.CONTACT_PLACEHOLDER in result.security_md
    assert "**Login** (`app.py`): Spoofing" in result.security_md


def test_generate_clear_errors(tmp_path):
    with pytest.raises(tm.EmptyRepoError):
        tm.generate(str(tmp_path), client=FakeClient([]), model="fake-model")
    client = FakeClient(["nope", "still nope", '{"threats": "wrong type"}'])
    with pytest.raises(tm.ModelOutputError, match="after 3 attempts"):
        tm.generate(FLASK, client=client, model="fake-model")
    assert client.calls == 3
    with pytest.raises(tm.ModelOutputError, match="Could not reach"):
        tm.generate(FLASK, client=FakeClient([ConnectionError("refused")]), model="fake-model")


def test_markdown_escapes_model_text():
    data = {"summary": "ok", "threats": [threat("app.py", description="a | b <script>x</script>")]}
    result = tm.generate(FLASK, client=FakeClient([json.dumps(data)]), model="fake-model")
    assert "a \\| b &lt;script&gt;" in result.threat_model_md
