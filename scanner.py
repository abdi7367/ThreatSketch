"""Repo scanner: collects hard facts about a repository. No AI here.

Everything in this file is deterministic. The model never sees the code itself,
only the facts bundle this module produces, and the validator in threatmodel.py
uses the file list from here to check every citation the model makes.
"""
from __future__ import annotations

import json
import os
import re

MAX_FILES = 300
MAX_READ_BYTES = 200_000
MAX_PROMPT_CHARS = 12_000

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".next", ".nuxt", "target", "coverage", "site-packages",
    ".idea", ".vscode", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".cache",
}

CODE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

ENTRY_NAMES = {
    "main.py", "app.py", "manage.py", "wsgi.py", "asgi.py", "server.py", "run.py",
    "server.js", "index.js", "app.js", "main.js",
    "server.ts", "index.ts", "app.ts", "main.ts",
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", "procfile",
}

AUTH_PATH_WORDS = (
    "auth", "login", "logout", "signup", "register", "session", "jwt", "oauth",
    "password", "passwd", "token", "permission", "acl", "rbac", "middleware", "crypto",
)

# Files that often hold secrets. We record that they exist, never their contents.
SENSITIVE_NAME = re.compile(
    r"(^\.env($|\.)|\.pem$|\.key$|\.p12$|\.pfx$|^id_rsa$|^id_ed25519$|credentials|secrets?\.(json|ya?ml|toml)$)",
    re.I,
)

PY_ROUTE = re.compile(
    r"@\s*[\w.]+\.(route|get|post|put|delete|patch|websocket)\(\s*[\"']([^\"']*)[\"']"
)
DJANGO_ROUTE = re.compile(r"\b(?:re_)?path\(\s*r?[\"']([^\"']*)[\"']")
JS_ROUTE = re.compile(
    r"\b(?:app|router|server|api)\.(get|post|put|delete|patch|all|use)\(\s*[\"'`]([^\"'`]+)[\"'`]"
)

ENV_PATTERNS = [
    re.compile(r"os\.environ(?:\.get)?\s*[\[(]\s*[\"'](\w+)[\"']"),
    re.compile(r"os\.getenv\(\s*[\"'](\w+)[\"']"),
    re.compile(r"process\.env\.([A-Za-z_]\w*)"),
    re.compile(r"process\.env\[\s*[\"'](\w+)[\"']"),
    re.compile(r"import\.meta\.env\.([A-Za-z_]\w*)"),
]

# Keyword hints only. A match means "this API appears in this file",
# not "this file is vulnerable".
PATTERNS = [
    ("runs shell commands or subprocesses", re.compile(r"\bsubprocess\.|\bos\.system\(|child_process|\bexecSync\(")),
    ("uses eval or exec on dynamic code", re.compile(r"(?<![\w.])(eval|exec)\(")),
    ("deserializes with pickle or unsafe YAML", re.compile(r"\bpickle\.loads?\(|yaml\.load\(")),
    ("runs SQL queries", re.compile(r"\.execute\(|\.query\(|\braw\(|SELECT\s.+\sFROM\s", re.I)),
    ("uses a database library", re.compile(r"\b(sqlite3|sqlalchemy|psycopg2|pymongo|mongoose|sequelize|prisma|redis)\b")),
    ("handles file uploads", re.compile(r"request\.files|\bmulter\b|UploadFile|\.save\(\s*os\.path")),
    ("reads or writes files from request-influenced paths", re.compile(r"send_file\(|sendFile\(|send_from_directory\(|fs\.(read|write)File")),
    ("debug mode enabled", re.compile(r"debug\s*=\s*True|DEBUG\s*=\s*True")),
    ("configures CORS", re.compile(r"\bCORS\(|\bcors\(|Access-Control-Allow-Origin")),
    ("hashes or verifies passwords", re.compile(r"\b(bcrypt|argon2|scrypt|pbkdf2|hashlib\.(md5|sha1|sha256)|werkzeug\.security)\b")),
    ("issues or verifies JWTs", re.compile(r"\bjwt\.(encode|decode|sign|verify)\(|jsonwebtoken")),
    ("uses cookies or server sessions", re.compile(r"\bsession\[|set_cookie\(|res\.cookie\(|express-session|flask_login")),
    ("makes outbound HTTP requests", re.compile(r"\brequests\.(get|post|put|delete)\(|\bfetch\(|\baxios\b|urllib\.request|httpx\.")),
    ("renders HTML templates", re.compile(r"render_template(_string)?\(|res\.render\(|dangerouslySetInnerHTML|innerHTML")),
]


def _read(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(MAX_READ_BYTES).decode("utf-8", errors="ignore")
    except OSError:
        return ""


def _parse_requirements(text: str) -> list[str]:
    deps = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        deps.append(line)
    return deps[:60]


def _parse_package_json(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    deps = []
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps += [f"{name}@{ver}" for name, ver in section.items()]
    return deps[:60]


def _parse_pyproject(text: str) -> list[str]:
    try:
        import tomllib  # Python 3.11+
        data = tomllib.loads(text)
    except Exception:
        return []
    deps = list(data.get("project", {}).get("dependencies", []) or [])
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry, dict):
        deps += [f"{k} {v}" if isinstance(v, str) else k for k, v in poetry.items() if k != "python"]
    return [str(d) for d in deps][:60]


def scan_repo(root: str) -> dict:
    """Walk a repository and return a facts dict. Never raises on unreadable files."""
    root = os.path.abspath(os.path.expanduser(root))
    if not os.path.isdir(root):
        raise NotADirectoryError(f"Not a folder: {root}")

    facts = {
        "repo_name": os.path.basename(root.rstrip(os.sep)) or "repo",
        "files": [],
        "file_count": 0,
        "truncated": False,
        "languages": {},
        "entry_points": [],
        "dependencies": {},
        "routes": [],
        "env_vars": [],
        "auth_files": [],
        "sensitive_files": [],
        "patterns": [],
    }
    seen_env = set()

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            if len(facts["files"]) >= MAX_FILES:
                facts["truncated"] = True
                break
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            facts["files"].append(rel)
            lower = name.lower()
            ext = os.path.splitext(lower)[1]
            if ext:
                facts["languages"][ext] = facts["languages"].get(ext, 0) + 1

            if lower in ENTRY_NAMES:
                facts["entry_points"].append(rel)
            if SENSITIVE_NAME.search(name) and lower != ".env.example":
                facts["sensitive_files"].append(rel)  # name only, contents never read
                continue
            if any(word in rel.lower() for word in AUTH_PATH_WORDS):
                facts["auth_files"].append(rel)

            if lower.startswith("requirements") and lower.endswith(".txt"):
                facts["dependencies"][rel] = _parse_requirements(_read(full))
            elif lower == "package.json":
                facts["dependencies"][rel] = _parse_package_json(_read(full))
            elif lower == "pyproject.toml":
                facts["dependencies"][rel] = _parse_pyproject(_read(full))

            if ext not in CODE_EXTS:
                continue
            text = _read(full)
            if not text:
                continue

            for lineno, line in enumerate(text.splitlines(), 1):
                if len(line) > 400:
                    continue
                if ext == ".py":
                    m = PY_ROUTE.search(line)
                    if m:
                        method = m.group(1).upper()
                        if method == "ROUTE":  # Flask: methods live in a keyword argument
                            found = re.findall(r"[\"'](GET|POST|PUT|DELETE|PATCH)[\"']", line.split("methods", 1)[-1]) if "methods" in line else []
                            method = "/".join(found) or "GET"
                        facts["routes"].append({"file": rel, "line": lineno, "method": method, "path": m.group(2)})
                    elif lower == "urls.py":
                        m = DJANGO_ROUTE.search(line)
                        if m:
                            facts["routes"].append({"file": rel, "line": lineno, "method": "ANY", "path": "/" + m.group(1)})
                else:
                    m = JS_ROUTE.search(line)
                    if m and m.group(2).startswith(("/", "*")):
                        facts["routes"].append({"file": rel, "line": lineno, "method": m.group(1).upper(), "path": m.group(2)})
                for pat in ENV_PATTERNS:
                    for var in pat.findall(line):
                        if (rel, var) not in seen_env:
                            seen_env.add((rel, var))
                            facts["env_vars"].append({"file": rel, "name": var})

            for label, pat in PATTERNS:
                if pat.search(text):
                    facts["patterns"].append({"file": rel, "pattern": label})
        if facts["truncated"]:
            break

    facts["file_count"] = len(facts["files"])
    facts["auth_files"] = sorted(set(facts["auth_files"]))
    return facts


def _priority_files(facts: dict) -> list[str]:
    """Order files so the ones the scanner has facts about survive truncation."""
    first = list(facts["entry_points"]) + list(facts["dependencies"]) + list(facts["auth_files"])
    first += [r["file"] for r in facts["routes"]]
    first += [e["file"] for e in facts["env_vars"]]
    first += [p["file"] for p in facts["patterns"]]
    first += facts["sensitive_files"]
    ordered, seen = [], set()
    for f in first + facts["files"]:
        if f not in seen:
            seen.add(f)
            ordered.append(f)
    return ordered


def build_prompt_facts(facts: dict, max_chars: int = MAX_PROMPT_CHARS) -> str:
    """Serialize facts for the model, trimmed to max_chars so small models keep the instructions."""
    bundle = {
        "repo_name": facts["repo_name"],
        "file_count": facts["file_count"],
        "file_list_truncated": facts["truncated"],
        "languages": facts["languages"],
        "entry_points": facts["entry_points"][:20],
        "dependencies": {k: v[:40] for k, v in list(facts["dependencies"].items())[:6]},
        "routes": facts["routes"][:60],
        "env_vars": facts["env_vars"][:40],
        "auth_files": facts["auth_files"][:25],
        "sensitive_files_present": facts["sensitive_files"][:15],
        "patterns": facts["patterns"][:60],
        "files": _priority_files(facts),
    }
    # Trim the least important things first until the bundle fits.
    for key, floor in (("files", 40), ("patterns", 20), ("routes", 20), ("env_vars", 10), ("files", 15)):
        while len(json.dumps(bundle)) > max_chars and len(bundle[key]) > floor:
            bundle[key] = bundle[key][: max(floor, len(bundle[key]) - 10)]
            bundle["file_list_truncated"] = True
    while len(json.dumps(bundle)) > max_chars and bundle["dependencies"]:
        longest = max(bundle["dependencies"], key=lambda k: len(bundle["dependencies"][k]))
        if len(bundle["dependencies"][longest]) <= 5:
            break
        bundle["dependencies"][longest] = bundle["dependencies"][longest][:-5]
    return json.dumps(bundle)


if __name__ == "__main__":
    import sys

    print(build_prompt_facts(scan_repo(sys.argv[1] if len(sys.argv) > 1 else ".")))
