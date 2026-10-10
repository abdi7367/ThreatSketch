"""ThreatSketch Streamlit UI. Run with: streamlit run app.py"""
import html
import io
import json
import re
import subprocess
import tempfile
import time
import zipfile

import streamlit as st

from scanner import build_prompt_facts, scan_repo
from threatmodel import STRIDE, EmptyRepoError, ModelOutputError, generate, get_client, get_config, load_env

load_env()
config = get_config()

st.set_page_config(page_title="ThreatSketch", page_icon="🛡️", layout="wide")

# Colors use translucent fills and inherit text color, so the same CSS works in light and dark themes.
st.markdown("""
<style>
.block-container {padding-top: 2rem; max-width: 1200px;}
.hero {padding: 28px 32px; border-radius: 18px; margin-bottom: 20px;
  background: radial-gradient(circle at 0% 0%, rgba(124,92,255,.28), transparent 55%),
              radial-gradient(circle at 100% 100%, rgba(0,180,216,.18), transparent 50%),
              rgba(127,127,127,.06);
  border: 1px solid rgba(127,127,127,.22);}
.hero h1 {margin: 0; padding: 0; font-size: 2.5rem; font-weight: 800; letter-spacing: -.02em;
  background: linear-gradient(90deg, #6d4aff, #00a6c8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;}
.hero p {margin: 6px 0 0; opacity: .75; font-size: 1.05rem;}
.pill {display: inline-block; padding: 3px 11px; margin: 14px 6px 0 0; border-radius: 999px; font-size: .78rem;
  background: rgba(127,127,127,.10); border: 1px solid rgba(127,127,127,.25);}
.mvp {background: rgba(255,170,0,.15); border-color: rgba(255,170,0,.45); color: #d48a00; font-weight: 700;}
.stat {border: 1px solid rgba(127,127,127,.22); background: rgba(127,127,127,.06); border-radius: 14px; padding: 16px 18px;}
.stat .n {font-size: 2rem; font-weight: 800; line-height: 1.1;}
.stat .l {opacity: .65; font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; margin-top: 2px;}
.chips {margin: 4px 0 12px;}
.chip {display: inline-block; padding: 4px 11px; margin: 4px 6px 0 0; border-radius: 8px; font-size: .82rem; font-weight: 600;}
.chip.on {background: rgba(46,200,130,.16); color: #1fa36a;}
.chip.off {background: rgba(127,127,127,.10); opacity: .6; text-decoration: line-through;}
.threat {border: 1px solid rgba(127,127,127,.22); background: rgba(127,127,127,.05); border-left: 4px solid var(--c);
  border-radius: 12px; padding: 14px 18px; margin-bottom: 12px;}
.threat .top {display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px;}
.badge {padding: 2px 9px; border-radius: 6px; font-size: .74rem; font-weight: 700;}
.threat .comp {font-weight: 700; font-size: 1.02rem;}
.threat .mit {opacity: .78; margin-top: 8px; font-size: .93rem;}
.summary {border-radius: 12px; padding: 14px 18px; margin: 4px 0 16px;
  background: rgba(109,74,255,.08); border: 1px solid rgba(109,74,255,.25);}
.footer {opacity: .55; font-size: .8rem; text-align: center; margin-top: 40px;}
div.stButton > button, div.stDownloadButton > button {border-radius: 10px;}
</style>
""", unsafe_allow_html=True)

SEVERITY_COLORS = {"High": "#e5484d", "Medium": "#f5a524", "Low": "#2ec882", "Unrated": "#8d93ad"}
GITHUB_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?$")


@st.cache_data(ttl=30, show_spinner=False)
def model_status(base_url: str, api_key: str, model: str) -> tuple[bool, str]:
    """Check the endpoint answers and has the configured model. Cached for 30 seconds."""
    try:
        client = get_client({"base_url": base_url, "api_key": api_key, "model": model}).with_options(timeout=4)
        names = [m.id for m in client.models.list().data]
    except Exception:
        return False, "Endpoint not reachable"
    if model in names:
        return True, "Connected"
    return False, f"Model not found. Run: ollama pull {model}"


def clone(url: str) -> str:
    """Shallow-clone a public GitHub repo into a temp folder and return its path."""
    target = tempfile.mkdtemp(prefix="threatsketch_")
    subprocess.run(
        ["git", "clone", "--depth", "1", "--", url, target],
        check=True, capture_output=True, text=True, timeout=120,
    )
    return target


def zip_outputs(result) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("THREAT_MODEL.md", result.threat_model_md)
        zf.writestr("SECURITY.md", result.security_md)
        zf.writestr("threats.json", json.dumps({"model": result.model, "kept": result.kept, "dropped": result.dropped}, indent=2))
    return buf.getvalue()


# ---------- sidebar ----------

with st.sidebar:
    st.markdown("### ⚙️ Model")
    ok, status = model_status(config["base_url"], config["api_key"], config["model"])
    st.markdown(f"{'🟢' if ok else '🔴'} **{status}**")
    st.markdown(f"**Model:** `{config['model']}`  \n**Endpoint:** `{config['base_url']}`")
    st.caption("Set BASE_URL, API_KEY and MODEL in a .env file to switch between Ollama and Groq.")
    st.markdown("### 🌗 Appearance")
    st.caption("Light and dark mode follow your system. Switch any time from the ⋮ menu (top right) → Settings → Theme.")
    st.markdown("### 🧭 How it works")
    st.markdown(
        "1. **Scan** the repo for facts (no AI)\n"
        "2. **Ask** the model for STRIDE threats\n"
        "3. **Validate**: drop threats citing files that don't exist\n"
        "4. **Render** THREAT_MODEL.md and SECURITY.md"
    )
    st.markdown("### ⚠️ MVP")
    st.caption("This is a minimum viable product. Output is a starting point for human review, not a security audit.")

# ---------- header ----------

st.markdown(f"""
<div class="hero">
  <h1>🛡️ ThreatSketch</h1>
  <p>Point it at a repo. Get a grounded STRIDE threat model and a ready-to-edit SECURITY.md.</p>
  <span class="pill mvp">MVP</span>
  <span class="pill">🤖 {html.escape(config['model'])}</span>
  <span class="pill">🔍 Scanners collect facts</span>
  <span class="pill">✅ Every citation verified</span>
  <span class="pill">🔒 Source code never sent to the model</span>
</div>
""", unsafe_allow_html=True)

# ---------- input ----------

if "source" not in st.session_state:
    st.session_state["source"] = ""

st.markdown("**Quick start**")
ex1, ex2, _ = st.columns([1, 1, 3])
if ex1.button("🐍 Flask example", use_container_width=True):
    st.session_state["source"] = "examples/sample_flask_app"
if ex2.button("🟨 Express example", use_container_width=True):
    st.session_state["source"] = "examples/sample_express_app"

col_in, col_btn = st.columns([5, 1], vertical_alignment="bottom")
source = col_in.text_input(
    "Local folder path or public GitHub URL",
    key="source",
    placeholder="examples/sample_flask_app   or   https://github.com/owner/repo",
)
go = col_btn.button("Generate ⚡", type="primary", disabled=not source.strip(), use_container_width=True)

if go:
    st.session_state.pop("result", None)
    path = source.strip()
    started = time.time()
    try:
        with st.status("Working...", expanded=True) as status_box:
            if path.startswith(("http://", "https://")):
                if not GITHUB_URL.match(path):
                    status_box.update(label="Invalid URL", state="error")
                    st.error("That does not look like a public GitHub repository URL (https://github.com/owner/repo).")
                    st.stop()
                st.write("📥 Cloning repository...")
                path = clone(path)
            st.write("🔍 Scanning repository...")
            preview = scan_repo(path)
            st.write(
                f"Found {preview['file_count']} files, {len(preview['entry_points'])} entry points, "
                f"{len(preview['routes'])} routes, {len(preview['dependencies'])} dependency files."
            )
            st.write(f"🤖 Asking `{config['model']}` for threats. A local model on CPU can take several minutes...")
            result = generate(path)
            st.write("✅ Validated citations and rendered files.")
            st.session_state["result"] = result
            st.session_state["elapsed"] = time.time() - started
            status_box.update(label=f"Done in {st.session_state['elapsed']:.0f}s", state="complete", expanded=False)
    except EmptyRepoError as err:
        st.warning(str(err))
    except NotADirectoryError:
        st.error("That folder does not exist. Check the path and try again.")
    except ModelOutputError as err:
        st.error(str(err))
    except subprocess.CalledProcessError as err:
        st.error(f"Could not clone that repository: {err.stderr.strip()[:300]}")
    except subprocess.TimeoutExpired:
        st.error("Cloning took too long. Try a smaller repository or clone it yourself and give the folder path.")

# ---------- results ----------

result = st.session_state.get("result")
if result:
    facts = result.facts
    st.markdown(f"## Results for `{html.escape(facts['repo_name'])}`")

    stats = [
        ("Proposed by model", result.raw_count, "inherit"),
        ("Kept (grounded)", len(result.kept), "#2ec882"),
        ("Dropped", len(result.dropped), "#e5484d"),
        ("STRIDE coverage", f"{len(result.categories)}/6", "#6d4aff"),
    ]
    for col, (label, value, color) in zip(st.columns(4), stats):
        col.markdown(f'<div class="stat"><div class="n" style="color:{color}">{value}</div>'
                     f'<div class="l">{label}</div></div>', unsafe_allow_html=True)

    chips = "".join(
        f'<span class="chip {"on" if c in result.categories else "off"}">{c}</span>' for c in STRIDE
    )
    st.markdown(f'<div class="chips">{chips}</div>', unsafe_allow_html=True)
    st.caption(
        f"Every kept threat cites a file that exists among the {facts['file_count']} scanned files. "
        f"Model attempts: {result.attempts}. Took {st.session_state.get('elapsed', 0):.0f}s. "
        "This proves the file exists, not that the threat is real."
    )
    if result.summary:
        st.markdown(f'<div class="summary"><b>Summary.</b> {html.escape(result.summary)}</div>', unsafe_allow_html=True)
    if not facts["entry_points"]:
        st.info("No recognizable entry point was found, so the model had less to work with.")

    d1, d2, d3, _ = st.columns([1.2, 1.2, 1.2, 2])
    d1.download_button("⬇️ All files (.zip)", zip_outputs(result), "threatsketch.zip", "application/zip",
                       type="primary", use_container_width=True)
    d2.download_button("⬇️ THREAT_MODEL.md", result.threat_model_md, "THREAT_MODEL.md", "text/markdown",
                       use_container_width=True)
    d3.download_button("⬇️ SECURITY.md", result.security_md, "SECURITY.md", "text/markdown",
                       use_container_width=True)

    tab0, tab1, tab2, tab3, tab4 = st.tabs(
        ["🎯 Threats", "📄 THREAT_MODEL.md", "🔐 SECURITY.md", f"🗑️ Dropped ({len(result.dropped)})", "🔍 Facts sent to model"]
    )
    with tab0:
        if not result.kept:
            st.info("No grounded threats were kept. Try again or try a different model.")
        else:
            present = [s for s in SEVERITY_COLORS if any(t["severity"] == s for t in result.kept)]
            chosen = st.pills("Filter by severity", present, default=present, selection_mode="multi")
            shown = [t for t in result.kept if t["severity"] in (chosen or [])]
            for t in shown:
                c = SEVERITY_COLORS.get(t["severity"], "#8d93ad")
                st.markdown(f"""
<div class="threat" style="--c:{c}">
  <div class="top">
    <span class="badge" style="background:{c}26;color:{c}">{html.escape(t['severity'])}</span>
    <span class="badge" style="background:rgba(109,74,255,.14);color:#6d4aff">{html.escape(t['category'])}</span>
    <span class="comp">{html.escape(t['component'])}</span>
    <code>{html.escape(t['evidence'])}</code>
  </div>
  <div>{html.escape(t['description'])}</div>
  <div class="mit">🛠️ <b>Mitigation:</b> {html.escape(t['mitigation'])}</div>
</div>""", unsafe_allow_html=True)
            if not shown:
                st.caption("No threats match the selected severities.")
    with tab1:
        st.markdown(result.threat_model_md)
    with tab2:
        st.markdown(result.security_md)
    with tab3:
        if result.dropped:
            st.caption("The validator rejected these model proposals. This is the grounding check working.")
            for d in result.dropped:
                st.markdown(f"- {html.escape(d['threat'])} — *{html.escape(d['reason'])}*")
        else:
            st.success("Nothing was dropped. Every threat the model proposed cited a real file.")
    with tab4:
        st.caption("This JSON is everything the model sees. It never receives the source code.")
        st.json(json.loads(build_prompt_facts(facts)))

st.markdown('<div class="footer">ThreatSketch MVP · Hacktoberfest Islamabad 2026 · MIT License</div>',
            unsafe_allow_html=True)
