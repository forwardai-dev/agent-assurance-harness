# Publishing checklist — private first, then public

The repo lives at `deliverables/agent-assurance-harness/` inside the smarts workspace.
To publish it as a standalone project, extract it to its own git repo and push.

## 0. Pre-flight quality gate (all currently PASS — real numbers)
```bash
ruff check src tests               # style/lint            -> clean
ruff format --check src tests      # formatting            -> clean
mypy src                           # types (41 files)      -> Success: no issues
PYTHONPATH=src pytest tests/ -q    # tests                 -> 30 passed
coverage run -m pytest tests/ && coverage report   # coverage -> 85%
interrogate -c pyproject.toml src  # docstring coverage    -> 98.8% (min 80%)
bandit -r src -c pyproject.toml    # security              -> 0 issues (LOW/MED/HIGH)
python -m build && twine check dist/*   # packaging        -> PASSED
pyroma .                           # packaging metadata    -> 8/10
./demo.sh                          # end-to-end story, offline
```
Local dev convenience: `pre-commit install` wires the same battery to every commit;
CI (`.github/workflows/ci.yml`) runs tests on 3.11/3.12/3.13 + the full quality job.

**One optional polish left (your call, one line):** pyroma's only remaining ding is a
missing `author-email`. Add your preferred contact to `pyproject.toml`
(`authors = [{ name = "Sanju Goswami", email = "you@example.com" }]`) to take it to 9/10.

## 1. IP self-check (do once, before anything goes public)
- The harness is original work. Confirm it contains **no client code or data** (it does not:
  the Arbiter target is a synthetic stand-in, all fixtures are native/invented).
- Confirm nothing names or reveals a live client (e.g. Arbitration Forums) — it does not.
- Keep it that way in every future commit.

## 2. Create a standalone repo (local, no network)
```bash
# from a clean copy OUTSIDE the smarts workspace
cp -r deliverables/agent-assurance-harness ~/agent-assurance-harness
cd ~/agent-assurance-harness
rm -rf .pytest_cache .mypy_cache .ruff_cache out out-* **/__pycache__
git init -b main && git add . && git commit -m "Agent Assurance Harness v0.1.0"
```

## 3. Publish PRIVATE (needs your GitHub login)
```bash
gh auth login                       # authenticate as yourself (interactive)
gh repo create agent-assurance-harness --private --source=. --push
```
Now review it on GitHub as a real repo: README renders, CI runs green, demo works.

## 4. Flip PUBLIC only when you're satisfied
```bash
gh repo edit --visibility public --accept-visibility-change-consequences
```

## Recommended polish before public (optional, high-signal)
- A short GIF/asciinema of `./demo.sh` embedded at the top of the README.
- A one-paragraph "why this exists" and the honest-scope section kept prominent.
- Topics/tags on GitHub: `agentic-ai`, `llm-evaluation`, `ai-red-team`, `ai-governance`,
  `owasp-agentic`, `attestation`.
- A CITATION.cff or a short blog post link.

## What NOT to do
- Do not push while the pre-flight gate is red.
- Do not name a live client, or include any non-synthetic data, ever.
- Do not overclaim: it is a reference implementation + evidence standard, not a production
  compliance product. The README already states this.
