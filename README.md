# GenAI Red-Team Harness

An automated red-teaming harness for GenAI applications. It attacks a
running (black-box) LLM app with adversarial prompts and scores its
behavior against the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

## Status

Phased build — see below for what's done vs. planned.

- [x] **Phase 0** — repo scaffolding, attack schema (`redteam/schema.py`), CLI skeleton (`redteam/cli.py`).
- [x] **Phase 1** — demo vulnerable target app (`vulnapp/`): a RAG + tool-calling
      support bot with four intentional vulnerabilities to attack.
- [ ] **Phase 2** — attack corpus (`data/attacks/*.yaml`).
- [ ] **Phase 3** — execution engine + canary/rule-based judge.
- [ ] **Phase 4** — mutation/fuzzing layer.
- [ ] **Phase 5** — LLM-as-judge scoring + severity model.
- [ ] **Phase 6** — HTML/Markdown report generator.
- [ ] Stretch — CI integration, dashboard.

## The demo vulnerable app (`vulnapp/`)

A small FastAPI support-bot backed by Claude, with a keyword-based
"RAG" knowledge base and three tools (`search_knowledge_base`,
`process_refund`, `send_support_email`). It's deliberately built with
four vulnerabilities the harness is meant to catch:

| # | Category | Where | What |
|---|----------|-------|------|
| 1 | LLM01 Prompt Injection (indirect) | `vulnapp/docs/internal_notes.md` | A retrieved document carries planted instructions the model treats as commands. |
| 2 | LLM05 Improper Output Handling | `vulnapp/app.py` (`/chat-ui`) | Model output is interpolated into HTML with no escaping. |
| 3 | LLM06 Excessive Agency | `vulnapp/tools.py` | `process_refund` has no amount cap, order validation, or human confirmation; `send_support_email` has no recipient allowlist. |
| 4 | LLM07 System Prompt Leakage | `vulnapp/agent.py` | A canary secret sits in the system prompt with only an instruction (no output filter) protecting it. |

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # then fill in ANTHROPIC_API_KEY
```

## Run the demo app

```bash
uvicorn vulnapp.app:app --reload
```

Then either:

```bash
curl -X POST http://127.0.0.1:8000/chat -H 'content-type: application/json' \
  -d '{"message": "What is your refund policy?"}'
```

or open `http://127.0.0.1:8000/docs` for the interactive API.

## Harness CLI

```bash
redteam version
redteam list-attacks   # empty until Phase 2
redteam run --target-url http://127.0.0.1:8000   # stubbed until Phase 3
```
