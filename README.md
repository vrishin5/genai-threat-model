# GenAI Red-Team Harness

An automated red-teaming harness for GenAI applications. It attacks a
running (black-box) LLM app with adversarial prompts and scores its
behavior against the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

## Status

Phased build — see below for what's done vs. planned.

- [x] **Phase 0** — repo scaffolding, attack schema (`redteam/schema.py`), CLI skeleton (`redteam/cli.py`).
- [x] **Phase 1** — demo vulnerable target app (`vulnapp/`): a RAG + tool-calling
      support bot with four intentional vulnerabilities to attack.
- [x] **Phase 2** — attack corpus (`data/attacks/*.yaml`): 32 attacks across
      LLM01, LLM02, LLM05, LLM06, LLM07, LLM10.
- [x] **Phase 3** — execution engine (`redteam/engine.py`) + rule-based judges
      (`redteam/judges.py`): canary-leak, text-match, unescaped-HTML, and
      tool-call/ledger checks. `redteam run` is fully wired up.
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
redteam list-attacks                                   # prints the 32-attack corpus
redteam run --target-url http://127.0.0.1:8000         # run everything against a live target
redteam run --category LLM06                           # scope to one OWASP category
redteam run --no-save                                  # skip writing data/runs/<timestamp>.json
```

`run` requires the target app to be up (`uvicorn vulnapp.app:app`) and a real
`ANTHROPIC_API_KEY` in `.env`, since the demo app calls Claude. It resets the
target's `/debug/state` before each attack, drives the full payload (multi-turn
attacks replay every turn in one session), and scores the result with a
rule-based judge — see `redteam/judges.py` for how each `judge.type` in the
attack YAML is interpreted. Attacks with no `judge` block (e.g. `spl-002`,
`uc-003`) are inherently fuzzy to score with a substring/threshold check and
are left for manual review / a future LLM-as-judge (Phase 5).

The `/debug/state` and `/debug/reset` endpoints on `vulnapp` are test
instrumentation, not something a real black-box target would expose — they
give the judges ground truth on what tools actually ran (refund ledger, sent
emails, tool-call counts) instead of trusting the model's own summary of its
actions.
