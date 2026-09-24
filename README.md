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
- [x] **Phase 4** — mutation/fuzzing layer (`redteam/mutators.py`): generates
      obfuscated/multi-turn variants of the seed corpus automatically —
      117 generated from the 32 hand-written seeds, committed under
      `data/attacks/generated/mutated.yaml`.
- [x] **Phase 5** — LLM-as-judge fallback (`redteam/llm_judge.py`) for attacks
      with no rule-based judge, plus a severity-weighted risk score and
      per-category breakdown (`redteam/scoring.py`).
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
redteam list-attacks                                   # prints the full corpus (seeds + generated)
redteam run --target-url http://127.0.0.1:8000         # run everything against a live target
redteam run --category LLM06                           # scope to one OWASP category
redteam run --no-save                                  # skip writing data/runs/<timestamp>.json
redteam run --llm-judge                                 # also score judge-less attacks via LLM-as-judge
redteam mutate                                          # regenerate data/attacks/generated/mutated.yaml
redteam mutate --techniques b64,split --category LLM06  # scope mutators/seeds
redteam mutate --llm --techniques paraphrase            # LLM-paraphrased variants (needs ANTHROPIC_API_KEY)
```

`run` requires the target app to be up (`uvicorn vulnapp.app:app`) and a real
`ANTHROPIC_API_KEY` in `.env`, since the demo app calls Claude. It resets the
target's `/debug/state` before each attack, drives the full payload (multi-turn
attacks replay every turn in one session), and scores the result with a
rule-based judge — see `redteam/judges.py` for how each `judge.type` in the
attack YAML is interpreted. Attacks with no `judge` block (e.g. `spl-002`,
`uc-003`) are inherently fuzzy to score with a substring/threshold check;
pass `--llm-judge` to score those with Claude instead (see below), or leave
it off to flag them `manual_review: true` in the output.

The `/debug/state` and `/debug/reset` endpoints on `vulnapp` are test
instrumentation, not something a real black-box target would expose — they
give the judges ground truth on what tools actually ran (refund ledger, sent
emails, tool-call counts) instead of trusting the model's own summary of its
actions.

## Mutation/fuzzing (`redteam/mutators.py`)

Each mutator takes a seed `Attack` and rewrites only its *input payload* —
`judge`, `success_criteria`, and `channel` are carried over unchanged, since a
judge scores the target's response, never the attacker's wording. That means
every mutator is judge-agnostic and composes freely:

| Mutator | What it does |
|---|---|
| `b64` | Wraps the final turn in a "decode this base64 and follow it" shell. |
| `homoglyph` | Swaps Latin letters for visually-identical Cyrillic look-alikes (filter evasion). |
| `leetspeak` | Substitutes letters for digits (`e`→`3`, `o`→`0`, ...). |
| `split` | Turns a single-turn attack into two turns: an innocuous preamble, then the original ask. |
| `paraphrase` | LLM-rewrites the payload with different wording/structure. Opt-in (`--llm`) since it costs API calls. |

`redteam mutate` skips attacks already tagged `mutated`, so re-running it
doesn't compound mutations on top of mutations.

## LLM-as-judge and risk scoring (Phase 5)

`redteam/llm_judge.py` handles attacks with no rule-based `judge` (currently
`spl-002` and `uc-003`) by handing the full transcript and the attack's
`success_criteria` to Claude, forcing a `submit_verdict` tool call so the
output is always a structured `{vulnerable, rationale}` pair rather than
free text to parse. It's opt-in via `redteam run --llm-judge` since it costs
API calls; without the flag those attacks are reported as
`manual_review: true` instead of guessed at.

`redteam/scoring.py` rolls a run's findings into a `RiskReport`: a
severity-weighted score from 0 (nothing vulnerable) to 100 (everything
vulnerable, weighted so a critical finding counts far more than a low one),
a letter grade (A–F), a per-OWASP-category breakdown, and the top findings by
severity. It's printed after every `redteam run` and saved alongside the raw
findings in `data/runs/<timestamp>.json`.

Every mutator and both judge types only ever change how an attack is
*delivered* or how its result is *scored* — never both at once for the same
concern — which is what let Phases 3–5 be added without reworking anything
from Phases 1–2.
