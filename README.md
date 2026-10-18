# ScamShield India

Architecture: FastAPI backend (`app.py`) + one static HTML page + `scamshield/` (rules, URL checks, Ollama client, pipeline).
Kept deliberately small: no database, no accounts, no external requests.

## Windows setup (PowerShell, inside this folder)
1. Install Ollama from https://ollama.com/download, then: `ollama pull gemma3:4b` (about 3.3 GB; runs on 16 GB RAM).
2. `python -m venv .venv` then `.venv\Scripts\Activate.ps1`
   (if blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`)
3. `pip install -r requirements.txt`
4. `python -m unittest discover -s tests -v`   (or `pytest`)
5. `uvicorn app:app --host 127.0.0.1 --port 8000` and open http://127.0.0.1:8000

Change model: `$env:SCAMSHIELD_MODEL="gemma3:1b"` (faster, weaker) before step 5.

## Troubleshooting
- "AI model was not available": Ollama is not running (open the Ollama app) or the model is not pulled (`ollama list`).
- First request is slow while the model loads; the timeout is 90 s (`SCAMSHIELD_TIMEOUT`).
- Port busy: use `--port 8001`.

## Model and license
Gemma 3 4B via Ollama. Gemma is released under Google's Gemma Terms of Use, not MIT/Apache: read it before redistributing the model.

## Privacy / deployment
Locally, everything stays on your machine. Do not expose Ollama (port 11434) publicly. On a remote server, messages travel to that
server, and typical free hosts cannot run Ollama; demo locally (e.g. screen recording) or use a host that supports it.

## Limits
Rule patterns are hand-written and will miss novel scams and flag some legitimate messages. URL checks are structural only.
Risk levels follow the documented heuristic in `scamshield/rules.py::rule_risk`, not a validated probability.
No accuracy benchmark exists yet, so none is claimed.
