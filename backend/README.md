# SurakshaAI Shield — Backend

Phishing detection API for code-mixed Hindi-English (Hinglish) messages, combining rule-based pattern matching with Claude AI contextual analysis.

## Architecture

```
Request → Text Preprocessing → Stage 1: Pattern Matching → Decision Logic → Response
                                                              ↓ (if score 30-100)
                                                        Stage 2: GenAI Analysis
```

**Stage 1 — Pattern Matching (ML component)**
Fast regex/keyword matching against 80+ phishing patterns across 8 categories. Returns a risk score in <100 ms.

**Stage 2 — GenAI Analysis (Claude AI)**
Triggered for uncertain (30-70) or high-risk (>70) scores. Claude analyzes context, social engineering tactics, and cultural nuance. Returns a refined score with Hinglish explanation.

**Score Combination**
- Pattern score <30 → return pattern result only (safe)
- Difference >30 → trust GenAI score
- Otherwise → weighted average (GenAI 70%, Pattern 30%)

## Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate   # Linux/Mac
pip install -r requirements.txt
```

### Environment variables

Copy the template and add your API key:

```bash
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | Yes (for GenAI) | — | Claude API key |
| `API_PORT` | No | 8000 | Server port |
| `LOG_LEVEL` | No | INFO | Logging level |
| `CACHE_TTL` | No | 60 | Cache TTL in seconds |
| `MAX_CACHE_SIZE` | No | 1000 | Max cached entries |
| `ENABLE_GENAI` | No | true | Enable/disable GenAI |
| `GENAI_TIMEOUT` | No | 5 | GenAI request timeout (s) |

The backend works without an API key — it falls back to pattern-only detection.

## Running

```bash
python app.py
# Server starts on http://localhost:8000
```

## API Endpoints

### `GET /` — Health check

```bash
curl http://localhost:8000/
```

### `POST /analyze` — Analyze a message

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"text":"URGENT! Password share karo immediately!"}'
```

Response:

```json
{
  "overall_risk": 85,
  "severity": "critical",
  "method": "hybrid",
  "ml_score": 80,
  "genai_score": 88,
  "threats": [
    {
      "phrase": "password share karo",
      "risk": 90,
      "category": "credential_request",
      "explanation": "Yeh message aapke password maang raha hai..."
    }
  ],
  "processing_time_ms": 234.5,
  "cached": false
}
```

### `POST /batch-analyze` — Analyze multiple messages

```bash
curl -X POST http://localhost:8000/batch-analyze \
  -H "Content-Type: application/json" \
  -d '{"texts":["msg1","msg2"]}'
```

### `GET /stats` — Usage statistics

```bash
curl http://localhost:8000/stats
```

### `GET /patterns` — View loaded patterns

```bash
curl http://localhost:8000/patterns
```

## Testing

### Unit tests (pytest)

```bash
cd backend
pytest tests/ -v
```

### Backend verification (requires running server)

```bash
python app.py &
python scripts/test_backend.py
```

### GenAI integration test

```bash
python scripts/test_genai.py
```

### Load test

```bash
python scripts/load_test.py
```

## Project Structure

```
backend/
├── app.py                  # FastAPI application
├── requirements.txt
├── .env.example
├── models/
│   ├── pattern_matcher.py  # Rule-based pattern detection
│   ├── risk_scorer.py      # Risk calculation and severity
│   └── patterns.json       # 80+ phishing patterns
├── services/
│   ├── classifier.py       # Hybrid classifier (ML + GenAI)
│   ├── genai_analyzer.py   # Claude API integration
│   └── cache_manager.py    # In-memory LRU cache
├── api/
│   └── routes.py           # API endpoints
├── utils/
│   ├── text_processor.py   # Text normalization and hashing
│   └── logger.py           # Logging configuration
├── tests/
│   ├── test_api.py         # API tests
│   ├── test_classifier.py  # Unit tests
│   └── test_data.json      # Test dataset
├── data/
│   ├── training_examples.json  # Labeled examples
│   └── test_messages.json      # Real-world test messages
└── scripts/
    ├── test_backend.py     # Full backend verification
    ├── test_genai.py       # GenAI integration test
    └── load_test.py        # Performance test
```

## Troubleshooting

**Server won't start**
- Check Python version: `python --version` (needs 3.11+)
- Install dependencies: `pip install -r requirements.txt`

**GenAI not working**
- Verify API key: `echo $ANTHROPIC_API_KEY`
- Run: `python scripts/test_genai.py`
- The backend still works without GenAI (pattern-only mode)

**Slow responses**
- First request triggers GenAI; subsequent identical requests are cached
- Set `ENABLE_GENAI=false` for pattern-only mode (<100 ms)
