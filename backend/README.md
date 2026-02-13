# SurakshaAI Shield — Backend

Phishing detection API for Indian multilingual/code-mixed messages using:
1) **ML classifier** (primary detector)
2) **GenAI (Claude)** for contextual explanation/refinement

## Model stack
- **ML model:** `TF-IDF + Logistic Regression (pure Python implementation)`
- **GenAI model:** `claude-sonnet-4-20250514` (optional; needs `ANTHROPIC_API_KEY`)
- **Method labels in API:** `ml` or `ml+genai`

## Dataset
A 7,500-row multilingual dataset is provided at:
- `backend/data/phishing_multilingual_7500.csv`

Columns:
- `text`
- `label` (`1=phishing`, `0=safe`)
- `language_mix`
- `category`
- `source`

## Training instructions
```bash
cd backend
python scripts/train_ml_model.py
```

This trains and saves the model to:
- `backend/models/phishing_tfidf_logreg_model.json`

To regenerate the 7,500 dataset:
```bash
python scripts/generate_multilingual_dataset.py
```

## Run
```bash
python app.py
```

## API
- `POST /analyze`
- `POST /batch-analyze`
- `GET /stats`
- `GET /patterns` (deprecated compatibility route; pattern engine removed)

## Notes
- Input validation is enforced through request schema (`1..5000` chars), so invalid requests return `422`.
- If GenAI key is unavailable, service still works with ML-only detection.
