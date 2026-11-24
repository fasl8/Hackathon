# ZeroTrust

## 1. Problem and Solution 

### Problem
Online scams use suspicious links, fake websites, phishing messages, and brand impersonation to trick users into sharing personal or financial information. Users may find it difficult to identify these threats before interacting with them.

### Solution
**ZeroTrust** is a cybersecurity project that combines rule-based URL detection with Generative AI to identify potential online scams.

The system provides:
- Local URL analysis to detect suspicious domains and technical indicators.
- AI-powered analysis of Arabic and English messages using Google Gemini API.
- Five independent demo phone instances for testing.
- A local Security Operations Center (SOC) to monitor manually performed scans and display their results.

## 2. Technical Choices / Tools / APIs / Data

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Flask | Backend and API endpoints |
| HTML, CSS, JavaScript | User interface and SOC dashboard |
| Google Gemini API | AI-powered text and message analysis |
| Google Web Risk API | Optional threat-list checking |
| RDAP | Domain registration information |
| CSV | URL evaluation datasets |
| JSON | Exporting AI analysis results |
| unittest | Automated testing |

**Main project files:**
- `app.py`: Flask application and API endpoints.
- `security_engine.py`: Rule-based URL analysis.
- `ai_analyzer.py`: Arabic and English content analysis using Gemini.
- `templates/index.html`: User interface, five demo phone instances, and SOC dashboard.
- `data/known_bad_urls.txt`: Optional list of confirmed malicious URLs.
- `tests/`: Automated tests.
- `evaluate_urls.py`: Model evaluation using Precision, Recall, F1-score, and False Positive Rate.

**Data:** The current MVP uses temporary in-memory mock data. It does not use a real database or connect to physical devices. Only manually performed demo activities appear in the SOC dashboard.

## 3. How to Build and Run the Project

### Requirements
- Python 3
- GitHub project downloaded to the computer
- Google Gemini API key (optional for AI analysis)

### Step 1: Install dependencies

Open the project folder in VS Code, then run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Configure environment variables

1. Copy `.env.example` and rename the copy to `.env`.
2. Add the required API keys:

```env
GEMINI_API_KEY=YOUR_GEMINI_API_KEY
GEMINI_MODEL=YOUR_GEMINI_MODEL
GOOGLE_WEB_RISK_API_KEY=YOUR_WEB_RISK_API_KEY
ENABLE_RDAP=1
```

Gemini is required for AI content analysis. Google Web Risk and RDAP are optional.

**Important:** Never upload `.env` or API keys to GitHub.

### Step 3: Run the application

```bash
python app.py
```

Open the application at:

http://127.0.0.1:5000

### Step 4: Run tests

```bash
python -m unittest discover -s tests -v
```

**Note:** Without a Gemini API key, local URL scanning remains available, but AI content analysis will be disabled.