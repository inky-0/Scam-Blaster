# Scam-Blaster

Email fraud detection tool that identifies spam, phishing, and scam emails.

## Features

- Detects urgency tactics, financial scams, phishing attempts, and threats
- Analyzes email headers (SPF/DKIM failures)
- Identifies suspicious domains and URLs
- Scores emails 0-100 with detailed reasoning
- Optional OpenAI integration for enhanced detection

## Installation

```bash
git clone https://github.com/yourusername/Scam-Blaster.git
cd Scam-Blaster
pip install openai
```

## Usage

```python
from email_spam_detector import tag_email

email = {
    "to": ["user@example.com"],
    "from": "prince@totallylegit.com",
    "subject": "URGENT: You Won $1,000,000!",
    "message": "Send your bank details to claim prize...",
    "headers": [{"SPF": "fail"}]
}

result = tag_email(email)
print(f"Scam Score: {result['scam_score']}/100")
```

## Output

```json
{
  "scam_score": 92,
  "reasons": [
    "Urgency phrases detected: urgent",
    "Financial scam phrases detected: bank details, claim prize",
    "Suspicious header: spf=fail"
  ]
}
```

## License

MIT