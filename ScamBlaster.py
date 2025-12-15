import json
import re
import hashlib
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
from urllib.parse import urlparse
from openai import OpenAI


@dataclass
class FilterResult:
    triggered: bool
    score_adjustment: int
    reasons: List[str]


class SpamKeywordDatabase:
    
    URGENCY_PHRASES = [
        "act now", "act immediately", "urgent", "immediate action required",
        "respond immediately", "time sensitive", "limited time", "expires today",
        "last chance", "final notice", "deadline", "don't delay", "hurry",
        "quick response needed", "asap", "right away", "without delay",
        "time is running out", "offer expires", "today only", "now or never",
        "immediate response required", "urgent action needed", "act fast",
        "limited availability", "while supplies last", "ending soon"
    ]
    
    FINANCIAL_SCAM_PHRASES = [
        "wire transfer", "bank account details", "processing fee", "advance fee",
        "send money", "western union", "moneygram", "bitcoin payment",
        "cryptocurrency", "investment opportunity", "guaranteed returns",
        "double your money", "risk free", "no risk", "100% guaranteed",
        "make money fast", "get rich quick", "financial freedom", "passive income",
        "secret investment", "offshore account", "tax haven", "untraceable",
        "cash prize", "prize money", "claim your prize", "lottery winner",
        "you have won", "congratulations you won", "unclaimed funds",
        "inheritance money", "beneficiary", "next of kin", "late client",
        "dormant account", "unclaimed inheritance", "million dollars",
        "transfer funds", "release funds", "processing charges"
    ]
    
    CREDENTIAL_PHISHING_PHRASES = [
        "verify your account", "confirm your identity", "update your information",
        "password expired", "account suspended", "account locked",
        "unusual activity", "suspicious activity", "security alert",
        "login credentials", "verify your email", "confirm your password",
        "reset your password", "account verification required",
        "your account will be closed", "failure to verify", "click here to verify",
        "enter your details", "provide your information", "submit your credentials",
        "social security number", "ssn", "date of birth", "mother's maiden name",
        "security questions", "pin number", "credit card number", "cvv",
        "expiration date", "billing information", "payment details"
    ]
    
    THREAT_PHRASES = [
        "legal action", "lawsuit", "court order", "arrest warrant",
        "police report", "criminal charges", "prosecution", "imprisonment",
        "warrant for your arrest", "federal investigation", "irs audit",
        "tax evasion", "account termination", "service disconnection",
        "collection agency", "credit score damage", "blacklist",
        "permanent ban", "legal consequences", "face charges"
    ]
    
    IMPERSONATION_KEYWORDS = [
        "official notice", "official notification", "from the desk of",
        "office of the president", "royal family", "government agency",
        "federal bureau", "internal revenue service", "social security administration",
        "microsoft support", "apple support", "google security team",
        "facebook security", "paypal security", "amazon security",
        "bank security department", "fraud department", "security team",
        "customer service department", "technical support", "it department",
        "ceo", "chief executive", "board of directors", "chairman"
    ]
    
    SUSPICIOUS_GREETINGS = [
        "dear friend", "dear beloved", "dear winner", "dear beneficiary",
        "dear customer", "dear user", "dear account holder", "dear sir/madam",
        "dear valued customer", "dear email user", "dear webmail user",
        "attention", "to whom it may concern", "dear lucky winner",
        "dear internet user", "hello friend", "greetings friend"
    ]
    
    TOO_GOOD_TO_BE_TRUE = [
        "free money", "free gift", "free vacation", "free trip",
        "you've been selected", "specially selected", "exclusively chosen",
        "one in a million", "lucky winner", "grand prize", "jackpot",
        "no purchase necessary", "no obligation", "no cost", "absolutely free",
        "100% free", "complimentary", "gift card", "voucher", "coupon code",
        "discount code", "special offer", "exclusive deal", "secret deal",
        "insider information", "confidential opportunity", "private offer"
    ]


class SuspiciousDomainDatabase:
    
    KNOWN_SPAM_TLDS = [
        ".xyz", ".top", ".click", ".link", ".work", ".date", ".download",
        ".stream", ".racing", ".win", ".bid", ".trade", ".webcam", ".party",
        ".science", ".review", ".country", ".cricket", ".accountant",
        ".loan", ".men", ".gq", ".cf", ".ga", ".ml", ".tk"
    ]
    
    SUSPICIOUS_DOMAIN_PATTERNS = [
        r".*-secure.*", r".*-login.*", r".*-verify.*", r".*-account.*",
        r".*-update.*", r".*-confirm.*", r".*-support.*", r".*-service.*",
        r".*paypal.*(?!paypal\.com$)", r".*apple.*(?!apple\.com$)",
        r".*google.*(?!google\.com$)", r".*microsoft.*(?!microsoft\.com$)",
        r".*amazon.*(?!amazon\.com$)", r".*facebook.*(?!facebook\.com$)",
        r".*netflix.*(?!netflix\.com$)", r".*bankofamerica.*(?!bankofamerica\.com$)",
        r".*wellsfargo.*(?!wellsfargo\.com$)", r".*chase.*(?!chase\.com$)"
    ]
    
    KNOWN_SPAM_DOMAINS = [
        "totallylegit.com", "secure-update.com", "account-verify.net",
        "login-secure.org", "payment-confirm.com", "suspicious.ru",
        "malware.cn", "phishing.tk", "scammer.ml", "fraud.ga"
    ]
    
    HIGH_RISK_COUNTRIES = [".ru", ".cn", ".ng", ".pk", ".ua", ".by", ".kz"]
    
    FREE_EMAIL_DOMAINS = [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
        "mail.com", "protonmail.com", "zoho.com", "yandex.com", "mail.ru",
        "gmx.com", "icloud.com", "live.com", "msn.com"
    ]


class HeaderAnalyzer:
    
    SUSPICIOUS_HEADERS = {
        "x-spam-status": ["yes", "high", "spam"],
        "x-spam-flag": ["yes", "true"],
        "spf": ["fail", "softfail", "none", "neutral"],
        "dkim": ["fail", "none"],
        "dmarc": ["fail", "none"],
        "x-originating-ip": [],
        "received-spf": ["fail", "softfail"]
    }
    
    @staticmethod
    def analyze_headers(headers: List) -> FilterResult:
        reasons = []
        score = 0
        
        if not headers:
            return FilterResult(triggered=False, score_adjustment=0, reasons=[])
        
        header_dict = {}
        for header in headers:
            if isinstance(header, dict):
                for key, value in header.items():
                    header_dict[key.lower()] = str(value).lower()
        
        for header_name, suspicious_values in HeaderAnalyzer.SUSPICIOUS_HEADERS.items():
            if header_name in header_dict:
                header_value = header_dict[header_name]
                
                if not suspicious_values:
                    continue
                    
                for suspicious_value in suspicious_values:
                    if suspicious_value in header_value:
                        reasons.append(f"Suspicious header detected: {header_name}={header_value}")
                        score += 15
                        break
        
        if "return-path" in header_dict:
            return_path = header_dict["return-path"]
            reasons.append(f"Return-Path header present with value: {return_path}")
            score += 5
        
        if "x-mailer" in header_dict:
            mailer = header_dict["x-mailer"]
            suspicious_mailers = ["phpmailer", "bulk", "mass", "campaign"]
            for sm in suspicious_mailers:
                if sm in mailer:
                    reasons.append(f"Suspicious mailer detected: {mailer}")
                    score += 10
                    break
        
        return FilterResult(
            triggered=len(reasons) > 0,
            score_adjustment=min(score, 40),
            reasons=reasons
        )


class ContentAnalyzer:
    
    @staticmethod
    def check_keyword_density(text: str, keywords: List[str]) -> Tuple[int, List[str]]:
        text_lower = text.lower()
        found_keywords = []
        
        for keyword in keywords:
            if keyword.lower() in text_lower:
                found_keywords.append(keyword)
        
        return len(found_keywords), found_keywords
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        
        href_pattern = r'href=["\']([^"\']+)["\']'
        href_urls = re.findall(href_pattern, text, re.IGNORECASE)
        
        return list(set(urls + href_urls))
    
    @staticmethod
    def analyze_urls(urls: List[str]) -> FilterResult:
        reasons = []
        score = 0
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                for tld in SuspiciousDomainDatabase.KNOWN_SPAM_TLDS:
                    if domain.endswith(tld):
                        reasons.append(f"URL uses suspicious TLD: {url}")
                        score += 15
                        break
                
                for pattern in SuspiciousDomainDatabase.SUSPICIOUS_DOMAIN_PATTERNS:
                    if re.match(pattern, domain):
                        reasons.append(f"URL matches suspicious pattern: {url}")
                        score += 20
                        break
                
                if domain in SuspiciousDomainDatabase.KNOWN_SPAM_DOMAINS:
                    reasons.append(f"URL uses known spam domain: {url}")
                    score += 30
                
                for country_tld in SuspiciousDomainDatabase.HIGH_RISK_COUNTRIES:
                    if domain.endswith(country_tld):
                        reasons.append(f"URL from high-risk country domain: {url}")
                        score += 10
                        break
                
                if len(domain) > 50:
                    reasons.append(f"Unusually long domain name: {domain}")
                    score += 10
                
                if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                    reasons.append(f"URL uses IP address instead of domain: {url}")
                    score += 25
                
                if domain.count('.') > 4:
                    reasons.append(f"Excessive subdomains in URL: {url}")
                    score += 10
                
            except Exception:
                reasons.append(f"Malformed URL detected: {url}")
                score += 5
        
        return FilterResult(
            triggered=len(reasons) > 0,
            score_adjustment=min(score, 50),
            reasons=reasons
        )
    
    @staticmethod
    def check_obfuscation(text: str) -> FilterResult:
        reasons = []
        score = 0
        
        homoglyph_patterns = [
            (r'[0О]', 'zero/O substitution'),
            (r'[1lІ]', 'one/l/I substitution'),
            (r'[3Е]', 'three/E substitution'),
            (r'[4А]', 'four/A substitution'),
            (r'[5Ѕ]', 'five/S substitution'),
            (r'[@а]', 'at/a substitution'),
        ]
        
        leetspeak_words = [
            (r'p[a@4]ss?w[o0]rd', 'password'),
            (r'[a@4]cc[o0]unt', 'account'),
            (r's[e3]cur[i1]ty', 'security'),
            (r'v[e3]r[i1]fy', 'verify'),
            (r'l[o0]g[i1]n', 'login'),
            (r'b[a@4]nk', 'bank'),
            (r'cr[e3]d[i1]t', 'credit'),
            (r'p[a@4]ym[e3]nt', 'payment'),
        ]
        
        for pattern, word in leetspeak_words:
            if re.search(pattern, text, re.IGNORECASE):
                reasons.append(f"Possible leetspeak obfuscation of '{word}'")
                score += 15
        
        invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']
        for char in invisible_chars:
            if char in text:
                reasons.append("Invisible/zero-width characters detected")
                score += 20
                break
        
        if re.search(r'<[^>]*style\s*=\s*["\'][^"\']*display\s*:\s*none', text, re.IGNORECASE):
            reasons.append("Hidden text with CSS display:none detected")
            score += 25
        
        if re.search(r'<[^>]*style\s*=\s*["\'][^"\']*font-size\s*:\s*0', text, re.IGNORECASE):
            reasons.append("Hidden text with zero font-size detected")
            score += 25
        
        return FilterResult(
            triggered=len(reasons) > 0,
            score_adjustment=min(score, 40),
            reasons=reasons
        )
    
    @staticmethod
    def check_grammar_patterns(text: str) -> FilterResult:
        reasons = []
        score = 0
        
        poor_grammar_patterns = [
            (r'\bi am\s+(?:a\s+)?(?:mr|mrs|miss|dr)\.?\s+\w+\s+from', 'Nigerian prince style introduction'),
            (r'(?:my\s+)?(?:late|deceased)\s+(?:father|mother|husband|wife|client)', 'Inheritance scam pattern'),
            (r'god\s+bless\s+you', 'Common scam closing'),
            (r'remain\s+bless(?:ed)?', 'Common scam blessing'),
            (r'your\s+humble\s+servant', 'Overly formal closing'),
            (r'awaiting\s+your\s+(?:urgent\s+)?(?:response|reply)', 'Urgency pressure'),
            (r'kindly\s+(?:reply|respond|contact)', 'Scam email formality'),
            (r'dear\s+(?:one|friend|beloved)', 'Generic scam greeting'),
            (r'sum\s+of\s+\$?\d+', 'Money amount pattern'),
            (r'(?:us\s+)?dollars?\s+(?:only|\()', 'Currency emphasis pattern'),
            (r'next\s+of\s+kin', 'Inheritance scam keyword'),
            (r'modalities\s+for', 'Formal scam language'),
            (r'to\s+be\s+(?:of\s+)?(?:help|assistance)', 'Assistance offer pattern'),
        ]
        
        for pattern, description in poor_grammar_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                reasons.append(f"Detected scam language pattern: {description}")
                score += 10
        
        caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if caps_ratio > 0.3:
            reasons.append("Excessive use of capital letters")
            score += 10
        
        exclamation_count = text.count('!')
        if exclamation_count > 3:
            reasons.append(f"Excessive exclamation marks ({exclamation_count} found)")
            score += 5
        
        dollar_pattern = re.findall(r'\$[\d,]+(?:\.\d{2})?(?:\s*(?:million|billion|usd|dollars?))?', text, re.IGNORECASE)
        if len(dollar_pattern) > 2:
            reasons.append(f"Multiple money amounts mentioned ({len(dollar_pattern)} found)")
            score += 15
        
        return FilterResult(
            triggered=len(reasons) > 0,
            score_adjustment=min(score, 35),
            reasons=reasons
        )


class SenderAnalyzer:
    
    @staticmethod
    def analyze_sender(from_address: str, subject: str, to_addresses: List[str]) -> FilterResult:
        reasons = []
        score = 0
        
        email_pattern = r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        match = re.search(email_pattern, from_address)
        
        if not match:
            reasons.append("Invalid or malformed sender email address")
            score += 20
            return FilterResult(triggered=True, score_adjustment=score, reasons=reasons)
        
        local_part = match.group(1).lower()
        domain = match.group(2).lower()
        
        for tld in SuspiciousDomainDatabase.KNOWN_SPAM_TLDS:
            if domain.endswith(tld):
                reasons.append(f"Sender uses suspicious TLD: {tld}")
                score += 20
                break
        
        for country_tld in SuspiciousDomainDatabase.HIGH_RISK_COUNTRIES:
            if domain.endswith(country_tld):
                reasons.append(f"Sender from high-risk country domain: {country_tld}")
                score += 15
                break
        
        if domain in SuspiciousDomainDatabase.KNOWN_SPAM_DOMAINS:
            reasons.append(f"Sender uses known spam domain: {domain}")
            score += 40
        
        suspicious_local_patterns = [
            (r'^(?:admin|support|security|help|service|info|noreply|no-reply)\d*$', 'Generic service address'),
            (r'^[a-z]{1,3}\d{5,}$', 'Random looking address'),
            (r'^[a-z]+\.[a-z]+\d{3,}$', 'Pattern matching auto-generated address'),
            (r'(?:nigerian|prince|lottery|winner|claim|prize)', 'Scam keyword in address'),
        ]
        
        for pattern, description in suspicious_local_patterns:
            if re.match(pattern, local_part):
                reasons.append(f"Suspicious sender pattern: {description}")
                score += 10
                break
        
        if len(local_part) > 40:
            reasons.append("Unusually long sender local part")
            score += 5
        
        claimed_org_patterns = [
            (r'paypal', 'paypal.com'),
            (r'apple', 'apple.com'),
            (r'google', 'google.com'),
            (r'microsoft', 'microsoft.com'),
            (r'amazon', 'amazon.com'),
            (r'facebook', 'facebook.com'),
            (r'netflix', 'netflix.com'),
            (r'bank\s*of\s*america', 'bankofamerica.com'),
            (r'wells\s*fargo', 'wellsfargo.com'),
            (r'chase', 'chase.com'),
            (r'irs|internal\s*revenue', 'irs.gov'),
            (r'social\s*security', 'ssa.gov'),
        ]
        
        full_text = f"{from_address} {subject}".lower()
        for pattern, expected_domain in claimed_org_patterns:
            if re.search(pattern, full_text) and expected_domain not in domain:
                reasons.append(f"Possible impersonation: claims to be {expected_domain} but sent from {domain}")
                score += 30
                break
        
        if domain in SuspiciousDomainDatabase.FREE_EMAIL_DOMAINS:
            org_indicators = ['official', 'support', 'security', 'admin', 'team', 'department', 'service']
            for indicator in org_indicators:
                if indicator in local_part or indicator in subject.lower():
                    reasons.append(f"Official-sounding email from free email provider: {domain}")
                    score += 15
                    break
        
        return FilterResult(
            triggered=len(reasons) > 0,
            score_adjustment=min(score, 50),
            reasons=reasons
        )


class AttachmentAnalyzer:
    
    DANGEROUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.js', '.jse',
        '.vbs', '.vbe', '.wsf', '.wsh', '.ps1', '.msi', '.msp', '.hta',
        '.cpl', '.jar', '.reg', '.dll', '.sys', '.drv', '.ocx'
    ]
    
    SUSPICIOUS_EXTENSIONS = [
        '.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img',
        '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm'
    ]
    
    @staticmethod
    def analyze_attachment_references(text: str) -> FilterResult:
        reasons = []
        score = 0
        
        attachment_mentions = [
            r'(?:attached|attachment|enclosed|enclosure)',
            r'(?:open|download|view)\s+(?:the\s+)?(?:attached|file|document)',
            r'(?:click|press)\s+(?:here\s+)?to\s+(?:download|open|view)',
            r'see\s+attach(?:ed|ment)',
        ]
        
        has_attachment_mention = False
        for pattern in attachment_mentions:
            if re.search(pattern, text, re.IGNORECASE):
                has_attachment_mention = True
                break
        
        for ext in AttachmentAnalyzer.DANGEROUS_EXTENSIONS:
            if ext in text.lower():
                reasons.append(f"Reference to dangerous file type: {ext}")
                score += 25
        
        for ext in AttachmentAnalyzer.SUSPICIOUS_EXTENSIONS:
            pattern = rf'{re.escape(ext)}(?:\s|$|["\'])'
            if re.search(pattern, text, re.IGNORECASE):
                if has_attachment_mention:
                    reasons.append(f"Reference to potentially risky file type with attachment context: {ext}")
                    score += 10
        
        double_ext_pattern = r'\.\w{2,4}\.\w{2,4}'
        if re.search(double_ext_pattern, text):
            reasons.append("Possible double extension detected (common malware technique)")
            score += 20
        
        return FilterResult(
            triggered=len(reasons) > 0,
            score_adjustment=min(score, 35),
            reasons=reasons
        )


class HardcodedFilter:
    
    def __init__(self):
        self.keyword_db = SpamKeywordDatabase()
        self.domain_db = SuspiciousDomainDatabase()
        self.header_analyzer = HeaderAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.sender_analyzer = SenderAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
    
    def calculate_base_score(self, email: dict) -> Tuple[int, List[str]]:
        total_score = 0
        all_reasons = []
        
        message = email.get('message', '')
        subject = email.get('subject', '')
        full_text = f"{subject} {message}"
        
        urgency_count, urgency_words = self.content_analyzer.check_keyword_density(
            full_text, self.keyword_db.URGENCY_PHRASES
        )
        if urgency_count > 0:
            score_add = min(urgency_count * 5, 25)
            total_score += score_add
            all_reasons.append(f"Urgency phrases detected ({urgency_count}): {', '.join(urgency_words[:5])}")
        
        financial_count, financial_words = self.content_analyzer.check_keyword_density(
            full_text, self.keyword_db.FINANCIAL_SCAM_PHRASES
        )
        if financial_count > 0:
            score_add = min(financial_count * 8, 40)
            total_score += score_add
            all_reasons.append(f"Financial scam phrases detected ({financial_count}): {', '.join(financial_words[:5])}")
        
        phishing_count, phishing_words = self.content_analyzer.check_keyword_density(
            full_text, self.keyword_db.CREDENTIAL_PHISHING_PHRASES
        )
        if phishing_count > 0:
            score_add = min(phishing_count * 7, 35)
            total_score += score_add
            all_reasons.append(f"Credential phishing phrases detected ({phishing_count}): {', '.join(phishing_words[:5])}")
        
        threat_count, threat_words = self.content_analyzer.check_keyword_density(
            full_text, self.keyword_db.THREAT_PHRASES
        )
        if threat_count > 0:
            score_add = min(threat_count * 6, 30)
            total_score += score_add
            all_reasons.append(f"Threat phrases detected ({threat_count}): {', '.join(threat_words[:5])}")
        
        impersonation_count, impersonation_words = self.content_analyzer.check_keyword_density(
            full_text, self.keyword_db.IMPERSONATION_KEYWORDS
        )
        if impersonation_count > 0:
            score_add = min(impersonation_count * 5, 25)
            total_score += score_add
            all_reasons.append(f"Impersonation keywords detected ({impersonation_count}): {', '.join(impersonation_words[:5])}")
        
        greeting_count, greeting_words = self.content_analyzer.check_keyword_density(
            full_text, self.keyword_db.SUSPICIOUS_GREETINGS
        )
        if greeting_count > 0:
            total_score += 10
            all_reasons.append(f"Suspicious greeting detected: {greeting_words[0]}")
        
        tgtbt_count, tgtbt_words = self.content_analyzer.check_keyword_density(
            full_text, self.keyword_db.TOO_GOOD_TO_BE_TRUE
        )
        if tgtbt_count > 0:
            score_add = min(tgtbt_count * 6, 30)
            total_score += score_add
            all_reasons.append(f"Too-good-to-be-true phrases detected ({tgtbt_count}): {', '.join(tgtbt_words[:5])}")
        
        header_result = self.header_analyzer.analyze_headers(email.get('headers', []))
        if header_result.triggered:
            total_score += header_result.score_adjustment
            all_reasons.extend(header_result.reasons)
        
        urls = self.content_analyzer.extract_urls(full_text)
        if urls:
            url_result = self.content_analyzer.analyze_urls(urls)
            if url_result.triggered:
                total_score += url_result.score_adjustment
                all_reasons.extend(url_result.reasons)
        
        obfuscation_result = self.content_analyzer.check_obfuscation(full_text)
        if obfuscation_result.triggered:
            total_score += obfuscation_result.score_adjustment
            all_reasons.extend(obfuscation_result.reasons)
        
        grammar_result = self.content_analyzer.check_grammar_patterns(full_text)
        if grammar_result.triggered:
            total_score += grammar_result.score_adjustment
            all_reasons.extend(grammar_result.reasons)
        
        sender_result = self.sender_analyzer.analyze_sender(
            email.get('from', ''),
            subject,
            email.get('to', [])
        )
        if sender_result.triggered:
            total_score += sender_result.score_adjustment
            all_reasons.extend(sender_result.reasons)
        
        attachment_result = self.attachment_analyzer.analyze_attachment_references(full_text)
        if attachment_result.triggered:
            total_score += attachment_result.score_adjustment
            all_reasons.extend(attachment_result.reasons)
        
        return min(total_score, 100), all_reasons


def format_email_for_analysis(email: dict) -> str:
    formatted = []
    formatted.append(f"From: {email.get('from', 'Unknown')}")
    formatted.append(f"To: {', '.join(email.get('to', []))}")
    
    if email.get('cc'):
        formatted.append(f"CC: {', '.join(email.get('cc', []))}")
    
    formatted.append(f"Subject: {email.get('subject', 'No Subject')}")
    
    if email.get('headers'):
        formatted.append("\nHeaders:")
        for header in email.get('headers', []):
            if isinstance(header, dict):
                for key, value in header.items():
                    formatted.append(f"  {key}: {value}")
            else:
                formatted.append(f"  {header}")
    
    formatted.append(f"\nMessage Body:\n{email.get('message', '')}")
    
    return "\n".join(formatted)


def tag_email(input_email: dict) -> dict:
    
    hardcoded_filter = HardcodedFilter()
    prefilter_score, prefilter_reasons = hardcoded_filter.calculate_base_score(input_email)
    
    if prefilter_score >= 85:
        return {
            "scam_score": prefilter_score,
            "reasons": prefilter_reasons,
            "analysis_method": "hardcoded_filter_only",
            "filter_confidence": "very_high"
        }
    
    API_KEY = "YOUR_OPENAI_API_KEY_HERE"
    
    client = OpenAI(api_key=API_KEY)
    
    email_text = format_email_for_analysis(input_email)
    
    prefilter_context = ""
    if prefilter_score > 0:
        prefilter_context = f"""
Pre-analysis has detected the following potential issues with score {prefilter_score}/100:
{chr(10).join('- ' + r for r in prefilter_reasons[:10])}

Please verify these findings and add any additional observations."""
    
    system_prompt = """You are an expert email security analyst specializing in detecting phishing, scams, and fraudulent emails. Your task is to analyze emails and determine the likelihood that they are scams.

Analyze the provided email for common scam indicators including but not limited to:
- Urgency or pressure tactics
- Requests for personal information, passwords, or financial details
- Suspicious sender addresses or mismatched domains
- Grammar and spelling errors typical of scam emails
- Too-good-to-be-true offers (lottery winnings, inheritances, etc.)
- Threats or intimidation
- Suspicious links or attachments references
- Impersonation of legitimate organizations
- Unusual requests from known contacts
- Generic greetings when specific ones would be expected
- Mismatched "From" address and claimed sender
- Suspicious header information (SPF failures, unusual routing, etc.)

You MUST respond with ONLY a valid JSON object in this exact format:
{
    "scam_score": <integer from 0 to 100>,
    "reasons": [<list of specific reasons why this email might be a scam, or empty if none>]
}

The scam_score should be:
- 0-20: Very unlikely to be a scam
- 21-40: Low probability of being a scam
- 41-60: Moderate suspicion, some red flags present
- 61-80: High probability of being a scam
- 81-100: Almost certainly a scam

Provide specific, actionable reasons based on the actual content of the email."""

    user_prompt = f"""Please analyze the following email for scam indicators:

{email_text}
{prefilter_context}

Respond with only a JSON object containing "scam_score" (0-100) and "reasons" (list of strings)."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3,
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        
        api_score = int(result.get("scam_score", 0))
        api_reasons = list(result.get("reasons", []))
        
        if prefilter_score >= 50:
            combined_score = max(prefilter_score, api_score)
        elif prefilter_score >= 30:
            combined_score = int((prefilter_score * 0.4) + (api_score * 0.6))
        else:
            combined_score = int((prefilter_score * 0.3) + (api_score * 0.7))
        
        combined_score = min(combined_score, 100)
        
        all_reasons = []
        seen_reasons = set()
        
        for reason in prefilter_reasons + api_reasons:
            reason_hash = hashlib.md5(reason.lower().encode()).hexdigest()[:8]
            if reason_hash not in seen_reasons:
                seen_reasons.add(reason_hash)
                all_reasons.append(reason)
        
        return {
            "scam_score": combined_score,
            "reasons": all_reasons,
            "analysis_method": "combined",
            "prefilter_score": prefilter_score,
            "api_score": api_score,
            "filter_confidence": "high" if prefilter_score >= 50 else "moderate" if prefilter_score >= 30 else "low"
        }
        
    except json.JSONDecodeError:
        return {
            "scam_score": prefilter_score,
            "reasons": prefilter_reasons + ["API response parsing error - using hardcoded filter results only"],
            "analysis_method": "hardcoded_filter_fallback",
            "filter_confidence": "moderate"
        }
    except Exception as e:
        return {
            "scam_score": prefilter_score,
            "reasons": prefilter_reasons + [f"API error: {str(e)} - using hardcoded filter results only"],
            "analysis_method": "hardcoded_filter_fallback",
            "filter_confidence": "moderate"
        }


if __name__ == "__main__":
    
    test_email = {
        "to": ["victim@example.com"],
        "from": "nigerian.prince@totallylegit.com",
        "cc": [],
        "subject": "URGENT: You Have Won $5,000,000 USD!!!",
        "message": """Dear Beloved Friend,
        
I am Prince Abubakar from Nigeria. My late father left $5,000,000 USD and I need your help to transfer it. 
Please send me your bank account details and a processing fee of $500 to claim your share.

Act NOW or lose this opportunity forever!!!

God Bless,
Prince Abubakar""",
        
        "headers": [
            {"X-Spam-Status": "Yes"},
            {"SPF": "fail"},
            {"Return-Path": "different-email@suspicious.ru"}
        ]
    }
    
    test_email_2 = {
        "to": ["user@company.com"],
        "from": "security@paypa1-secure.com",
        "cc": [],
        "subject": "Your PayPal account has been limited",
        "message": """Dear Valued Customer,

We have noticed unusual activity on your PayPal account. Your account access has been limited until you verify your information.

Click here to verify your account: http://paypal-verify.suspicious.xyz/login

If you do not verify within 24 hours, your account will be permanently suspended.

PayPal Security Team""",
        "headers": [
            {"SPF": "none"},
            {"DKIM": "fail"}
        ]
    }
    
    test_email_3 = {
        "to": ["colleague@company.com"],
        "from": "john.smith@company.com",
        "cc": [],
        "subject": "Meeting tomorrow at 2pm",
        "message": """Hi,

Just wanted to confirm our meeting tomorrow at 2pm in Conference Room B.

Let me know if that still works for you.

Thanks,
John""",
        "headers": [
            {"SPF": "pass"},
            {"DKIM": "pass"}
        ]
    }
    
    print("=" * 80)
    print("TEST 1: Nigerian Prince Scam")
    print("=" * 80)
    result1 = tag_email(test_email)
    print(json.dumps(result1, indent=2))
    
    print("\n" + "=" * 80)
    print("TEST 2: PayPal Phishing")
    print("=" * 80)
    result2 = tag_email(test_email_2)
    print(json.dumps(result2, indent=2))
    
    print("\n" + "=" * 80)
    print("TEST 3: Legitimate Email")
    print("=" * 80)
    result3 = tag_email(test_email_3)
    print(json.dumps(result3, indent=2))