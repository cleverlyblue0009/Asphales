"""Advanced link and scam detection with comprehensive threat analysis."""

import re
from typing import List, Dict, Tuple
from urllib.parse import urlparse

from utils.logger import setup_logger

logger = setup_logger("link_analyzer")


class AdvancedLinkAnalyzer:
    """Detects malicious links and scam patterns with high accuracy."""

    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = {
        ".top",
        ".xyz",
        ".click",
        ".gq",
        ".tk",
        ".work",
        ".fit",
        ".site",
        ".link",
        ".pw",
        ".date",
        ".review",
        ".win",
        ".stream",
        ".party",
        ".download",
        ".science",
        ".trade",
        ".accountant",
        ".space",
        ".rocks",
        ".hosting",
        ".monster",
        ".bid",
        ".download",
        ".faith",
        ".rest",
        ".webcam",
        ".repair",
        ".systems",
        ".services",
    }

    # URL shorteners commonly used to hide phishing links
    URL_SHORTENERS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "short.link",
        "tiny.cc",
        "shorte.st",
        "u.to",
        "x.co",
        "link.zip",
        "2no.co",
        "short.cm",
    }

    # Common phishing keywords and scam patterns
    URGENCY_KEYWORDS = {
        "urgent",
        "immediately",
        "now",
        "asap",
        "final warning",
        "last chance",
        "act now",
        "hurry",
        "before it's too late",
        "don't wait",
        "तुरंत",
        "जल्दी",
        "अभी",
        "तुरंता",
        "अब",
        "உடனே",
        "உடனடி",
        "ஆண்டு",
        "क्षण",
        "forthwith",
        "immediately",
        "תיכף",
    }

    CREDENTIAL_KEYWORDS = {
        "password",
        "otp",
        "cvv",
        "pin",
        "kyc",
        "aadhar",
        "pan",
        "ssn",
        "account",
        "verify",
        "confirm",
        "authenticate",
        "login",
        "sign in",
        "card number",
        "debit card",
        "credit card",
        "bank account",
        "पासवर्ड",
        "ओटीपी",
        "सीवीवी",
        "पिन",
        "केवाईसी",
        "आधार",
        "पान",
        "खाता",
        "सत्यापन",
        "पुष्टि",
        "प्रमाणीकरण",
        "लॉगिन",
        "साइन इन",
        "কার্ড",
        "পাসওয়ার্ড",
        "অ্যাকাউন্ট",
        "সত্যাপন",
    }

    IMPERSONATION_KEYWORDS = {
        "bank",
        "rbi",
        "sbi",
        "hdfc",
        "icici",
        "axis",
        "paypal",
        "amazon",
        "google",
        "apple",
        "microsoft",
        "admin",
        "support",
        "security team",
        "verification team",
        "compliance team",
        "official",
        "authorized",
        "certified",
        "administrator",
        "manager",
        "supervisor",
        "बैंक",
        "आरबीआई",
        "एसबीआई",
        "एचडीएफसी",
        "आईसीआईसीआई",
        "एक्सिस",
        "एडमिन",
        "सपोर्ट",
        "सुरक्षा दल",
        "सत्यापन दल",
        "आधिकारिक",
        "अधिकृत",
    }

    REWARD_SCAM_KEYWORDS = {
        "prize",
        "reward",
        "won",
        "lottery",
        "bonus",
        "refund",
        "claim",
        "payment pending",
        "transfer",
        "money",
        "cash",
        "compensation",
        "inheritance",
        "settlement",
        "congratulations",
        "lucky",
        "lucky draw",
        "grand prize",
        "इनाम",
        "पुरस्कार",
        "लॉटरी",
        "बोनस",
        "रिफंड",
        "दावा",
        "पेमेंट",
        "ट्रांसफर",
        "पैसा",
        "नकद",
        "मुआवजा",
        "विरासत",
        "समझौता",
        "बधाई",
        "भाग्यशाली",
    }

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract all URLs from text."""
        url_pattern = r"https?://[^\s\)]+|www\.[^\s\)]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?"
        return re.findall(url_pattern, text, re.IGNORECASE)

    @classmethod
    def analyze_url(cls, url: str) -> Dict[str, any]:
        """Analyze a single URL for phishing indicators."""
        risk_score = 0.0
        risk_factors = []

        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            domain = parsed.netloc or url.split("/")[0]

            # Check for suspicious TLD
            for tld in cls.SUSPICIOUS_TLDS:
                if domain.lower().endswith(tld):
                    risk_score += 0.25
                    risk_factors.append(f"Suspicious TLD: {tld}")
                    break

            # Check for URL shortener
            for shortener in cls.URL_SHORTENERS:
                if shortener in domain.lower():
                    risk_score += 0.20
                    risk_factors.append(f"URL shortener detected: {shortener}")
                    break

            # Check for IP address instead of domain
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
                risk_score += 0.30
                risk_factors.append("IP address used instead of domain (common in phishing)")

            # Check for punycode (internationalized domain names that look like legitimate domains)
            if "xn--" in domain:
                risk_score += 0.15
                risk_factors.append("Punycode domain (potential homograph attack)")

            # Check for too many subdomains (common obfuscation)
            subdomain_count = domain.count(".")
            if subdomain_count > 3:
                risk_score += 0.10
                risk_factors.append(f"Suspicious subdomain structure: {subdomain_count} dots")

            # Check for suspicious keywords in domain
            suspicious_domain_keywords = ["secure", "verify", "confirm", "update", "support", "login"]
            for keyword in suspicious_domain_keywords:
                if keyword in domain.lower():
                    # Check if it's a legitimate domain that contains these words
                    if not any(
                        legit in domain.lower()
                        for legit in [
                            "github",
                            "google",
                            "amazon",
                            "official",
                            "verifieddomain",
                        ]
                    ):
                        risk_score += 0.08
                        risk_factors.append(f"Phishing keyword in domain: {keyword}")

            # Check for domain misspelling patterns
            legitimate_domains = [
                "facebook.com",
                "google.com",
                "amazon.com",
                "microsoft.com",
                "apple.com",
                "paypal.com",
            ]
            for legit in legitimate_domains:
                if cls._similar_domain(domain.lower(), legit):
                    risk_score += 0.35
                    risk_factors.append(f"Domain similar to: {legit} (homoglyphic attack)")

        except Exception as e:
            logger.warning(f"Error analyzing URL {url}: {e}")

        # Clamp score to 0-1
        risk_score = min(1.0, risk_score)

        return {
            "url": url,
            "risk_score": risk_score,
            "is_suspicious": risk_score >= 0.3,
            "risk_factors": risk_factors,
        }

    @staticmethod
    def _similar_domain(domain: str, target: str) -> bool:
        """Check if domain is similar to target (homoglyphic attack)."""
        # Simple similarity check: check for common misspellings
        similar_pairs = [
            ("goog1e", "google"),
            ("amazo", "amazon"),
            ("faceboo", "facebook"),
            ("paypol", "paypal"),
            ("microsof", "microsoft"),
            ("app1e", "apple"),
        ]

        for misspelled, original in similar_pairs:
            if misspelled in domain and original in target:
                return True

        # Check if domain has extra characters inserted
        for i, char in enumerate(target):
            if i < len(domain) and domain[i] != char:
                # Allow one character difference
                if abs(ord(domain[i]) - ord(char)) <= 1:
                    continue
                return False
        return False

    @classmethod
    def analyze_text_for_scams(
        cls, text: str
    ) -> Tuple[float, List[str], List[str]]:
        """
        Analyze text for scam patterns.

        Returns:
            Tuple of (risk_score, detected_tactics, warning_signs)
        """
        text_lower = text.lower()
        risk_score = 0.0
        tactics = []
        warning_signs = []

        # Check for urgency tactics
        urgency_count = sum(1 for keyword in cls.URGENCY_KEYWORDS if keyword in text_lower)
        if urgency_count > 0:
            risk_score += 0.15 * min(urgency_count, 3)
            tactics.append("Urgency Tactic")
            warning_signs.append(f"Repeated urgency keywords ({urgency_count} found)")

        # Check for credential requests
        cred_count = sum(1 for keyword in cls.CREDENTIAL_KEYWORDS if keyword in text_lower)
        if cred_count > 0:
            risk_score += 0.20 * min(cred_count, 3)
            tactics.append("Credential Harvesting")
            warning_signs.append(f"Requests for sensitive information ({cred_count} indicators)")

        # Check for impersonation
        impersonation_count = sum(
            1 for keyword in cls.IMPERSONATION_KEYWORDS if keyword in text_lower
        )
        if impersonation_count > 0:
            risk_score += 0.18 * min(impersonation_count, 2)
            tactics.append("Impersonation")
            warning_signs.append(f"Impersonates authority ({impersonation_count} found)")

        # Check for reward/money scams
        reward_count = sum(1 for keyword in cls.REWARD_SCAM_KEYWORDS if keyword in text_lower)
        if reward_count > 0:
            risk_score += 0.15 * min(reward_count, 2)
            tactics.append("Financial Incentive")
            warning_signs.append(f"Too-good-to-be-true offers ({reward_count} found)")

        # Check for combination of tactics (amplifies risk)
        tactic_combinations = [
            ("urgency", "credential", 0.1),
            ("impersonation", "urgency", 0.1),
            ("reward", "credential", 0.15),
            ("impersonation", "reward", 0.08),
        ]

        for tactic1, tactic2, bonus in tactic_combinations:
            has_tactic1 = any(kw in text_lower for kw in getattr(cls, f"{tactic1.upper()}_KEYWORDS"))
            has_tactic2 = any(kw in text_lower for kw in getattr(cls, f"{tactic2.upper()}_KEYWORDS"))
            if has_tactic1 and has_tactic2:
                risk_score += bonus
                warning_signs.append(f"Combined {tactic1} + {tactic2} tactics detected")

        # Extract and analyze URLs
        urls = cls.extract_urls(text)
        suspicious_urls = []
        for url in urls:
            url_analysis = cls.analyze_url(url)
            if url_analysis["is_suspicious"]:
                risk_score += 0.1
                suspicious_urls.append(url)
                warning_signs.extend(url_analysis["risk_factors"])

        if suspicious_urls:
            tactics.append("Suspicious Links")

        # Clamp to 0-1
        risk_score = min(1.0, max(0.0, risk_score))

        return risk_score, list(set(tactics)), warning_signs

    def get_info(self) -> dict:
        """Get analyzer capabilities."""
        return {
            "name": "Advanced Link Analyzer",
            "suspicious_tlds": len(self.SUSPICIOUS_TLDS),
            "url_shorteners_tracked": len(self.URL_SHORTENERS),
            "urgency_keywords": len(self.URGENCY_KEYWORDS),
            "credential_keywords": len(self.CREDENTIAL_KEYWORDS),
            "impersonation_keywords": len(self.IMPERSONATION_KEYWORDS),
            "reward_scam_keywords": len(self.REWARD_SCAM_KEYWORDS),
        }
