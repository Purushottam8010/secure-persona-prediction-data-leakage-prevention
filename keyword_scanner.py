# app/security/keyword_scanner.py
import re
import json
import pickle
from pathlib import Path

class KeywordScanner:
    def __init__(self):
        self.keywords = self.load_keywords()
        self.patterns = self.compile_patterns()
        
    def load_keywords(self):
        """Load 1000+ keywords from JSON file"""
        keywords_path = Path("config/keywords.json")
        
        if not keywords_path.exists():
            # Create default keywords file
            default_keywords = {
                "pii": [
                    "social security", "ssn", "passport number", "driver license",
                    "credit card", "bank account", "routing number", "dob",
                    "date of birth", "patient id", "medical record", "health insurance",
                    # ... 200+ more PII terms
                ],
                "credentials": [
                    "password", "secret", "token", "api_key", "auth_token",
                    "bearer token", "oauth", "private key", "ssh key", "aws_key",
                    # ... 150+ credential terms
                ],
                "financial": [
                    "confidential", "proprietary", "trade secret", "nda",
                    "non-disclosure", "internal only", "strictly confidential",
                    "company secret", "business strategy", "merger", "acquisition",
                    # ... 200+ financial terms
                ],
                "threats": [
                    "exploit", "malware", "ransomware", "trojan", "virus",
                    "phishing", "brute force", "ddos", "backdoor", "rootkit",
                    # ... 150+ threat terms
                ]
            }
            
            # Create config directory if it doesn't exist
            keywords_path.parent.mkdir(exist_ok=True)
            
            with open(keywords_path, 'w') as f:
                json.dump(default_keywords, f, indent=2)
            
            return default_keywords
        
        with open(keywords_path, 'r') as f:
            return json.load(f)
    
    def compile_patterns(self):
        """Compile regex patterns for each category"""
        patterns = {}
        
        for category, terms in self.keywords.items():
            # Create case-insensitive regex pattern
            pattern_str = r'\b(' + '|'.join(
                re.escape(term) for term in terms
            ) + r')\b'
            
            patterns[category] = re.compile(pattern_str, re.IGNORECASE)
        
        return patterns
    
    def scan_text(self, text):
        """Scan text for sensitive keywords"""
        results = {
            "match_count": 0,
            "categories_found": [],
            "matches": [],
            "risk_score": 0.0
        }
        
        for category, pattern in self.patterns.items():
            matches = list(pattern.finditer(text))
            
            if matches:
                results["categories_found"].append(category)
                results["match_count"] += len(matches)
                
                for match in matches:
                    # Get context (50 chars before/after)
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    context = text[start:end]
                    
                    results["matches"].append({
                        "keyword": match.group(),
                        "category": category,
                        "position": match.start(),
                        "context": context,
                        "severity": self.get_severity(category)
                    })
        
        # Calculate risk score
        results["risk_score"] = self.calculate_risk_score(results)
        
        return results
    
    def get_severity(self, category):
        severity_map = {
            "pii": "high",
            "credentials": "critical",
            "financial": "high",
            "threats": "medium"
        }
        return severity_map.get(category, "low")
    
    def calculate_risk_score(self, results):
        """Calculate risk score based on matches"""
        weights = {
            "pii": 0.4,
            "credentials": 0.8,
            "financial": 0.6,
            "threats": 0.5
        }
        
        score = 0
        for match in results["matches"]:
            score += weights.get(match["category"], 0.1)
        
        # Normalize to 0-1 range
        return min(1.0, score / 10.0)