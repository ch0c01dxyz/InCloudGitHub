"""
Sensitive information detection module
"""
import re
from typing import List, Dict, Optional
from config import SENSITIVE_PATTERNS, EXCLUDED_EXTENSIONS, EXCLUDED_DIRS


class SecretDetector:
    """Sensitive information detector"""

    def __init__(self, patterns: List[str] = SENSITIVE_PATTERNS):
        """
        Initialize detector

        Args:
            patterns: List of regular expression patterns
        """
        self.patterns = [re.compile(pattern) for pattern in patterns]
        self.excluded_extensions = EXCLUDED_EXTENSIONS
        self.excluded_dirs = EXCLUDED_DIRS
    
    def should_scan_file(self, file_path: str) -> bool:
        """
        Determine if file should be scanned

        Args:
            file_path: File path

        Returns:
            Whether file should be scanned
        """
        # Check file extension
        for ext in self.excluded_extensions:
            if file_path.lower().endswith(ext):
                return False

        # Check directory
        path_parts = file_path.split('/')
        for excluded_dir in self.excluded_dirs:
            if excluded_dir in path_parts:
                return False

        return True
    
    def detect_secrets_in_text(self, text: str, file_path: str = "") -> List[Dict]:
        """
        Detect sensitive information in text

        Args:
            text: Text content to detect
            file_path: File path (for reporting)

        Returns:
            List of detected sensitive information
        """
        if not text:
            return []

        findings = []
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            for pattern in self.patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    # Extract matched secret
                    secret = match.group(0)

                    # Check if it's a comment or example
                    if self._is_likely_example(line, secret):
                        continue

                    findings.append({
                        'file_path': file_path,
                        'line_number': line_num,
                        'line_content': line.strip(),
                        'secret': secret,
                        'pattern': pattern.pattern,
                        'confidence': self._calculate_confidence(secret, line)
                    })

        return findings
    
    def _is_likely_example(self, line: str, secret: str) -> bool:
        """
        Determine if likely example code

        Args:
            line: Code line
            secret: Detected secret

        Returns:
            Whether likely an example
        """
        line_lower = line.lower()

        # Check for example-related keywords
        example_keywords = [
            'example', 'sample', 'demo', 'test', 'placeholder',
            'your_api_key', 'your-api-key', 'xxx', 'yyy',
            'todo', 'replace', 'change_me', 'changeme'
        ]

        for keyword in example_keywords:
            if keyword in line_lower:
                return True

        # Check if secret contains obvious placeholder patterns
        placeholder_patterns = [
            r'x{10,}',  # Multiple x's
            r'_+',      # Multiple underscores
            r'\*{3,}',  # Multiple asterisks
        ]

        for pattern in placeholder_patterns:
            if re.search(pattern, secret, re.IGNORECASE):
                return True

        return False
    
    def _calculate_confidence(self, secret: str, line: str) -> str:
        """
        Calculate confidence level

        Args:
            secret: Detected secret
            line: Code line

        Returns:
            Confidence level (high/medium/low)
        """
        # High confidence: complete key format and not in comments
        if (secret.startswith('sk-') and len(secret) > 40 and
            not line.strip().startswith('#') and
            not line.strip().startswith('//')):
            return 'high'

        # Medium confidence: matches basic pattern
        if len(secret) >= 30:
            return 'medium'

        # Low confidence
        return 'low'
    
    def filter_high_confidence(self, findings: List[Dict]) -> List[Dict]:
        """
        Filter out high confidence findings

        Args:
            findings: List of detection results

        Returns:
            High confidence results
        """
        return [f for f in findings if f['confidence'] in ['high', 'medium']]

    def deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Remove duplicate findings

        Args:
            findings: List of detection results

        Returns:
            Deduplicated results
        """
        seen = set()
        unique_findings = []

        for finding in findings:
            # Use secret and file_path as unique identifier
            key = (finding['secret'], finding['file_path'])
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return unique_findings
