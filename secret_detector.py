"""
Sensitive information detection module
"""
import re
from typing import List, Dict, Optional, Set
from config import SENSITIVE_PATTERNS, EXCLUDED_EXTENSIONS, EXCLUDED_DIRS


class SecretDetector:
    """Sensitive information detector with optimized pattern matching"""

    def __init__(self, patterns: List[str] = SENSITIVE_PATTERNS):
        """
        Initialize detector with compiled patterns

        Args:
            patterns: List of regular expression patterns
        """
        # Compile all patterns at initialization for better performance
        self.patterns = [re.compile(pattern) for pattern in patterns]

        # Convert exclusion lists to sets for O(1) lookup
        self.excluded_extensions: Set[str] = set(ext.lower() for ext in EXCLUDED_EXTENSIONS)
        self.excluded_dirs: Set[str] = set(EXCLUDED_DIRS)

        # Cache for file path checks
        self._should_scan_cache: Dict[str, bool] = {}
    
    def should_scan_file(self, file_path: str) -> bool:
        """
        Determine if file should be scanned (with caching)

        Args:
            file_path: File path

        Returns:
            Whether file should be scanned
        """
        # Check cache first
        if file_path in self._should_scan_cache:
            return self._should_scan_cache[file_path]

        file_path_lower = file_path.lower()

        # Check file extension (optimized with set lookup)
        if any(file_path_lower.endswith(ext) for ext in self.excluded_extensions):
            self._should_scan_cache[file_path] = False
            return False

        # Check directory (optimized with set intersection)
        path_parts = set(file_path.split('/'))
        if path_parts & self.excluded_dirs:  # Set intersection is faster
            self._should_scan_cache[file_path] = False
            return False

        # Cache positive result
        self._should_scan_cache[file_path] = True
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
        line_stripped = line.strip()

        # Check if in comment (low confidence for comments)
        is_comment = (line_stripped.startswith('#') or
                     line_stripped.startswith('//') or
                     line_stripped.startswith('/*') or
                     line_stripped.startswith('*'))

        # High confidence patterns
        high_confidence_patterns = [
            # OpenAI keys
            (secret.startswith('sk-proj-'), len(secret) >= 48),
            (secret.startswith('sk-ant-'), len(secret) >= 40),
            # AWS keys
            (secret.startswith('AKIA'), len(secret) == 20),
            # GitHub tokens
            (secret.startswith('ghp_'), len(secret) == 40),
            (secret.startswith('gho_'), len(secret) == 40),
            (secret.startswith('ghs_'), len(secret) == 40),
            # Stripe keys
            (secret.startswith('sk_live_'), len(secret) >= 32),
            (secret.startswith('sk_test_'), len(secret) >= 32),
            # SendGrid
            (secret.startswith('SG.'), len(secret) >= 66),
            # Google AI
            (secret.startswith('AIza'), len(secret) == 39),
        ]

        # Check high confidence patterns
        for pattern_match, length_check in high_confidence_patterns:
            if pattern_match and length_check and not is_comment:
                return 'high'

        # Generic sk- keys (OpenAI-like)
        if secret.startswith('sk-') and len(secret) >= 40 and not is_comment:
            return 'high'

        # Medium confidence: Environment variable assignments with reasonable length
        if ('=' in line or ':' in line) and len(secret) >= 32 and not is_comment:
            return 'medium'

        # Medium confidence: JWT tokens
        if secret.count('.') == 2 and len(secret) >= 100:
            return 'medium'

        # Medium confidence: reasonable length API keys
        if len(secret) >= 40 and not is_comment:
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
