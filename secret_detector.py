import re
from typing import List, Dict, Optional, Set
from config import SENSITIVE_PATTERNS, EXCLUDED_EXTENSIONS, EXCLUDED_DIRS


class SecretDetector:
	def __init__(self, patterns: List[str] = SENSITIVE_PATTERNS):
		self.patterns = [re.compile(pattern) for pattern in patterns]
		self.excluded_extensions: Set[str] = set(ext.lower() for ext in EXCLUDED_EXTENSIONS)
		self.excluded_dirs: Set[str] = set(EXCLUDED_DIRS)
		self._should_scan_cache: Dict[str, bool] = {}


	def should_scan_file(self, file_path: str) -> bool:
		if file_path in self._should_scan_cache:
			return self._should_scan_cache[file_path]

		file_path_lower = file_path.lower()

		if any(file_path_lower.endswith(ext) for ext in self.excluded_extensions):
			self._should_scan_cache[file_path] = False

			return False

		path_parts = set(file_path.split('/'))

		if path_parts & self.excluded_dirs:  # Set intersection is faster
			self._should_scan_cache[file_path] = False

			return False

		self._should_scan_cache[file_path] = True

		return True


	def detect_secrets_in_text(self, text: str, file_path: str = "") -> List[Dict]:
		if not text:
			return []

		findings = []
		lines = text.split('\n')

		for line_num, line in enumerate(lines, 1):
			for pattern in self.patterns:
				matches = pattern.finditer(line)
				for match in matches:
					secret = match.group(0)

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
		line_lower = line.lower()

		example_keywords = [
			'example', 'sample', 'demo', 'test', 'placeholder',
			'your_api_key', 'your-api-key', 'xxx', 'yyy',
			'todo', 'replace', 'change_me', 'changeme'
		]

		for keyword in example_keywords:
			if keyword in line_lower:
				return True

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
		line_stripped = line.strip()

		is_comment = (line_stripped.startswith('#') or line_stripped.startswith('//') or line_stripped.startswith('/*') or line_stripped.startswith('*'))

		high_confidence_patterns = [
			(secret.startswith('sk-proj-'), len(secret) >= 48),
			(secret.startswith('sk-ant-'), len(secret) >= 40),
			(secret.startswith('AKIA'), len(secret) == 20),
			(secret.startswith('ghp_'), len(secret) == 40),
			(secret.startswith('gho_'), len(secret) == 40),
			(secret.startswith('ghs_'), len(secret) == 40),
			(secret.startswith('sk_live_'), len(secret) >= 32),
			(secret.startswith('sk_test_'), len(secret) >= 32),
			(secret.startswith('SG.'), len(secret) >= 66),
			(secret.startswith('AIza'), len(secret) == 39),
		]

		for pattern_match, length_check in high_confidence_patterns:
			if pattern_match and length_check and not is_comment:
				return 'high'

		if secret.startswith('sk-') and len(secret) >= 40 and not is_comment:
			return 'high'

		if ('=' in line or ':' in line) and len(secret) >= 32 and not is_comment:
			return 'medium'

		if secret.count('.') == 2 and len(secret) >= 100:
			return 'medium'

		if len(secret) >= 40 and not is_comment:
			return 'medium'

		return 'low'


	def filter_high_confidence(self, findings: List[Dict]) -> List[Dict]:
		return [f for f in findings if f['confidence'] in ['high', 'medium']]


	def deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
		seen = set()
		unique_findings = []

		for finding in findings:
			key = (finding['secret'], finding['file_path'])

			if key not in seen:
				seen.add(key)

				unique_findings.append(finding)

		return unique_findings