import os
import re
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')

SCAN_INTERVAL_HOURS = int(os.getenv('SCAN_INTERVAL_HOURS', 24))
OUTPUT_DIR = os.getenv('OUTPUT_DIR', './scan_reports')

CRITICAL_PATTERNS = [
	r'AKIA[0-9A-Z]{16}',
	r'AWS_ACCESS_KEY_ID[\s]*=[\s]*["\']?(AKIA[0-9A-Z]{16})["\']?',
	r'AWS_SECRET_ACCESS_KEY[\s]*=[\s]*["\']?([A-Za-z0-9/+=]{40})["\']?',
	r'aws_access_key_id[\s]*=[\s]*["\']?(AKIA[0-9A-Z]{16})["\']?',
	r'AWS_SESSION_TOKEN[\s]*=[\s]*["\']?([A-Za-z0-9/+=]{100,})["\']?',
	r'AZURE_CLIENT_SECRET[\s]*=[\s]*["\']?([a-zA-Z0-9~._-]{34,})["\']?',
	r'AZURE_CLIENT_ID[\s]*=[\s]*["\']?([a-f0-9-]{36})["\']?',
	r'AZURE_TENANT_ID[\s]*=[\s]*["\']?([a-f0-9-]{36})["\']?',
	r'AZURE_SUBSCRIPTION_ID[\s]*=[\s]*["\']?([a-f0-9-]{36})["\']?',
	r'"private_key"[\s]*:[\s]*"-----BEGIN PRIVATE KEY-----',
	r'GOOGLE_APPLICATION_CREDENTIALS[\s]*=[\s]*["\']?([^\s"\']+\.json)["\']?',
	r'-----BEGIN RSA PRIVATE KEY-----',
	r'-----BEGIN OPENSSH PRIVATE KEY-----',
	r'-----BEGIN PRIVATE KEY-----',
	r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
	r'-----BEGIN DSA PRIVATE KEY-----',
	r'-----BEGIN EC PRIVATE KEY-----',
	r'ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}',
	r'ssh-ed25519 AAAA[0-9A-Za-z+/]+[=]{0,3}',
	r'ecdsa-sha2-nistp256 AAAA[0-9A-Za-z+/]+[=]{0,3}',
	r'postgresql://[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_-]+',
	r'postgres://[a-zA-Z0-9_-]+:[^@\s]+@',
	r'mongodb(\+srv)?://[a-zA-Z0-9_-]+:[^@\s]+@',
	r'mysql://[a-zA-Z0-9_-]+:[^@\s]+@',
	r'redis://[^@\s]*:[^@\s]+@',
	r'MONGO_URI[\s]*=[\s]*["\']?(mongodb[^\s"\']+)["\']?',
	r'MONGODB_URI[\s]*=[\s]*["\']?(mongodb[^\s"\']+)["\']?',
	r'DATABASE_URL[\s]*=[\s]*["\']?([a-z]+://[^\s"\']+)["\']?',
	r'REDIS_URL[\s]*=[\s]*["\']?(redis://[^\s"\']+)["\']?',
]

HIGH_PRIORITY_PATTERNS = [
	r'sk-proj-[a-zA-Z0-9_-]{32,}',
	r'OPENAI_API_KEY[\s]*=[\s]*["\']?(sk-[a-zA-Z0-9_-]{32,})["\']?',
	r'openai_api_key[\s]*[:=][\s]*["\']?(sk-[a-zA-Z0-9_-]{32,})["\']?',
	r'OPENAI_KEY[\s]*=[\s]*["\']?(sk-[a-zA-Z0-9_-]{32,})["\']?',
	r'openaiApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{32,})["\']',
	r'sk_live_[a-zA-Z0-9]{24,}',
	r'pk_live_[a-zA-Z0-9]{24,}',
	r'sk_test_[a-zA-Z0-9]{24,}',
	r'STRIPE_SECRET_KEY[\s]*=[\s]*["\']?(sk_[a-z]+_[a-zA-Z0-9]{24,})["\']?',
	r'sk-ant-[a-zA-Z0-9_-]{32,}',
	r'ANTHROPIC_API_KEY[\s]*=[\s]*["\']?(sk-ant-[a-zA-Z0-9_-]{32,})["\']?',
	r'ANTHROPIC_AUTH_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'CLAUDE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'anthropic_api_key[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{32,})["\']',
	r'sk-[a-zA-Z0-9]{48,}',
	r'AIza[a-zA-Z0-9_-]{35}',
	r'GOOGLE_API_KEY[\s]*=[\s]*["\']?(AIza[a-zA-Z0-9_-]{35})["\']?',
	r'GEMINI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'GROQ_API_KEY[\s]*=[\s]*["\']?(gsk_[a-zA-Z0-9]{32,})["\']?',
	r'gsk_[a-zA-Z0-9]{32,}',
	r'MISTRAL_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'PERPLEXITY_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'REPLICATE_API_TOKEN[\s]*=[\s]*["\']?(r8_[a-zA-Z0-9]{40})["\']?',
	r'r8_[a-zA-Z0-9]{40}',
	r'STABILITY_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'TOGETHER_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{64,})["\']?',
	r'AI21_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'COHERE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'ANYSCALE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'FIREWORKS_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'AZURE_OPENAI_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'AZURE_OPENAI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'HUGGINGFACE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'HF_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'hf_[a-zA-Z0-9]{34,}',
	r'LANGCHAIN_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'LANGSMITH_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'WANDB_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9]{40})["\']?',
	r'ghp_[a-zA-Z0-9]{36}',
	r'gho_[a-zA-Z0-9]{36}',
	r'ghu_[a-zA-Z0-9]{36}',
	r'ghs_[a-zA-Z0-9]{36}',
	r'ghr_[a-zA-Z0-9]{36}',
	r'GITHUB_TOKEN[\s]*=[\s]*["\']?(gh[a-z]_[a-zA-Z0-9]{36})["\']?',
	r'glpat-[a-zA-Z0-9_-]{20}',
	r'GITLAB_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
	r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
	r'Bearer[\s]+[a-zA-Z0-9_\-\.=]{20,}',
	r'client_secret[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{32,})["\']',
	r'CLIENT_SECRET[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'OAUTH_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'ACCESS_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9._-]{32,})["\']?',
	r'REFRESH_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9._-]{32,})["\']?',
	r'SESSION_SECRET[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'SECRET_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'ENCRYPTION_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'NEXTAUTH_SECRET[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
]

MEDIUM_PRIORITY_PATTERNS = [
	r'SK[a-z0-9]{32}',
	r'TWILIO_AUTH_TOKEN[\s]*=[\s]*["\']?([a-f0-9]{32})["\']?',
	r'TWILIO_ACCOUNT_SID[\s]*=[\s]*["\']?(AC[a-f0-9]{32})["\']?',
	r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
	r'SENDGRID_API_KEY[\s]*=[\s]*["\']?(SG\.[a-zA-Z0-9_-]+)["\']?',
	r'MAILGUN_API_KEY[\s]*=[\s]*["\']?([a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})["\']?',
	r'xox[baprs]-[a-zA-Z0-9-]{10,}',
	r'SLACK_TOKEN[\s]*=[\s]*["\']?(xox[a-z]-[a-zA-Z0-9-]{10,})["\']?',
	r'SLACK_WEBHOOK[\s]*=[\s]*["\']?(https://hooks\.slack\.com/services/[^\s"\']+)["\']?',
	r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]{68}',
	r'DISCORD_WEBHOOK[\s]*=[\s]*["\']?(https://discord[^\s"\']+)["\']?',
	r'DISCORD_BOT_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{59,})["\']?',
	r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}',
	r'TELEGRAM_BOT_TOKEN[\s]*=[\s]*["\']?([0-9]{8,10}:[a-zA-Z0-9_-]{35})["\']?',
	r'VERCEL_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9]{24})["\']?',
	r'NETLIFY_ACCESS_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{40,})["\']?',
	r'CLOUDFLARE_API_KEY[\s]*=[\s]*["\']?([a-f0-9]{37})["\']?',
	r'CLOUDFLARE_API_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{40})["\']?',
	r'DATADOG_API_KEY[\s]*=[\s]*["\']?([a-f0-9]{32})["\']?',
	r'DATADOG_APP_KEY[\s]*=[\s]*["\']?([a-f0-9]{40})["\']?',
	r'FIREBASE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{39})["\']?',
	r'SUPABASE_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{40,})["\']?',
	r'SUPABASE_SERVICE_ROLE_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{40,})["\']?',
	r'SUPABASE_ANON_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{40,})["\']?',
	r'PLANETSCALE_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'npm_[a-zA-Z0-9]{36}',
	r'NPM_TOKEN[\s]*=[\s]*["\']?(npm_[a-zA-Z0-9]{36})["\']?',
	r'pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}',
	r'PINECONE_API_KEY[\s]*=[\s]*["\']?([a-f0-9-]{36})["\']?',
	r'WEAVIATE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'QDRANT_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'MILVUS_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'CHROMA_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'MODAL_TOKEN_ID[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
	r'MODAL_TOKEN_SECRET[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
	r'RUNPOD_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
	r'VOYAGE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
]

LOW_PRIORITY_PATTERNS = [
	r'AI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
	r'ai_api_key[\s]*[:=][\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
	r'CHAT_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
	r'chat_api_key[\s]*[:=][\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
	r'apiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
	r'ApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
	r'chatApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
	r'ChatApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
	r'API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{30,})["\']?',
	r'api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{30,})["\']?',
]

SENSITIVE_PATTERNS = (
	CRITICAL_PATTERNS +
	HIGH_PRIORITY_PATTERNS +
	MEDIUM_PRIORITY_PATTERNS +
	LOW_PRIORITY_PATTERNS
)

AI_SEARCH_KEYWORDS = [
	'openai api',
	'anthropic claude',
	'gpt api',
	'AI_API_KEY',
	'ANTHROPIC_AUTH_TOKEN',
	'chat_api_key',
	'apiKey',
	'sk-ant-',
	'sk-proj-',
	'OPENAI_API_KEY',
	'chatApiKey',
	'GEMINI_API_KEY',
	'GROQ_API_KEY',
	'MISTRAL_API_KEY',
	'LANGCHAIN_API_KEY',
	'HUGGINGFACE_API_KEY',
	'AWS_ACCESS_KEY_ID',
	'AZURE_OPENAI_KEY',
]

EXCLUDED_EXTENSIONS = [
	'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
	'.mp4', '.avi', '.mov', '.wmv',
	'.zip', '.tar', '.gz', '.rar',
	'.exe', '.dll', '.so', '.dylib',
	'.pdf', '.doc', '.docx',
]

EXCLUDED_DIRS = [
	'node_modules',
	'.git',
	'dist',
	'build',
	'__pycache__',
	'venv',
	'env',
]

MAX_REPOS_PER_SEARCH = 100
SEARCH_DELAY_SECONDS = 60

MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_FILE_SIZE_WARNING = 5 * 1024 * 1024

MAX_RECURSION_DEPTH = 10
ENABLE_CACHING = True
PARALLEL_WORKERS = 1

PRODUCTION_MODE = os.getenv('PRODUCTION_MODE', 'false').lower() == 'true'
STRICT_VALIDATION = os.getenv('STRICT_VALIDATION', 'true').lower() == 'true'
ENABLE_RETRY = os.getenv('ENABLE_RETRY', 'true').lower() == 'true'
MAX_RETRIES = int(os.getenv('MAX_RETRIES', 5))

PATTERN_SEVERITY = {
	'AKIA': 'critical',
	'sk-proj-': 'critical',
	'sk-ant-': 'critical',
	'-----BEGIN PRIVATE KEY-----': 'critical',
	'-----BEGIN RSA PRIVATE KEY-----': 'critical',
	'postgresql://': 'critical',
	'mongodb://': 'critical',
	'sk_live_': 'high',
	'ghp_': 'high',
	'AIza': 'high',
	'gsk_': 'high',
	'SG.': 'high',
	'sk_test_': 'medium',
	'xox': 'medium',
	'eyJ': 'medium',
	'api_key': 'low',
	'API_KEY': 'low',
}


def validate_configuration():
	errors = []
	warnings = []

	if not GITHUB_TOKEN:
		errors.append("GITHUB_TOKEN is not set. Please add it to your .env file.")
	elif len(GITHUB_TOKEN) < 20:
		warnings.append("GITHUB_TOKEN appears too short. Please verify it's correct.")

	invalid_patterns = []

	for idx, pattern in enumerate(SENSITIVE_PATTERNS):
		try:
			re.compile(pattern)
		except re.error as e:
			invalid_patterns.append(f"Pattern {idx}: {pattern[:50]}... - Error: {e}")

	if invalid_patterns:
		errors.append(f"Invalid regex patterns found:\n" + "\n".join(invalid_patterns))

	if MAX_FILE_SIZE < 1024 * 1024:
		warnings.append(f"MAX_FILE_SIZE ({MAX_FILE_SIZE}) is very small, may skip important files")

	if not os.path.exists(OUTPUT_DIR):
		try:
			os.makedirs(OUTPUT_DIR, exist_ok=True)

			warnings.append(f"Created output directory: {OUTPUT_DIR}")
		except Exception as e:
			errors.append(f"Cannot create output directory {OUTPUT_DIR}: {e}")

	if errors and STRICT_VALIDATION:
		error_msg = "\n❌ Configuration Validation Failed:\n" + "\n".join(f"  - {e}" for e in errors)

		if warnings:
			error_msg += "\n\n⚠️  Warnings:\n" + "\n".join(f"  - {w}" for w in warnings)

		raise ValueError(error_msg)

	if warnings and PRODUCTION_MODE:
		print("\n⚠️  Configuration Warnings:")

		for warning in warnings:
			print(f"  - {warning}")

	if errors and not STRICT_VALIDATION:
		print("\n⚠️  Configuration Errors:")

		for error in errors:
			print(f"  - {error}")

	return len(errors) == 0, len(warnings) == 0

try:
	if STRICT_VALIDATION:
		validate_configuration()
except ValueError as e:
	if PRODUCTION_MODE:
		raise
	print(f"\n⚠️  Configuration validation failed:\n{e}\n")