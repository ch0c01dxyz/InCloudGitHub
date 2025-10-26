"""
Configuration file - InCloud GitHub Scanner
Pattern Version: 2.1.0 (Production Ready)
Last Updated: 2025-10-27
"""
import os
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# GitHub configuration
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')

# Scan configuration
SCAN_INTERVAL_HOURS = int(os.getenv('SCAN_INTERVAL_HOURS', 24))
OUTPUT_DIR = os.getenv('OUTPUT_DIR', './scan_reports')

# ===== CRITICAL PATTERNS (Priority 1) =====
# Cloud Provider Credentials, Private Keys, Database Connections
CRITICAL_PATTERNS = [
    # === AWS Credentials ===
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
    r'AWS_ACCESS_KEY_ID[\s]*=[\s]*["\']?(AKIA[0-9A-Z]{16})["\']?',
    r'AWS_SECRET_ACCESS_KEY[\s]*=[\s]*["\']?([A-Za-z0-9/+=]{40})["\']?',
    r'aws_access_key_id[\s]*=[\s]*["\']?(AKIA[0-9A-Z]{16})["\']?',
    r'AWS_SESSION_TOKEN[\s]*=[\s]*["\']?([A-Za-z0-9/+=]{100,})["\']?',

    # === Azure Credentials ===
    r'AZURE_CLIENT_SECRET[\s]*=[\s]*["\']?([a-zA-Z0-9~._-]{34,})["\']?',
    r'AZURE_CLIENT_ID[\s]*=[\s]*["\']?([a-f0-9-]{36})["\']?',
    r'AZURE_TENANT_ID[\s]*=[\s]*["\']?([a-f0-9-]{36})["\']?',
    r'AZURE_SUBSCRIPTION_ID[\s]*=[\s]*["\']?([a-f0-9-]{36})["\']?',

    # === Google Cloud ===
    r'"private_key"[\s]*:[\s]*"-----BEGIN PRIVATE KEY-----',
    r'GOOGLE_APPLICATION_CREDENTIALS[\s]*=[\s]*["\']?([^\s"\']+\.json)["\']?',

    # === Private Keys & Certificates ===
    r'-----BEGIN RSA PRIVATE KEY-----',
    r'-----BEGIN OPENSSH PRIVATE KEY-----',
    r'-----BEGIN PRIVATE KEY-----',
    r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    r'-----BEGIN DSA PRIVATE KEY-----',
    r'-----BEGIN EC PRIVATE KEY-----',

    # === SSH Keys ===
    r'ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}',
    r'ssh-ed25519 AAAA[0-9A-Za-z+/]+[=]{0,3}',
    r'ecdsa-sha2-nistp256 AAAA[0-9A-Za-z+/]+[=]{0,3}',

    # === Database Connection Strings ===
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

# ===== HIGH PRIORITY PATTERNS (Priority 2) =====
# AI/ML Services, Authentication Tokens, OAuth
# NOTE: Specific patterns MUST come before generic patterns to avoid misidentification
HIGH_PRIORITY_PATTERNS = [
    # === OpenAI API Keys ===
    r'sk-proj-[a-zA-Z0-9_-]{32,}',  # Project keys (specific, check first)
    r'OPENAI_API_KEY[\s]*=[\s]*["\']?(sk-[a-zA-Z0-9_-]{32,})["\']?',
    r'openai_api_key[\s]*[:=][\s]*["\']?(sk-[a-zA-Z0-9_-]{32,})["\']?',
    r'OPENAI_KEY[\s]*=[\s]*["\']?(sk-[a-zA-Z0-9_-]{32,})["\']?',
    r'openaiApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{32,})["\']',

    # === Stripe Keys (MUST be before generic sk- pattern) ===
    r'sk_live_[a-zA-Z0-9]{24,}',
    r'pk_live_[a-zA-Z0-9]{24,}',
    r'sk_test_[a-zA-Z0-9]{24,}',
    r'STRIPE_SECRET_KEY[\s]*=[\s]*["\']?(sk_[a-z]+_[a-zA-Z0-9]{24,})["\']?',

    # === Anthropic/Claude API Keys ===
    r'sk-ant-[a-zA-Z0-9_-]{32,}',
    r'ANTHROPIC_API_KEY[\s]*=[\s]*["\']?(sk-ant-[a-zA-Z0-9_-]{32,})["\']?',
    r'ANTHROPIC_AUTH_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'CLAUDE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'anthropic_api_key[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{32,})["\']',

    # === Generic OpenAI Keys (AFTER specific patterns) ===
    r'sk-[a-zA-Z0-9]{48,}',  # OpenAI keys are typically 48+ chars (NOT 32 to avoid Stripe collision)

    # === Google AI/Gemini ===
    r'AIza[a-zA-Z0-9_-]{35}',
    r'GOOGLE_API_KEY[\s]*=[\s]*["\']?(AIza[a-zA-Z0-9_-]{35})["\']?',
    r'GEMINI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',

    # === Other AI Services ===
    r'GROQ_API_KEY[\s]*=[\s]*["\']?(gsk_[a-zA-Z0-9]{32,})["\']?',
    r'gsk_[a-zA-Z0-9]{32,}',  # Groq keys
    r'MISTRAL_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'PERPLEXITY_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'REPLICATE_API_TOKEN[\s]*=[\s]*["\']?(r8_[a-zA-Z0-9]{40})["\']?',
    r'r8_[a-zA-Z0-9]{40}',  # Replicate tokens
    r'STABILITY_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'TOGETHER_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{64,})["\']?',
    r'AI21_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'COHERE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'ANYSCALE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'FIREWORKS_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',

    # === Azure OpenAI ===
    r'AZURE_OPENAI_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'AZURE_OPENAI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',

    # === Hugging Face ===
    r'HUGGINGFACE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'HF_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'hf_[a-zA-Z0-9]{34,}',  # Hugging Face token format

    # === LangChain/LangSmith ===
    r'LANGCHAIN_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'LANGSMITH_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',

    # === Weights & Biases ===
    r'WANDB_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9]{40})["\']?',

    # === GitHub Tokens ===
    r'ghp_[a-zA-Z0-9]{36}',  # Personal Access Token
    r'gho_[a-zA-Z0-9]{36}',  # OAuth Access Token
    r'ghu_[a-zA-Z0-9]{36}',  # User-to-server Token
    r'ghs_[a-zA-Z0-9]{36}',  # Server-to-server Token
    r'ghr_[a-zA-Z0-9]{36}',  # Refresh Token
    r'GITHUB_TOKEN[\s]*=[\s]*["\']?(gh[a-z]_[a-zA-Z0-9]{36})["\']?',

    # === GitLab Tokens ===
    r'glpat-[a-zA-Z0-9_-]{20}',
    r'GITLAB_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # === JWT Tokens ===
    r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',

    # === Bearer Tokens ===
    r'Bearer[\s]+[a-zA-Z0-9_\-\.=]{20,}',

    # === OAuth Secrets ===
    r'client_secret[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{32,})["\']',
    r'CLIENT_SECRET[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'OAUTH_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'ACCESS_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9._-]{32,})["\']?',
    r'REFRESH_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9._-]{32,})["\']?',

    # === Session Secrets ===
    r'SESSION_SECRET[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'SECRET_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'ENCRYPTION_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'NEXTAUTH_SECRET[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
]

# ===== MEDIUM PRIORITY PATTERNS (Priority 3) =====
# SaaS APIs, Webhooks, Vector Databases
MEDIUM_PRIORITY_PATTERNS = [
    # === Twilio ===
    r'SK[a-z0-9]{32}',
    r'TWILIO_AUTH_TOKEN[\s]*=[\s]*["\']?([a-f0-9]{32})["\']?',
    r'TWILIO_ACCOUNT_SID[\s]*=[\s]*["\']?(AC[a-f0-9]{32})["\']?',

    # === SendGrid ===
    r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    r'SENDGRID_API_KEY[\s]*=[\s]*["\']?(SG\.[a-zA-Z0-9_-]+)["\']?',

    # === Mailgun ===
    r'MAILGUN_API_KEY[\s]*=[\s]*["\']?([a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})["\']?',

    # === Slack ===
    r'xox[baprs]-[a-zA-Z0-9-]{10,}',
    r'SLACK_TOKEN[\s]*=[\s]*["\']?(xox[a-z]-[a-zA-Z0-9-]{10,})["\']?',
    r'SLACK_WEBHOOK[\s]*=[\s]*["\']?(https://hooks\.slack\.com/services/[^\s"\']+)["\']?',

    # === Discord ===
    r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]{68}',
    r'DISCORD_WEBHOOK[\s]*=[\s]*["\']?(https://discord[^\s"\']+)["\']?',
    r'DISCORD_BOT_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{59,})["\']?',

    # === Telegram ===
    r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}',
    r'TELEGRAM_BOT_TOKEN[\s]*=[\s]*["\']?([0-9]{8,10}:[a-zA-Z0-9_-]{35})["\']?',

    # === Vercel ===
    r'VERCEL_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9]{24})["\']?',

    # === Netlify ===
    r'NETLIFY_ACCESS_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{40,})["\']?',

    # === Cloudflare ===
    r'CLOUDFLARE_API_KEY[\s]*=[\s]*["\']?([a-f0-9]{37})["\']?',
    r'CLOUDFLARE_API_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{40})["\']?',

    # === DataDog ===
    r'DATADOG_API_KEY[\s]*=[\s]*["\']?([a-f0-9]{32})["\']?',
    r'DATADOG_APP_KEY[\s]*=[\s]*["\']?([a-f0-9]{40})["\']?',

    # === Firebase ===
    r'FIREBASE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{39})["\']?',

    # === Supabase ===
    r'SUPABASE_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{40,})["\']?',
    r'SUPABASE_SERVICE_ROLE_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{40,})["\']?',
    r'SUPABASE_ANON_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{40,})["\']?',

    # === PlanetScale ===
    r'PLANETSCALE_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',

    # === npm Tokens ===
    r'npm_[a-zA-Z0-9]{36}',
    r'NPM_TOKEN[\s]*=[\s]*["\']?(npm_[a-zA-Z0-9]{36})["\']?',

    # === PyPI Tokens ===
    r'pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}',

    # === Vector Databases ===
    r'PINECONE_API_KEY[\s]*=[\s]*["\']?([a-f0-9-]{36})["\']?',
    r'WEAVIATE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'QDRANT_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'MILVUS_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
    r'CHROMA_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',

    # === Modal ===
    r'MODAL_TOKEN_ID[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'MODAL_TOKEN_SECRET[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # === RunPod ===
    r'RUNPOD_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',

    # === Voyage AI ===
    r'VOYAGE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{32,})["\']?',
]

# ===== LOW PRIORITY PATTERNS (Priority 4) =====
# Generic patterns for broader coverage
LOW_PRIORITY_PATTERNS = [
    # === Generic AI API Keys (Lower specificity) ===
    r'AI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'ai_api_key[\s]*[:=][\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'CHAT_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'chat_api_key[\s]*[:=][\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # === camelCase/PascalCase Generic Patterns ===
    r'apiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'ApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'chatApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'ChatApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',

    # === Very Generic Patterns (Catch-all) ===
    r'API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{30,})["\']?',
    r'api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{30,})["\']?',
]

# Combine all patterns
SENSITIVE_PATTERNS = (
    CRITICAL_PATTERNS +
    HIGH_PRIORITY_PATTERNS +
    MEDIUM_PRIORITY_PATTERNS +
    LOW_PRIORITY_PATTERNS
)

# GitHub search keywords - Updated for broader coverage
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

# File extensions to exclude
EXCLUDED_EXTENSIONS = [
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
    '.mp4', '.avi', '.mov', '.wmv',
    '.zip', '.tar', '.gz', '.rar',
    '.exe', '.dll', '.so', '.dylib',
    '.pdf', '.doc', '.docx',
]

# Directories to exclude
EXCLUDED_DIRS = [
    'node_modules',
    '.git',
    'dist',
    'build',
    '__pycache__',
    'venv',
    'env',
]

# GitHub API rate limit
MAX_REPOS_PER_SEARCH = 500
SEARCH_DELAY_SECONDS = 30

# File size limits (bytes) - Production safeguards
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB - Skip files larger than this
MAX_FILE_SIZE_WARNING = 5 * 1024 * 1024  # 5MB - Warn for files larger than this

# Performance settings
MAX_RECURSION_DEPTH = 10  # Maximum directory depth
ENABLE_CACHING = True  # Enable pattern and file caching
PARALLEL_WORKERS = 1  # Number of parallel workers (1 = sequential, increase for parallel scanning)

# Production mode settings
PRODUCTION_MODE = os.getenv('PRODUCTION_MODE', 'false').lower() == 'true'
STRICT_VALIDATION = os.getenv('STRICT_VALIDATION', 'true').lower() == 'true'
ENABLE_RETRY = os.getenv('ENABLE_RETRY', 'true').lower() == 'true'
MAX_RETRIES = int(os.getenv('MAX_RETRIES', 3))

# Pattern severity metadata for prioritization
PATTERN_SEVERITY = {
    # Critical - Immediate action required
    'AKIA': 'critical',  # AWS Access Keys
    'sk-proj-': 'critical',  # OpenAI Project Keys
    'sk-ant-': 'critical',  # Anthropic Keys
    '-----BEGIN PRIVATE KEY-----': 'critical',  # Private Keys
    '-----BEGIN RSA PRIVATE KEY-----': 'critical',
    'postgresql://': 'critical',  # Database connections
    'mongodb://': 'critical',

    # High - Address promptly
    'sk_live_': 'high',  # Stripe Live Keys
    'ghp_': 'high',  # GitHub PAT
    'AIza': 'high',  # Google AI Keys
    'gsk_': 'high',  # Groq Keys
    'SG.': 'high',  # SendGrid

    # Medium - Review and fix
    'sk_test_': 'medium',  # Stripe Test Keys
    'xox': 'medium',  # Slack tokens
    'eyJ': 'medium',  # JWT tokens

    # Low - Monitor
    'api_key': 'low',
    'API_KEY': 'low',
}


def validate_configuration():
    """
    Validate configuration settings at startup
    Raises ValueError if critical configuration is missing or invalid
    """
    errors = []
    warnings = []

    # Check GitHub Token
    if not GITHUB_TOKEN:
        errors.append("GITHUB_TOKEN is not set. Please add it to your .env file.")
    elif len(GITHUB_TOKEN) < 20:
        warnings.append("GITHUB_TOKEN appears too short. Please verify it's correct.")

    # Validate patterns
    invalid_patterns = []
    for idx, pattern in enumerate(SENSITIVE_PATTERNS):
        try:
            re.compile(pattern)
        except re.error as e:
            invalid_patterns.append(f"Pattern {idx}: {pattern[:50]}... - Error: {e}")

    if invalid_patterns:
        errors.append(f"Invalid regex patterns found:\n" + "\n".join(invalid_patterns))

    # Check file size limits
    if MAX_FILE_SIZE < 1024 * 1024:  # Less than 1MB
        warnings.append(f"MAX_FILE_SIZE ({MAX_FILE_SIZE}) is very small, may skip important files")

    # Check output directory
    if not os.path.exists(OUTPUT_DIR):
        try:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            warnings.append(f"Created output directory: {OUTPUT_DIR}")
        except Exception as e:
            errors.append(f"Cannot create output directory {OUTPUT_DIR}: {e}")

    # Report results
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
        print("\n⚠️  Configuration Errors (non-strict mode):")
        for error in errors:
            print(f"  - {error}")

    return len(errors) == 0, len(warnings) == 0


# Validate on module import
try:
    if STRICT_VALIDATION:
        validate_configuration()
except ValueError as e:
    # Re-raise in production mode
    if PRODUCTION_MODE:
        raise
    # Warn in development mode
    print(f"\n⚠️  Configuration validation failed (development mode):\n{e}\n")
