"""
Configuration file - InCloud GitHub Scanner
"""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# GitHub configuration
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')

# Scan configuration
SCAN_INTERVAL_HOURS = int(os.getenv('SCAN_INTERVAL_HOURS', 24))
OUTPUT_DIR = os.getenv('OUTPUT_DIR', './scan_reports')

# AI-related sensitive information patterns
SENSITIVE_PATTERNS = [
    # OpenAI API key format
    r'sk-[a-zA-Z0-9]{32,}',
    r'sk-proj-[a-zA-Z0-9_-]{32,}',

    # Anthropic API key format
    r'sk-ant-[a-zA-Z0-9_-]{32,}',

    # Google AI (Gemini) API key format
    r'AIza[a-zA-Z0-9_-]{35}',

    # ===== Common environment variable name patterns (snake_case) =====
    # AI API Keys
    r'AI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'ai_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # OpenAI
    r'OPENAI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'openai_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'OPENAI_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # Anthropic
    r'ANTHROPIC_AUTH_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'ANTHROPIC_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'anthropic_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # Claude
    r'CLAUDE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'claude_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # Generic API Key
    r'API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # Chat API Key
    r'CHAT_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'chat_api_key[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # ===== camelCase and PascalCase patterns =====
    # Object property assignment: apiKey: "value"
    r'apiKey[\s]*:[\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'ApiKey[\s]*:[\s]*["\']([a-zA-Z0-9_-]{20,})["\']',

    # Variable assignment: apiKey = "value"
    r'apiKey[\s]*=[\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'ApiKey[\s]*=[\s]*["\']([a-zA-Z0-9_-]{20,})["\']',

    # chatApiKey patterns
    r'chatApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'ChatApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',

    # openaiApiKey patterns
    r'openaiApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'OpenaiApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'openAIKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',

    # anthropicApiKey patterns
    r'anthropicApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
    r'AnthropicApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',

    # ===== Other AI services =====
    # Google AI / Gemini
    r'GOOGLE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'GEMINI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # Hugging Face
    r'HUGGINGFACE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'HF_TOKEN[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # Cohere
    r'COHERE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',

    # Azure OpenAI
    r'AZURE_OPENAI_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'AZURE_OPENAI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?',
]

# GitHub search keywords
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
