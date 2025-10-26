"""
Report generation module
"""
import os
from datetime import datetime
from typing import List, Dict
from config import OUTPUT_DIR


class ReportGenerator:
    """Scan report generator"""

    def __init__(self, output_dir: str = OUTPUT_DIR):
        """
        Initialize report generator

        Args:
            output_dir: Output directory
        """
        self.output_dir = output_dir
        self._ensure_output_dir()
    
    def _ensure_output_dir(self):
        """Ensure output directory exists"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def generate_report(self,
                       scan_results: List[Dict],
                       scan_start_time: datetime,
                       scan_type: str = "auto") -> str:
        """
        Generate scan report

        Args:
            scan_results: List of scan results
            scan_start_time: Scan start time
            scan_type: Scan type (user/org/auto)

        Returns:
            Report file path
        """
        report_time = datetime.now()
        timestamp = report_time.strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.txt"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            # Write report header
            f.write("╔" + "═" * 78 + "╗\n")
            f.write("║" + " " * 78 + "║\n")
            f.write("║" + "          🔒 InCloud GitHub Scanner - AI API Key Scan Report".ljust(78) + "║\n")
            f.write("║" + " " * 78 + "║\n")
            f.write("╚" + "═" * 78 + "╝\n\n")

            # Scan duration
            duration = (report_time - scan_start_time).total_seconds()
            duration_str = f"{int(duration // 60)}min {int(duration % 60)}s" if duration >= 60 else f"{int(duration)}s"

            # Write scan information
            f.write("📋 Scan Information\n")
            f.write("━" * 80 + "\n")
            f.write(f"  🎯 Scan Type:     {self._format_scan_type(scan_type)}\n")
            f.write(f"  ⏱️  Start Time:    {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  ⏱️  End Time:      {report_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  ⏳ Duration:      {duration_str}\n")
            
            # Quick overview
            high_count = sum(1 for r in scan_results if r.get('confidence') == 'high')
            medium_count = sum(1 for r in scan_results if r.get('confidence') == 'medium')
            repos_count = len(set(r.get('repo_url') for r in scan_results)) if scan_results else 0

            status_emoji = "🔴" if high_count > 0 else "🟡" if medium_count > 0 else "✅"
            f.write(f"  {status_emoji} Issues Found:  {len(scan_results)}")
            if len(scan_results) > 0:
                f.write(f" (🔴 {high_count} high, 🟡 {medium_count} medium)")
            f.write("\n")
            f.write(f"  📦 Repositories:  {repos_count}\n")
            f.write("\n")

            # If no issues found
            if not scan_results:
                f.write("✅ No sensitive information leakage detected!\n")
                f.write("\nScan completed, all clear.\n")
            else:
                # Group by repository
                results_by_repo = self._group_by_repo(scan_results)

                # Write findings for each repository
                for repo_url, findings in results_by_repo.items():
                    self._write_repo_findings(f, repo_url, findings)

                # Write statistics
                self._write_statistics(f, scan_results)

            # Write report footer
            f.write("\n╔" + "═" * 78 + "╗\n")
            f.write("║" + " " * 78 + "║\n")
            f.write("║" + "                 ✅ Report Generated - Please Address Issues Promptly".ljust(78) + "║\n")
            f.write("║" + " " * 78 + "║\n")
            f.write("║" + f"  Generated: {report_time.strftime('%Y-%m-%d %H:%M:%S')}".ljust(78) + "║\n")
            f.write("║" + f"  Location: {filepath}".ljust(78) + "║\n")
            f.write("║" + " " * 78 + "║\n")
            f.write("╚" + "═" * 78 + "╝\n")
        
        return filepath
    
    def _group_by_repo(self, scan_results: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Group scan results by repository

        Args:
            scan_results: List of scan results

        Returns:
            Dictionary of results grouped by repository
        """
        grouped = {}
        for result in scan_results:
            repo_url = result.get('repo_url', 'Unknown')
            if repo_url not in grouped:
                grouped[repo_url] = []
            grouped[repo_url].append(result)
        return grouped
    
    def _format_scan_type(self, scan_type: str) -> str:
        """Format scan type display"""
        type_map = {
            'auto:ai-projects': '🤖 Auto Search AI Projects',
            'user': '👤 Specified User Scan',
            'org': '🏢 Specified Organization Scan',
            'single': '📦 Single Repository Scan',
        }
        for key, value in type_map.items():
            if scan_type.startswith(key):
                return value
        return scan_type
    
    def _write_repo_findings(self, f, repo_url: str, findings: List[Dict]):
        """
        Write findings for a single repository

        Args:
            f: File object
            repo_url: Repository URL
            findings: List of findings for this repository
        """
        # Extract repository name
        repo_name = repo_url.split('/')[-2:] if '/' in repo_url else [repo_url]
        repo_name = '/'.join(repo_name) if len(repo_name) == 2 else repo_url

        # Calculate risk level
        high_count = sum(1 for f in findings if f.get('confidence') == 'high')
        risk_level = "🔴 HIGH" if high_count > 0 else "🟡 MEDIUM"

        f.write("\n╭" + "─" * 78 + "╮\n")
        f.write(f"│ 📦 Repository: {repo_name}".ljust(80) + "│\n")
        f.write(f"│ 🔗 URL: {repo_url}".ljust(80) + "│\n")
        f.write(f"│ {risk_level}  Found {len(findings)} issue(s)".ljust(80) + "│\n")
        f.write("╰" + "─" * 78 + "╯\n\n")
        
        for idx, finding in enumerate(findings, 1):
            # Confidence marker
            confidence = finding.get('confidence', 'unknown')
            confidence_info = {
                'high': ('🔴', 'HIGH', 'Immediate action required'),
                'medium': ('🟡', 'MEDIUM', 'Address soon'),
                'low': ('🟢', 'LOW', 'Recommended to fix')
            }.get(confidence, ('⚪', 'UNKNOWN', 'Needs verification'))

            f.write(f"  ┌─ Issue #{idx} {'─' * 66}\n")
            f.write(f"  │\n")
            f.write(f"  │ {confidence_info[0]} Risk Level: {confidence_info[1]} - {confidence_info[2]}\n")
            f.write(f"  │\n")

            # File information
            file_path = finding.get('file_path', 'N/A')
            f.write(f"  │ 📄 File Path: {file_path}\n")

            # Line number
            if finding.get('line_number'):
                f.write(f"  │ 📍 Line: {finding['line_number']}\n")

            # Found secret
            secret = finding.get('secret', '')
            masked_secret = self._mask_secret(secret)
            secret_type = self._identify_secret_type(secret)
            f.write(f"  │\n")
            f.write(f"  │ 🔑 Secret Type: {secret_type}\n")
            f.write(f"  │ 🔐 Secret Value: {masked_secret}\n")

            # Match source (detection rule)
            if finding.get('pattern'):
                pattern_desc = self._explain_pattern(finding['pattern'])
                f.write(f"  │ 🎯 Match Rule: {pattern_desc}\n")

            # Code context
            if finding.get('line_content'):
                line_content = finding['line_content'].strip()[:80]
                f.write(f"  │\n")
                f.write(f"  │ 💻 Code Snippet:\n")
                f.write(f"  │    {line_content}\n")

            # Scan time
            if finding.get('scan_time'):
                f.write(f"  │\n")
                f.write(f"  │ 🕐 Detected: {finding['scan_time']}\n")
            
            f.write(f"  │\n")
            f.write(f"  └{'─' * 74}\n\n")
        
        f.write("\n")
    
    def _identify_secret_type(self, secret: str) -> str:
        """
        Identify secret type

        Args:
            secret: Secret string

        Returns:
            Secret type description
        """
        if secret.startswith('sk-proj-'):
            return '🤖 OpenAI API Key (Project)'
        elif secret.startswith('sk-ant-'):
            return '🤖 Anthropic API Key (Claude)'
        elif secret.startswith('sk-'):
            return '🤖 OpenAI API Key'
        elif secret.startswith('AIza'):
            return '🔍 Google AI API Key (Gemini)'
        elif 'openai' in secret.lower():
            return '🤖 OpenAI-related Key'
        elif 'anthropic' in secret.lower() or 'claude' in secret.lower():
            return '🤖 Anthropic-related Key'
        elif 'api_key' in secret.lower() or 'apikey' in secret.lower():
            return '🔑 Generic API Key'
        else:
            return '🔐 Unknown Key Type'
    
    def _explain_pattern(self, pattern: str) -> str:
        """
        Convert regex pattern to readable description

        Args:
            pattern: Regular expression string

        Returns:
            Readable pattern description
        """
        # Specific key formats
        if 'sk-proj-' in pattern:
            return '📌 OpenAI Project API Key format (sk-proj-...)'
        elif 'sk-ant-' in pattern:
            return '📌 Anthropic Claude API Key format (sk-ant-...)'
        elif pattern == r'sk-[a-zA-Z0-9]{32,}':
            return '📌 OpenAI API Key format (sk-...)'
        elif 'AIza' in pattern:
            return '📌 Google AI/Gemini API Key format (AIza...)'

        # Environment variable patterns
        elif 'OPENAI_API_KEY' in pattern:
            return '📌 OPENAI_API_KEY environment variable assignment'
        elif 'AI_API_KEY' in pattern and 'OPENAI' not in pattern:
            return '📌 AI_API_KEY environment variable assignment'
        elif 'ANTHROPIC_AUTH_TOKEN' in pattern:
            return '📌 ANTHROPIC_AUTH_TOKEN environment variable assignment'
        elif 'ANTHROPIC_API_KEY' in pattern:
            return '📌 ANTHROPIC_API_KEY environment variable assignment'
        elif 'CLAUDE_API_KEY' in pattern:
            return '📌 CLAUDE_API_KEY environment variable assignment'
        elif 'CHAT_API_KEY' in pattern:
            return '📌 CHAT_API_KEY environment variable assignment'
        elif 'GOOGLE_API_KEY' in pattern:
            return '📌 GOOGLE_API_KEY environment variable assignment'
        elif 'GEMINI_API_KEY' in pattern:
            return '📌 GEMINI_API_KEY environment variable assignment'
        elif 'AZURE_OPENAI' in pattern:
            return '📌 Azure OpenAI environment variable assignment'
        elif 'HUGGINGFACE_API_KEY' in pattern:
            return '📌 HUGGINGFACE_API_KEY environment variable assignment'
        elif 'HF_TOKEN' in pattern:
            return '📌 HF_TOKEN environment variable assignment'
        elif 'COHERE_API_KEY' in pattern:
            return '📌 COHERE_API_KEY environment variable assignment'
        elif 'API_KEY' in pattern and 'api_key' in pattern:
            return '📌 API_KEY/api_key environment variable assignment'

        # camelCase/PascalCase patterns
        elif 'apiKey' in pattern and 'chat' not in pattern.lower() and 'openai' not in pattern.lower():
            return '📌 apiKey object property/variable assignment'
        elif 'chatApiKey' in pattern:
            return '📌 chatApiKey object property/variable assignment'
        elif 'openaiApiKey' in pattern or 'openAIKey' in pattern:
            return '📌 openaiApiKey/openAIKey object property/variable assignment'
        elif 'anthropicApiKey' in pattern:
            return '📌 anthropicApiKey object property/variable assignment'

        # Generic patterns
        elif 'api_key' in pattern.lower():
            return '📌 Generic api_key variable assignment'

        # Default
        else:
            return f'📌 Regex pattern: {pattern[:50]}...' if len(pattern) > 50 else f'📌 Regex pattern: {pattern}'
    
    def _mask_secret(self, secret: str) -> str:
        """
        Partially mask secret

        Args:
            secret: Original secret

        Returns:
            Masked secret
        """
        if len(secret) <= 8:
            return "*" * len(secret)

        # Show first 4 and last 4 characters
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"
    
    def _write_statistics(self, f, scan_results: List[Dict]):
        """
        Write statistics

        Args:
            f: File object
            scan_results: List of scan results
        """
        f.write("\n╔" + "═" * 78 + "╗\n")
        f.write("║" + " " * 78 + "║\n")
        f.write("║" + "                           📊 Statistics and Analysis".ljust(78) + "║\n")
        f.write("║" + " " * 78 + "║\n")
        f.write("╚" + "═" * 78 + "╝\n\n")

        # Statistics by confidence level
        confidence_counts = {
            'high': 0,
            'medium': 0,
            'low': 0
        }

        for result in scan_results:
            confidence = result.get('confidence', 'low')
            confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1

        f.write("┌─ Risk Level Distribution\n")
        f.write("│\n")
        total = len(scan_results)
        high_pct = (confidence_counts['high'] / total * 100) if total > 0 else 0
        medium_pct = (confidence_counts['medium'] / total * 100) if total > 0 else 0
        low_pct = (confidence_counts['low'] / total * 100) if total > 0 else 0

        f.write(f"│  🔴 High Risk:   {confidence_counts['high']:3d} ({high_pct:5.1f}%)")
        f.write(f"  {'█' * int(high_pct / 5)}\n")
        f.write(f"│  🟡 Medium Risk: {confidence_counts['medium']:3d} ({medium_pct:5.1f}%)")
        f.write(f"  {'█' * int(medium_pct / 5)}\n")
        f.write(f"│  🟢 Low Risk:    {confidence_counts['low']:3d} ({low_pct:5.1f}%)")
        f.write(f"  {'█' * int(low_pct / 5)}\n")
        f.write("│\n")
        f.write(f"│  📊 Total: {total} potential issues\n")
        f.write("└" + "─" * 78 + "\n\n")

        # Statistics by repository
        repos = set(r.get('repo_url') for r in scan_results)
        f.write("┌─ Impact Scope\n")
        f.write("│\n")
        f.write(f"│  📦 Affected Repositories: {len(repos)}\n")
        f.write(f"│  📄 Affected Files: {len(set(r.get('file_path') for r in scan_results))}\n")
        f.write("│\n")
        f.write("└" + "─" * 78 + "\n\n")

        # Statistics by secret type
        secret_types = {}
        for result in scan_results:
            secret = result.get('secret', '')
            stype = self._identify_secret_type(secret)
            secret_types[stype] = secret_types.get(stype, 0) + 1

        if secret_types:
            f.write("┌─ Secret Type Distribution\n")
            f.write("│\n")
            for stype, count in sorted(secret_types.items(), key=lambda x: x[1], reverse=True):
                f.write(f"│  {stype}: {count}\n")
            f.write("│\n")
            f.write("└" + "─" * 78 + "\n\n")

        # Security recommendations
        f.write("╔" + "═" * 78 + "╗\n")
        f.write("║" + "                           🛡️  Security Recommendations".ljust(78) + "║\n")
        f.write("╚" + "═" * 78 + "╝\n\n")

        f.write("⚠️  Immediate Actions (for high-risk issues):\n")
        f.write("  1. 🚨 Immediately revoke/rotate all leaked API keys\n")
        f.write("  2. 🔍 Check API usage logs to confirm if they were abused\n")
        f.write("  3. 🗑️  Completely remove sensitive info from Git history (use git-filter-repo)\n")
        f.write("  4. 📧 Notify relevant team members\n\n")

        f.write("🔒 Long-term Protection Measures:\n")
        f.write("  1. 📝 Use environment variables or key management services (e.g., AWS Secrets Manager)\n")
        f.write("  2. 🚫 Add .env, config.json and other sensitive files to .gitignore\n")
        f.write("  3. 🪝 Configure pre-commit hooks to prevent sensitive info commits\n")
        f.write("  4. 🔄 Regularly rotate API keys\n")
        f.write("  5. 👥 Conduct security training for the team\n")
        f.write("  6. 📊 Regularly run this scanning tool for audits\n\n")

        f.write("📚 Reference Resources:\n")
        f.write("  • GitHub Secret Scanning: https://docs.github.com/en/code-security/secret-scanning\n")
        f.write("  • Git History Cleanup: https://github.com/newren/git-filter-repo\n")
        f.write("  • Best Practices: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html\n")
    
    def generate_summary(self, report_path: str, total_findings: int) -> str:
        """
        Generate brief summary

        Args:
            report_path: Report file path
            total_findings: Total number of findings

        Returns:
            Summary text
        """
        if total_findings > 0:
            summary = f"""
{'━' * 80}
✅ Scan Completed!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 Report saved to: {report_path}

⚠️  Found {total_findings} potential security issue(s)!

🔴 Immediate Recommendations:
   1. Review detailed report
   2. Revoke leaked API keys
   3. Check for abuse
   4. Remove sensitive info from Git history

{'━' * 80}
"""
        else:
            summary = f"""
{'━' * 80}
✅ Scan Completed!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 Report saved to: {report_path}

🎉 No obvious API key leaks detected!

💡 Recommendations:
   • Continue maintaining good security practices
   • Run periodic scans
   • Conduct security training for the team

{'━' * 80}
"""
        return summary
