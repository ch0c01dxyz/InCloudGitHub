"""
Main scanner module - Integrates all functionality
"""
import time
from datetime import datetime
from typing import List, Dict, Optional
from github_scanner import GitHubScanner
from secret_detector import SecretDetector
from report_generator import ReportGenerator
from scan_history import ScanHistory


class CloudScanner:
    """Cloud Scanner - Main scanning logic"""

    def __init__(self, github_token: str, skip_scanned: bool = True, timeout_minutes: int = 50):
        """
        Initialize scanner

        Args:
            github_token: GitHub Personal Access Token
            skip_scanned: Whether to skip already scanned repositories (default: True)
            timeout_minutes: Scan timeout in minutes, default 50 minutes
        """
        self.github_scanner = GitHubScanner(github_token)
        self.secret_detector = SecretDetector()
        self.report_generator = ReportGenerator()
        self.scan_history = ScanHistory()
        self.skip_scanned = skip_scanned
        self.timeout_seconds = timeout_minutes * 60
        self.scan_start_time = None
    
    def _is_timeout(self) -> bool:
        """Check if timed out"""
        if self.scan_start_time is None:
            return False
        elapsed = time.time() - self.scan_start_time
        return elapsed >= self.timeout_seconds

    def _check_timeout(self, current_idx: int, total_repos: int) -> bool:
        """
        Check if timed out, print info and return True if timeout

        Args:
            current_idx: Current repository index being scanned
            total_repos: Total number of repositories

        Returns:
            Whether timed out
        """
        if self._is_timeout():
            elapsed_minutes = (time.time() - self.scan_start_time) / 60
            print(f"\n⏰ Scan timeout (ran for {elapsed_minutes:.1f} minutes)")
            print(f"✅ Completed {current_idx}/{total_repos} repositories")
            print(f"💾 Saved previous scan data, remaining {total_repos - current_idx} repositories will be processed next time")
            return True
        return False
    
    def scan_user(self, username: str) -> str:
        """
        Scan all public repositories of specified user

        Args:
            username: GitHub username

        Returns:
            Report file path
        """
        print(f"🚀 Starting scan for user: {username}")
        scan_start_time = datetime.now()
        self.scan_start_time = time.time()  # Start timing

        # Get all user repositories
        repos = self.github_scanner.get_user_repos(username)
        print(f"📦 Found {len(repos)} public repositories")

        # Filter already scanned repositories
        repos_to_scan, skipped_count = self._filter_scanned_repos(repos)
        if skipped_count > 0:
            print(f"⏭️  Skipped {skipped_count} already scanned repositories")
            print(f"📦 Need to scan {len(repos_to_scan)} new repositories")

        # Scan all repositories
        all_findings = []
        for idx, repo in enumerate(repos_to_scan, 1):
            # Check timeout
            if self._check_timeout(idx - 1, len(repos_to_scan)):
                break

            print(f"🔍 [{idx}/{len(repos_to_scan)}] Scanning repository: {repo['full_name']}")
            findings = self._scan_repository(repo, scan_type=f"user:{username}")
            all_findings.extend(findings)

        # Generate report
        print(f"\n📝 Generating report...")
        report_path = self.report_generator.generate_report(
            all_findings,
            scan_start_time,
            scan_type=f"user:{username}"
        )

        # Print summary
        summary = self.report_generator.generate_summary(report_path, len(all_findings))
        print(summary)

        return report_path
    
    def scan_organization(self, org_name: str) -> str:
        """
        Scan all public repositories of specified organization

        Args:
            org_name: GitHub organization name

        Returns:
            Report file path
        """
        print(f"🚀 Starting scan for organization: {org_name}")
        scan_start_time = datetime.now()
        self.scan_start_time = time.time()  # Start timing

        # Get all organization repositories
        repos = self.github_scanner.get_org_repos(org_name)
        print(f"📦 Found {len(repos)} public repositories")

        # Filter already scanned repositories
        repos_to_scan, skipped_count = self._filter_scanned_repos(repos)
        if skipped_count > 0:
            print(f"⏭️  Skipped {skipped_count} already scanned repositories")
            print(f"📦 Need to scan {len(repos_to_scan)} new repositories")

        # Scan all repositories
        all_findings = []
        for idx, repo in enumerate(repos_to_scan, 1):
            # Check timeout
            if self._check_timeout(idx - 1, len(repos_to_scan)):
                break

            print(f"🔍 [{idx}/{len(repos_to_scan)}] Scanning repository: {repo['full_name']}")
            findings = self._scan_repository(repo, scan_type=f"org:{org_name}")
            all_findings.extend(findings)

        # Generate report
        print(f"\n📝 Generating report...")
        report_path = self.report_generator.generate_report(
            all_findings,
            scan_start_time,
            scan_type=f"org:{org_name}"
        )

        # Print summary
        summary = self.report_generator.generate_summary(report_path, len(all_findings))
        print(summary)

        return report_path
    
    def scan_ai_projects(self, max_repos: int = 50) -> str:
        """
        Auto search and scan AI-related projects

        Args:
            max_repos: Maximum number of repositories to scan

        Returns:
            Report file path
        """
        print(f"🚀 Starting auto search for AI-related projects")
        print(f"🎯 Target: Find and scan {max_repos} unscanned repositories")
        scan_start_time = datetime.now()
        self.scan_start_time = time.time()  # Start timing

        # Define filter function: check if repository is already scanned
        def is_scanned(repo_full_name: str) -> bool:
            return self.scan_history.is_scanned(repo_full_name)

        # Search repositories, filter already scanned ones in real-time
        # Search process will automatically skip scanned repositories until enough new ones are found
        repos_to_scan = self.github_scanner.search_ai_repos(
            max_repos=max_repos,
            skip_filter=is_scanned if self.skip_scanned else None
        )

        print(f"📦 Found {len(repos_to_scan)} repositories to scan")

        # Scan all repositories
        all_findings = []
        for idx, repo in enumerate(repos_to_scan, 1):
            # Check timeout
            if self._check_timeout(idx - 1, len(repos_to_scan)):
                break

            print(f"🔍 [{idx}/{len(repos_to_scan)}] Scanning repository: {repo['full_name']}")
            findings = self._scan_repository(repo, scan_type="auto:ai-projects")
            all_findings.extend(findings)

        # Generate report
        print(f"\n📝 Generating report...")
        report_path = self.report_generator.generate_report(
            all_findings,
            scan_start_time,
            scan_type="auto:ai-projects"
        )

        # Print summary
        summary = self.report_generator.generate_summary(report_path, len(all_findings))
        print(summary)

        return report_path
    
    def scan_single_repo(self, repo_full_name: str) -> str:
        """
        Scan a single repository

        Args:
            repo_full_name: Repository full name (owner/repo)

        Returns:
            Report file path
        """
        print(f"🚀 Starting scan for repository: {repo_full_name}")
        scan_start_time = datetime.now()

        # Build repository information
        repo_info = {
            'full_name': repo_full_name,
            'url': f"https://github.com/{repo_full_name}",
            'clone_url': f"https://github.com/{repo_full_name}.git",
        }

        # Scan repository
        findings = self._scan_repository(repo_info)

        # Generate report
        print(f"\n📝 Generating report...")
        report_path = self.report_generator.generate_report(
            findings,
            scan_start_time,
            scan_type=f"single:{repo_full_name}"
        )

        # Print summary
        summary = self.report_generator.generate_summary(report_path, len(findings))
        print(summary)

        return report_path
    
    def _filter_scanned_repos(self, repos: List[Dict]) -> tuple:
        """
        Filter already scanned repositories

        Args:
            repos: Repository list

        Returns:
            (List of repositories to scan, number of skipped repositories)
        """
        if not self.skip_scanned:
            return repos, 0

        repos_to_scan = []
        skipped_count = 0

        for repo in repos:
            repo_name = repo.get('full_name', '')
            if self.scan_history.is_scanned(repo_name):
                skipped_count += 1
            else:
                repos_to_scan.append(repo)

        return repos_to_scan, skipped_count

    def _scan_repository(self, repo: Dict, scan_type: str = "unknown") -> List[Dict]:
        """
        Scan a single repository

        Args:
            repo: Repository information dictionary
            scan_type: Scan type

        Returns:
            List of found sensitive information
        """
        findings = []
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        repo_name = repo.get('full_name', 'unknown')
        
        try:
            # Get repository file list
            files = self.github_scanner.get_repo_files(repo['full_name'])

            # If getting file list fails (e.g., 403 error), return directly
            if not files:
                # Record to scan history to avoid rescanning
                self.scan_history.mark_as_scanned(repo_name, 0, f"{scan_type}:no-access")
                return findings

            # Scan each file
            for file_info in files:
                # Check if this file should be scanned
                if not self.secret_detector.should_scan_file(file_info['path']):
                    continue

                # Get file content
                content = self.github_scanner.get_file_content(
                    repo['full_name'],
                    file_info['path']
                )

                if content:
                    # Detect sensitive information
                    secrets = self.secret_detector.detect_secrets_in_text(
                        content,
                        file_info['path']
                    )

                    # Add repository information
                    for secret in secrets:
                        secret['repo_url'] = repo.get('url', f"https://github.com/{repo_name}")
                        secret['repo_name'] = repo['full_name']
                        secret['scan_time'] = scan_time
                        findings.append(secret)

            # Deduplicate and filter
            findings = self.secret_detector.deduplicate_findings(findings)
            findings = self.secret_detector.filter_high_confidence(findings)

            if findings:
                print(f"  ⚠️  Found {len(findings)} potential issue(s)")
            else:
                print(f"  ✅ No obvious issues found")

            # Record to scan history
            self.scan_history.mark_as_scanned(repo_name, len(findings), scan_type)

        except Exception as e:
            error_msg = str(e)
            # Handle 403 errors silently
            if "403" in error_msg or "Forbidden" in error_msg:
                print(f"  ⏭️  Skipping: No access")
                self.scan_history.mark_as_scanned(repo_name, 0, f"{scan_type}:forbidden")
            else:
                print(f"  ❌ Scan failed: {e}")
                # Record even if scan fails to avoid repeated attempts
                self.scan_history.mark_as_scanned(repo_name, 0, f"{scan_type}:failed")

        return findings
