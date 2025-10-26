import time
from datetime import datetime
from typing import List, Dict, Optional


try:
	from tqdm import tqdm
	TQDM_AVAILABLE = True
except ImportError:
	TQDM_AVAILABLE = False
	def tqdm(iterable, *args, **kwargs):
		return iterable


from github_scanner import GitHubScanner
from secret_detector import SecretDetector
from report_generator import ReportGenerator
from scan_history import ScanHistory
from config import MAX_FILE_SIZE, MAX_FILE_SIZE_WARNING, PRODUCTION_MODE


class CloudScanner:
	def __init__(self, github_token: str, skip_scanned: bool = True, timeout_minutes: int = 50, output_dir: str = None):
		self.github_scanner = GitHubScanner(github_token)
		self.secret_detector = SecretDetector()
		self.report_generator = ReportGenerator(output_dir) if output_dir else ReportGenerator()
		self.scan_history = ScanHistory()
		self.skip_scanned = skip_scanned
		self.timeout_seconds = timeout_minutes * 60
		self.scan_start_time = None


	def _is_timeout(self) -> bool:
		if self.scan_start_time is None:
			return False
		elapsed = time.time() - self.scan_start_time

		return elapsed >= self.timeout_seconds


	def _check_timeout(self, current_idx: int, total_repos: int) -> bool:
		if self._is_timeout():
			elapsed_minutes = (time.time() - self.scan_start_time) / 60

			print(f"\n⏰ Scan timeout (ran for {elapsed_minutes:.1f} minutes)")
			print(f"✅ Completed {current_idx}/{total_repos} repositories")
			print(f"💾 Saved previous scan data, remaining {total_repos - current_idx} repositories will be processed next time")

			return True
		return False


	def scan_user(self, username: str, return_data: bool = False):
		print(f"🚀 Starting scan for user: {username}")

		scan_start_time = datetime.now()

		self.scan_start_time = time.time()  # Start timing

		repos = self.github_scanner.get_user_repos(username)

		print(f"📦 Found {len(repos)} public repositories")

		repos_to_scan, skipped_count = self._filter_scanned_repos(repos)

		if skipped_count > 0:
			print(f"⏭️  Skipped {skipped_count} already scanned repositories")
			print(f"📦 Need to scan {len(repos_to_scan)} new repositories")

		all_findings = []

		with tqdm(total=len(repos_to_scan), desc="Scanning repositories", unit="repo", ncols=100) as pbar:
			for idx, repo in enumerate(repos_to_scan, 1):
				if self._check_timeout(idx - 1, len(repos_to_scan)):
					break

				pbar.set_description(f"Scanning {repo['full_name'][:40]}")

				findings = self._scan_repository(repo, scan_type=f"user:{username}")

				all_findings.extend(findings)

				pbar.update(1)

		print(f"\n📝 Generating report...")

		report_path = self.report_generator.generate_report(
			all_findings,
			scan_start_time,
			scan_type=f"user:{username}"
		)

		summary = self.report_generator.generate_summary(report_path, len(all_findings))

		print(summary)

		if return_data:
			return report_path, {
				'findings': all_findings,
				'start_time': scan_start_time,
				'scan_type': f"user:{username}"
			}
		return report_path


	def scan_organization(self, org_name: str, return_data: bool = False):
		print(f"🚀 Starting scan for organization: {org_name}")

		scan_start_time = datetime.now()

		self.scan_start_time = time.time()

		repos = self.github_scanner.get_org_repos(org_name)

		print(f"📦 Found {len(repos)} public repositories")

		repos_to_scan, skipped_count = self._filter_scanned_repos(repos)

		if skipped_count > 0:
			print(f"⏭️  Skipped {skipped_count} already scanned repositories")
			print(f"📦 Need to scan {len(repos_to_scan)} new repositories")

		all_findings = []

		with tqdm(total=len(repos_to_scan), desc="Scanning repositories", unit="repo", ncols=100) as pbar:
			for idx, repo in enumerate(repos_to_scan, 1):
				if self._check_timeout(idx - 1, len(repos_to_scan)):
					break

				pbar.set_description(f"Scanning {repo['full_name'][:40]}")

				findings = self._scan_repository(repo, scan_type=f"org:{org_name}")

				all_findings.extend(findings)

				pbar.update(1)

		print(f"\n📝 Generating report...")

		report_path = self.report_generator.generate_report(
			all_findings,
			scan_start_time,
			scan_type=f"org:{org_name}"
		)

		summary = self.report_generator.generate_summary(report_path, len(all_findings))

		print(summary)

		if return_data:
			return report_path, {
				'findings': all_findings,
				'start_time': scan_start_time,
				'scan_type': f"org:{org_name}"
			}

		return report_path


	def scan_ai_projects(self, max_repos: int = 50, return_data: bool = False):
		print(f"🚀 Starting auto search for AI-related projects")

		print(f"🎯 Target: Find and scan {max_repos} unscanned repositories")

		scan_start_time = datetime.now()

		self.scan_start_time = time.time()

		def is_scanned(repo_full_name: str) -> bool:
			return self.scan_history.is_scanned(repo_full_name)

		repos_to_scan = self.github_scanner.search_ai_repos(
			max_repos=max_repos,
			skip_filter=is_scanned if self.skip_scanned else None
		)

		print(f"📦 Found {len(repos_to_scan)} repositories to scan")

		all_findings = []

		with tqdm(total=len(repos_to_scan), desc="Scanning AI projects", unit="repo", ncols=100) as pbar:
			for idx, repo in enumerate(repos_to_scan, 1):
				if self._check_timeout(idx - 1, len(repos_to_scan)):
					break

				pbar.set_description(f"Scanning {repo['full_name'][:40]}")

				findings = self._scan_repository(repo, scan_type="auto:ai-projects")

				all_findings.extend(findings)

				pbar.update(1)

		print(f"\n📝 Generating report...")

		report_path = self.report_generator.generate_report(
			all_findings,
			scan_start_time,
			scan_type="auto:ai-projects"
		)

		summary = self.report_generator.generate_summary(report_path, len(all_findings))

		print(summary)

		if return_data:
			return report_path, {
				'findings': all_findings,
				'start_time': scan_start_time,
				'scan_type': "auto:ai-projects"
			}
		return report_path


	def scan_single_repo(self, repo_full_name: str, return_data: bool = False):
		print(f"🚀 Starting scan for repository: {repo_full_name}")

		scan_start_time = datetime.now()

		repo_info = {
			'full_name': repo_full_name,
			'url': f"https://github.com/{repo_full_name}",
			'clone_url': f"https://github.com/{repo_full_name}.git",
		}

		findings = self._scan_repository(repo_info)

		print(f"\n📝 Generating report...")

		report_path = self.report_generator.generate_report(
			findings,
			scan_start_time,
			scan_type=f"single:{repo_full_name}"
		)

		summary = self.report_generator.generate_summary(report_path, len(findings))

		print(summary)

		if return_data:
			return report_path, {
				'findings': findings,
				'start_time': scan_start_time,
				'scan_type': f"single:{repo_full_name}"
			}
		return report_path


	def _filter_scanned_repos(self, repos: List[Dict]) -> tuple:
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
		findings = []
		scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		repo_name = repo.get('full_name', 'unknown')

		if not repo_name or repo_name == 'unknown':
			print(f"  ❌ Invalid repository data: missing 'full_name'")

			return findings

		try:
			files = self.github_scanner.get_repo_files(repo_name)

			if not files:
				self.scan_history.mark_as_scanned(repo_name, 0, f"{scan_type}:no-access")

				return findings

			for file_info in files:
				file_path = file_info.get('path', '')

				if not file_path:
					continue

				file_size = file_info.get('size', 0)

				if file_size > MAX_FILE_SIZE:
					if PRODUCTION_MODE:
						print(f"  ⏭️  Skipping large file: {file_path} ({file_size / 1024 / 1024:.1f}MB)")
					continue
				elif file_size > MAX_FILE_SIZE_WARNING and PRODUCTION_MODE:
					print(f"  ⚠️  Scanning large file: {file_path} ({file_size / 1024 / 1024:.1f}MB)")

				if not self.secret_detector.should_scan_file(file_path):
					continue

				content = self.github_scanner.get_file_content(
					repo_name,
					file_path
				)

				if content:
					secrets = self.secret_detector.detect_secrets_in_text(
						content,
						file_path
					)

					for secret in secrets:
						secret['repo_url'] = repo.get('url', f"https://github.com/{repo_name}")
						secret['repo_name'] = repo['full_name']
						secret['scan_time'] = scan_time
						findings.append(secret)

			findings = self.secret_detector.deduplicate_findings(findings)
			findings = self.secret_detector.filter_high_confidence(findings)

			if findings:
				print(f"  ⚠️  Found {len(findings)} potential issue(s)")
			else:
				print(f"  ✅ No obvious issues found")

			self.scan_history.mark_as_scanned(repo_name, len(findings), scan_type)
		except Exception as e:
			error_msg = str(e)

			if "403" in error_msg or "Forbidden" in error_msg:
				print(f"  ⏭️  Skipping: No access")

				self.scan_history.mark_as_scanned(repo_name, 0, f"{scan_type}:forbidden")
			else:
				print(f"  ❌ Scan failed: {e}")

				self.scan_history.mark_as_scanned(repo_name, 0, f"{scan_type}:failed")

		return findings