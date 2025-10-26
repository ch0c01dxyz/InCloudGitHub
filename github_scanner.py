import time
import re
from datetime import datetime
from typing import List, Dict, Optional
from github import Github, GithubException

try:
	from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

	TENACITY_AVAILABLE = True
except ImportError:
	TENACITY_AVAILABLE = False

	def retry(*args, **kwargs):
		def decorator(func):
			return func
		return decorator

	stop_after_attempt = wait_exponential = retry_if_exception_type = lambda *args, **kwargs: None


from config import (
	GITHUB_TOKEN, AI_SEARCH_KEYWORDS, MAX_REPOS_PER_SEARCH,
	SEARCH_DELAY_SECONDS, ENABLE_RETRY, MAX_RETRIES, PRODUCTION_MODE
)


class GitHubScanner:
	def __init__(self, token: str = GITHUB_TOKEN):
		if not token:
			raise ValueError("GitHub Token is required. Please set GITHUB_TOKEN in .env file")

		self.github = Github(
			token,
			timeout=30,
			retry=None
		)

		self.rate_limit_remaining = None
		self.rate_limit_reset = None


	def get_rate_limit_info(self) -> Dict:
		rate_limit = self.github.get_rate_limit()
		core = rate_limit.core

		return {
			'remaining': core.remaining,
			'limit': core.limit,
			'reset': core.reset
		}


	def wait_for_rate_limit(self):
		info = self.get_rate_limit_info()

		if info['remaining'] < 10:
			wait_time = (info['reset'] - datetime.now()).total_seconds() + 10

			print(f"⚠️  API rate limit nearly exhausted, waiting {wait_time:.0f} seconds...")

			time.sleep(max(0, wait_time))


	def get_user_repos(self, username: str) -> List[Dict]:
		try:
			user = self.github.get_user(username)
			repos = []

			for repo in user.get_repos():
				if not repo.private:
					repos.append({
						'name': repo.name,
						'full_name': repo.full_name,
						'url': repo.html_url,
						'clone_url': repo.clone_url,
						'description': repo.description,
						'updated_at': repo.updated_at,
					})

			return repos
		except GithubException as e:
			print(f"❌ Failed to get user repositories: {e}")

			return []


	def get_org_repos(self, org_name: str) -> List[Dict]:
		try:
			org = self.github.get_organization(org_name)
			repos = []

			for repo in org.get_repos():
				if not repo.private:
					repos.append({
						'name': repo.name,
						'full_name': repo.full_name,
						'url': repo.html_url,
						'clone_url': repo.clone_url,
						'description': repo.description,
						'updated_at': repo.updated_at,
					})

			return repos
		except GithubException as e:
			print(f"❌ Failed to get organization repositories: {e}")

			return []


	def search_ai_repos(self, max_repos: int = MAX_REPOS_PER_SEARCH, skip_filter=None) -> List[Dict]:
		all_repos = []
		seen_repos = set()
		skipped_count = 0

		for keyword in AI_SEARCH_KEYWORDS:
			try:
				print(f"🔍 Searching keyword: {keyword}")

				self.wait_for_rate_limit()

				query = f'{keyword} in:file language:python'
				results = self.github.search_code(query, order='desc')

				for code in results:
					if len(all_repos) >= max_repos:
						break

					repo = code.repository

					if repo.private or repo.full_name in seen_repos:
						continue

					seen_repos.add(repo.full_name)

					if skip_filter and skip_filter(repo.full_name):
						skipped_count += 1

						print(f"  ⏭️  Skipping already scanned: {repo.full_name}")

						continue

					all_repos.append({
						'name': repo.name,
						'full_name': repo.full_name,
						'url': repo.html_url,
						'clone_url': repo.clone_url,
						'description': repo.description,
						'updated_at': repo.updated_at,
					})

				time.sleep(SEARCH_DELAY_SECONDS)

				if len(all_repos) >= max_repos:
					print(f"✅ Found {len(all_repos)} unscanned repositories (skipped {skipped_count} already scanned)")

					break

			except GithubException as e:
				print(f"⚠️  Error searching '{keyword}': {e}")

				continue

		if skipped_count > 0 and len(all_repos) < max_repos:
			print(f"ℹ️  Found {len(all_repos)} unscanned repositories (skipped {skipped_count} already scanned)")

		return all_repos


	def get_repo_files(self, repo_full_name: str, path: str = "", max_depth: int = 10, _current_depth: int = 0) -> List[Dict]:
		if _current_depth >= max_depth:
			if PRODUCTION_MODE:
				print(f"  ⚠️  Max depth reached at {path}, skipping deeper directories")
			return []

		if ENABLE_RETRY and TENACITY_AVAILABLE:
			@retry(
				stop=stop_after_attempt(MAX_RETRIES),
				wait=wait_exponential(multiplier=1, min=2, max=10),
				retry=retry_if_exception_type(GithubException),
				reraise=True
			)

			def _get_contents():
				repo = self.github.get_repo(repo_full_name)

				return repo.get_contents(path)

			get_contents = _get_contents
		else:
			def get_contents():
				repo = self.github.get_repo(repo_full_name)

				return repo.get_contents(path)

		try:
			contents = get_contents()

			files = []

			for content in contents:
				if content.type == "dir":
					files.extend(self.get_repo_files(repo_full_name, content.path, max_depth, _current_depth + 1))
				else:
					files.append({
						'path': content.path,
						'name': content.name,
						'download_url': content.download_url,
						'sha': content.sha,
						'size': content.size,
					})

			return files
		except GithubException as e:
			if e.status == 403:
				if PRODUCTION_MODE:
					print(f"  ⏭️  Skipping: No access (403 Forbidden)")
			else:
				print(f"⚠️  Failed to get file list: {e}")
			return []


	def get_file_content(self, repo_full_name: str, file_path: str) -> Optional[str]:
		try:
			repo = self.github.get_repo(repo_full_name)
			content = repo.get_contents(file_path)

			try:
				return content.decoded_content.decode('utf-8')
			except UnicodeDecodeError:
				return None
		except GithubException as e:
			if e.status == 403:
				return None
			return None
