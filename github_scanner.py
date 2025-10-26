"""
GitHub repository scanning module
"""
import time
import re
from datetime import datetime
from typing import List, Dict, Optional
from github import Github, GithubException
from config import GITHUB_TOKEN, AI_SEARCH_KEYWORDS, MAX_REPOS_PER_SEARCH, SEARCH_DELAY_SECONDS


class GitHubScanner:
    """GitHub repository scanner"""

    def __init__(self, token: str = GITHUB_TOKEN):
        """
        Initialize GitHub scanner

        Args:
            token: GitHub Personal Access Token
        """
        if not token:
            raise ValueError("GitHub Token is required. Please set GITHUB_TOKEN in .env file")
        
        # Configure timeout and retry parameters to avoid long waits
        self.github = Github(
            token,
            timeout=30,  # Set 30 second timeout
            retry=None   # Disable auto-retry, we handle it ourselves
        )
        self.rate_limit_remaining = None
        self.rate_limit_reset = None
        
    def get_rate_limit_info(self) -> Dict:
        """Get API rate limit information"""
        rate_limit = self.github.get_rate_limit()
        core = rate_limit.core
        
        return {
            'remaining': core.remaining,
            'limit': core.limit,
            'reset': core.reset
        }
    
    def wait_for_rate_limit(self):
        """Wait for rate limit reset"""
        info = self.get_rate_limit_info()
        if info['remaining'] < 10:
            # info['reset'] is a datetime object, needs to be compared with datetime.now()
            wait_time = (info['reset'] - datetime.now()).total_seconds() + 10
            print(f"⚠️  API rate limit nearly exhausted, waiting {wait_time:.0f} seconds...")
            time.sleep(max(0, wait_time))
    
    def get_user_repos(self, username: str) -> List[Dict]:
        """
        Get all public repositories of a specified user

        Args:
            username: GitHub username

        Returns:
            List of repository information
        """
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
        """
        Get all public repositories of a specified organization

        Args:
            org_name: GitHub organization name

        Returns:
            List of repository information
        """
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
        """
        Search AI-related GitHub projects

        Args:
            max_repos: Maximum number of repositories to return
            skip_filter: Optional filter function, accepts repository full name, returns True to skip the repository

        Returns:
            List of repository information
        """
        all_repos = []
        seen_repos = set()
        skipped_count = 0
        
        for keyword in AI_SEARCH_KEYWORDS:
            try:
                print(f"🔍 Searching keyword: {keyword}")
                self.wait_for_rate_limit()

                # Search code
                query = f'{keyword} in:file language:python'
                results = self.github.search_code(query, order='desc')

                # Extract repositories from code search results
                for code in results:
                    # Stop searching if enough repositories found
                    if len(all_repos) >= max_repos:
                        break

                    repo = code.repository

                    # Skip private repositories and already seen repositories
                    if repo.private or repo.full_name in seen_repos:
                        continue

                    seen_repos.add(repo.full_name)

                    # If a filter function is provided, check if we should skip
                    if skip_filter and skip_filter(repo.full_name):
                        skipped_count += 1
                        print(f"  ⏭️  Skipping already scanned: {repo.full_name}")
                        continue  # Don't count, continue to next one
                    
                    # Add to results list
                    all_repos.append({
                        'name': repo.name,
                        'full_name': repo.full_name,
                        'url': repo.html_url,
                        'clone_url': repo.clone_url,
                        'description': repo.description,
                        'updated_at': repo.updated_at,
                    })

                # Delay to avoid triggering rate limit
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
    
    def get_repo_files(self, repo_full_name: str, path: str = "") -> List[Dict]:
        """
        Get list of files in repository

        Args:
            repo_full_name: Repository full name (owner/repo)
            path: File path

        Returns:
            List of file information
        """
        try:
            repo = self.github.get_repo(repo_full_name)
            contents = repo.get_contents(path)
            
            files = []
            for content in contents:
                if content.type == "dir":
                    # Recursively get subdirectory files
                    files.extend(self.get_repo_files(repo_full_name, content.path))
                else:
                    files.append({
                        'path': content.path,
                        'name': content.name,
                        'download_url': content.download_url,
                        'sha': content.sha,
                    })

            return files
        except GithubException as e:
            # Skip 403 errors directly, no waiting
            if e.status == 403:
                print(f"  ⏭️  Skipping: No access (403 Forbidden)")
            else:
                print(f"⚠️  Failed to get file list: {e}")
            return []
    
    def get_file_content(self, repo_full_name: str, file_path: str) -> Optional[str]:
        """
        Get file content

        Args:
            repo_full_name: Repository full name (owner/repo)
            file_path: File path

        Returns:
            File content (text)
        """
        try:
            repo = self.github.get_repo(repo_full_name)
            content = repo.get_contents(file_path)

            # Decode content
            try:
                return content.decoded_content.decode('utf-8')
            except UnicodeDecodeError:
                # Return None for binary files
                return None
        except GithubException as e:
            # Skip 403 errors directly, don't print error
            if e.status == 403:
                pass  # Silent skip
            return None
