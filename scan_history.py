"""
Scan history management module - Track scanned repositories to avoid duplicate scans
"""
import json
import os
from datetime import datetime
from typing import Dict, List, Set
from pathlib import Path


class ScanHistory:
    """Scan history manager"""

    def __init__(self, history_file: str = None):
        """
        Initialize scan history manager

        Args:
            history_file: History file path, defaults to scan_history/scanned_repos.json
        """
        if history_file is None:
            history_dir = Path("scan_history")
            history_dir.mkdir(exist_ok=True)
            self.history_file = history_dir / "scanned_repos.json"
        else:
            self.history_file = Path(history_file)
            self.history_file.parent.mkdir(exist_ok=True, parents=True)
        
        self.history = self._load_history()
    
    def _load_history(self) -> Dict:
        """
        Load scan history from file

        Returns:
            History dictionary
        """
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️  Failed to load scan history: {e}, creating new history")
                return {"repos": {}, "total_scanned": 0, "last_updated": None}
        else:
            return {"repos": {}, "total_scanned": 0, "last_updated": None}
    
    def _save_history(self):
        """Save scan history to file"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"⚠️  Failed to save scan history: {e}")
    
    def is_scanned(self, repo_full_name: str) -> bool:
        """
        Check if repository has been scanned

        Args:
            repo_full_name: Repository full name (owner/repo)

        Returns:
            True if scanned, False if not scanned
        """
        return repo_full_name in self.history["repos"]

    def get_scan_info(self, repo_full_name: str) -> Dict:
        """
        Get scan information for repository

        Args:
            repo_full_name: Repository full name (owner/repo)

        Returns:
            Scan information dictionary, or None if not scanned
        """
        return self.history["repos"].get(repo_full_name)

    def mark_as_scanned(self, repo_full_name: str, findings_count: int = 0,
                        scan_type: str = "unknown"):
        """
        Mark repository as scanned

        Args:
            repo_full_name: Repository full name (owner/repo)
            findings_count: Number of findings
            scan_type: Scan type
        """
        self.history["repos"][repo_full_name] = {
            "first_scan": self.history["repos"].get(repo_full_name, {}).get(
                "first_scan", 
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ),
            "last_scan": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "findings_count": findings_count,
            "scan_type": scan_type,
            "scan_count": self.history["repos"].get(repo_full_name, {}).get("scan_count", 0) + 1
        }
        
        self.history["total_scanned"] = len(self.history["repos"])
        self.history["last_updated"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        self._save_history()
    
    def get_scanned_repos(self) -> List[str]:
        """
        Get list of all scanned repositories

        Returns:
            List of repository full names
        """
        return list(self.history["repos"].keys())

    def get_scanned_count(self) -> int:
        """
        Get total count of scanned repositories

        Returns:
            Repository count
        """
        return self.history["total_scanned"]

    def clear_history(self):
        """Clear scan history"""
        self.history = {"repos": {}, "total_scanned": 0, "last_updated": None}
        self._save_history()
        print("✅ Scan history cleared")

    def remove_repo(self, repo_full_name: str):
        """
        Remove specified repository from history

        Args:
            repo_full_name: Repository full name (owner/repo)
        """
        if repo_full_name in self.history["repos"]:
            del self.history["repos"][repo_full_name]
            self.history["total_scanned"] = len(self.history["repos"])
            self.history["last_updated"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self._save_history()
            print(f"✅ Removed from history: {repo_full_name}")
        else:
            print(f"⚠️  Repository not in history: {repo_full_name}")
    
    def get_statistics(self) -> Dict:
        """
        Get scan statistics

        Returns:
            Statistics dictionary
        """
        total_findings = sum(
            repo_info.get("findings_count", 0)
            for repo_info in self.history["repos"].values()
        )

        repos_with_findings = sum(
            1 for repo_info in self.history["repos"].values()
            if repo_info.get("findings_count", 0) > 0
        )

        return {
            "total_scanned": self.history["total_scanned"],
            "total_findings": total_findings,
            "repos_with_findings": repos_with_findings,
            "last_updated": self.history["last_updated"]
        }

    def print_statistics(self):
        """Print scan statistics"""
        stats = self.get_statistics()
        print(f"\n📊 Scan History Statistics:")
        print(f"   Total Repositories Scanned: {stats['total_scanned']}")
        print(f"   Total Issues Found: {stats['total_findings']}")
        print(f"   Repositories with Issues: {stats['repos_with_findings']}")
        if stats['last_updated']:
            print(f"   Last Updated: {stats['last_updated']}")

