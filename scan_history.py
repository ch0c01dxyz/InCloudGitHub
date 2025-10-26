import json
import os
from datetime import datetime
from typing import Dict, List, Set
from pathlib import Path


class ScanHistory:
	def __init__(self, history_file: str = None):
		if history_file is None:
			history_dir = Path("scan_history")

			history_dir.mkdir(exist_ok=True)

			self.history_file = history_dir / "scanned_repos.json"
		else:
			self.history_file = Path(history_file)
			self.history_file.parent.mkdir(exist_ok=True, parents=True)

		self.history = self._load_history()


	def _load_history(self) -> Dict:
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
		try:
			with open(self.history_file, 'w', encoding='utf-8') as f:
				json.dump(self.history, f, indent=2, ensure_ascii=False)
		except Exception as e:
			print(f"⚠️  Failed to save scan history: {e}")


	def is_scanned(self, repo_full_name: str) -> bool:
		return repo_full_name in self.history["repos"]


	def get_scan_info(self, repo_full_name: str) -> Dict:
		return self.history["repos"].get(repo_full_name)


	def mark_as_scanned(self, repo_full_name: str, findings_count: int = 0, scan_type: str = "unknown"):
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
		return list(self.history["repos"].keys())


	def get_scanned_count(self) -> int:
		return self.history["total_scanned"]


	def clear_history(self):
		self.history = {"repos": {}, "total_scanned": 0, "last_updated": None}

		self._save_history()

		print("✅ Scan history cleared")


	def remove_repo(self, repo_full_name: str):
		if repo_full_name in self.history["repos"]:
			del self.history["repos"][repo_full_name]

			self.history["total_scanned"] = len(self.history["repos"])

			self.history["last_updated"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

			self._save_history()

			print(f"✅ Removed from history: {repo_full_name}")
		else:
			print(f"⚠️  Repository not in history: {repo_full_name}")


	def get_statistics(self) -> Dict:
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
		stats = self.get_statistics()

		print(f"\n📊 Scan History Stats:")
		print(f"   Total Repo Scanned: {stats['total_scanned']}")
		print(f"   Total Issues Found: {stats['total_findings']}")
		print(f"   Repos with Issues: {stats['repos_with_findings']}")
		if stats['last_updated']:
			print(f"   Updated: {stats['last_updated']}")

