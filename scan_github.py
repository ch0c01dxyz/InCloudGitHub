#!/usr/bin/env python3
import argparse
import sys
import os
from datetime import datetime
from config import GITHUB_TOKEN
from scanner import CloudScanner


def print_banner():
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        InCloud GitHub Scanner                             ║
║                                                           ║
║        Version: 1.0.0                                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)


def validate_github_token() -> bool:
    if not GITHUB_TOKEN:
        print("❌ Error: GitHub Token not found")
        print("\nPlease follow these steps to set up:")
        print("1. Copy .env.example to .env")
        print("2. Create Personal Access Token at https://github.com/settings/tokens")
        print("3. Add Token to GITHUB_TOKEN variable in .env file")
        return False
    return True


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='Scan GitHub repositories for sensitive information',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  # Scan all pub repo of specified user
  python scan_github.py --user username

  # Scan all pub repo of specified org
  python scan_github.py --org organization_name

  # Scan single repo
  python scan_github.py --repo owner/repo_name

  # Auto search and scan projects
  python scan_github.py --auto

  # Auto search and scan specified n repo
  python scan_github.py --auto --max-repos 100
        """
    )
    
    parser.add_argument(
        '--user',
        type=str,
        help='Scan all pub repo of specified user'
    )

    parser.add_argument(
        '--org',
        type=str,
        help='Scan all pub repo of specified org'
    )

    parser.add_argument(
        '--repo',
        type=str,
        help='Scan single repo (format: owner/repo_name)'
    )

    parser.add_argument(
        '--auto',
        action='store_true',
        help='Auto search and scan projects'
    )

    parser.add_argument(
        '--max-repos',
        type=int,
        default=50,
        help='Maximum n repo to scan in auto mode (def: 50)'
    )

    parser.add_argument(
        '--token',
        type=str,
        help='GitHub Personal Token (opt, default reads from .env)'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        help='Report output dir (opt, default: ./scan_reports)'
    )

    parser.add_argument(
        '--no-skip-scanned',
        action='store_true',
        help='Force rescan all repositories'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Generate JSON report in addt. to text report (for auto/intg)'
    )

    parser.add_argument(
        '--production',
        action='store_true',
        help='Enable prod mode with strict validation and logging'
    )

    args = parser.parse_args()

    if not any([args.user, args.org, args.repo, args.auto]):
        parser.print_help()

        print("\n❌ Error: Please specify at least one scan option (--user, --org, --repo, or --auto)")

        sys.exit(1)

    token = args.token or GITHUB_TOKEN

    if not token:
        if not validate_github_token():
            sys.exit(1)

    output_dir = args.output_dir if args.output_dir else None

    if args.production:
        os.environ['PRODUCTION_MODE'] = 'true'
        print("🔒 Prod mode enabled")

    try:
        skip_scanned = not args.no_skip_scanned
        scanner = CloudScanner(token, skip_scanned=skip_scanned, output_dir=output_dir)

        if args.user:
            report_path, scan_data = scanner.scan_user(args.user, return_data=True)
        elif args.org:
            report_path, scan_data = scanner.scan_organization(args.org, return_data=True)
        elif args.repo:
            report_path, scan_data = scanner.scan_single_repo(args.repo, return_data=True)
        elif args.auto:
            report_path, scan_data = scanner.scan_ai_projects(max_repos=args.max_repos, return_data=True)

        print(f"\n✅ Scan completed!")
        print(f"📄 Text report saved to: {report_path}")

        if args.json and scan_data:
            json_path = scanner.report_generator.generate_json_report(
                scan_data['findings'],
                scan_data['start_time'],
                scan_data['scan_type']
            )

            print(f"📊 JSON report saved to: {json_path}")
    except KeyboardInterrupt:
        print("\n\n⚠️  User interrupted scan")

        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")

        import traceback

        traceback.print_exc()

        sys.exit(1)


if __name__ == "__main__":
    main()
