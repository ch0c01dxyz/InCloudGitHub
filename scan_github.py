#!/usr/bin/env python3
"""
InCloud GitHub Scanner - Main Program
For scanning leaked AI API keys and sensitive information in GitHub repositories
"""
import argparse
import sys
import os
from datetime import datetime
from config import GITHUB_TOKEN
from scanner import CloudScanner


def print_banner():
    """Print program banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        InCloud GitHub Scanner                             ║
║        AI API Key Leakage Scanner                         ║
║                                                           ║
║        Version: 1.0.0                                     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)


def validate_github_token() -> bool:
    """Validate GitHub Token existence"""
    if not GITHUB_TOKEN:
        print("❌ Error: GitHub Token not found")
        print("\nPlease follow these steps to set up:")
        print("1. Copy .env.example to .env")
        print("2. Create Personal Access Token at https://github.com/settings/tokens")
        print("3. Add Token to GITHUB_TOKEN variable in .env file")
        return False
    return True


def main():
    """Main function"""
    print_banner()

    # Create command line argument parser
    parser = argparse.ArgumentParser(
        description='Scan GitHub repositories for leaked AI API keys and sensitive information',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  # Scan all public repositories of a specified user
  python scan_github.py --user username

  # Scan all public repositories of a specified organization
  python scan_github.py --org organization_name

  # Scan a single repository
  python scan_github.py --repo owner/repo_name

  # Auto search and scan AI-related projects
  python scan_github.py --auto

  # Auto search and scan specified number of repositories
  python scan_github.py --auto --max-repos 100
        """
    )
    
    # Add arguments
    parser.add_argument(
        '--user',
        type=str,
        help='Scan all public repositories of specified GitHub user'
    )

    parser.add_argument(
        '--org',
        type=str,
        help='Scan all public repositories of specified GitHub organization'
    )

    parser.add_argument(
        '--repo',
        type=str,
        help='Scan single repository (format: owner/repo_name)'
    )

    parser.add_argument(
        '--auto',
        action='store_true',
        help='Auto search and scan AI-related projects'
    )

    parser.add_argument(
        '--max-repos',
        type=int,
        default=50,
        help='Maximum number of repositories to scan in auto mode (default: 50)'
    )

    parser.add_argument(
        '--token',
        type=str,
        help='GitHub Personal Access Token (optional, default reads from .env)'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        help='Report output directory (optional, default: ./scan_reports)'
    )

    parser.add_argument(
        '--no-skip-scanned',
        action='store_true',
        help='Do not skip already scanned repositories, force rescan all repositories'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Generate JSON report in addition to text report (for automation/integration)'
    )

    parser.add_argument(
        '--production',
        action='store_true',
        help='Enable production mode with strict validation and enhanced logging'
    )
    
    # Parse arguments
    args = parser.parse_args()

    # Check if at least one scan option is provided
    if not any([args.user, args.org, args.repo, args.auto]):
        parser.print_help()
        print("\n❌ Error: Please specify at least one scan option (--user, --org, --repo, or --auto)")
        sys.exit(1)

    # Validate GitHub Token
    token = args.token or GITHUB_TOKEN
    if not token:
        if not validate_github_token():
            sys.exit(1)

    # Get output directory
    output_dir = args.output_dir if args.output_dir else None

    # Set production mode if requested
    if args.production:
        os.environ['PRODUCTION_MODE'] = 'true'
        print("🔒 Production mode enabled")

    try:
        # Create scanner instance
        skip_scanned = not args.no_skip_scanned
        scanner = CloudScanner(token, skip_scanned=skip_scanned, output_dir=output_dir)

        # Execute different scans based on arguments
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

        # Generate JSON report if requested
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
