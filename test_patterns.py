#!/usr/bin/env python3
"""
Basic test file for pattern detection
Tests the newly added patterns and core functionality
"""
import sys
from secret_detector import SecretDetector


def test_patterns():
    """Test various secret patterns"""
    detector = SecretDetector()

    test_cases = [
        # OpenAI
        ("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD", "OpenAI Project Key"),
        ("sk-ant-api03-1234567890abcdefABCDEF", "Anthropic Key"),

        # AWS
        ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AWS Access Key"),

        # GitHub
        ("GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuv", "GitHub PAT"),

        # Groq
        ("GROQ_API_KEY=gsk_1234567890abcdefghijklmnopqrstuvwxyz", "Groq API Key"),

        # Database
        ("postgresql://user:password@localhost:5432/dbname", "PostgreSQL connection"),

        # JWT
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "JWT Token"),

        # Stripe
        ("sk_live_1234567890abcdefghijklmnop", "Stripe Live Key"),

        # SendGrid
        ("SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg", "SendGrid Key"),

        # Slack
        ("xoxb-1234567890-abcdefghijklmnopqrstuvwx", "Slack Bot Token"),

        # Example code (should be filtered)
        ("OPENAI_API_KEY=your_api_key_here", "Example code - should filter"),
        ("api_key = 'placeholder_value'", "Placeholder - should filter"),
    ]

    print("=" * 80)
    print("Testing Secret Detector with Enhanced Patterns")
    print("=" * 80)
    print(f"\nTotal compiled patterns: {len(detector.patterns)}")
    print(f"Testing {len(test_cases)} test cases...\n")

    passed = 0
    failed = 0

    for idx, (test_input, description) in enumerate(test_cases, 1):
        findings = detector.detect_secrets_in_text(test_input, f"test_file_{idx}.py")

        # Check if it's supposed to be filtered
        should_filter = "filter" in description.lower()

        if should_filter:
            if len(findings) == 0:
                print(f"✓ Test {idx}: {description} - CORRECTLY FILTERED")
                passed += 1
            else:
                print(f"✗ Test {idx}: {description} - FAILED (should be filtered)")
                print(f"  Found: {findings}")
                failed += 1
        else:
            if len(findings) > 0:
                print(f"✓ Test {idx}: {description} - DETECTED")
                print(f"  Confidence: {findings[0]['confidence']}")
                passed += 1
            else:
                print(f"✗ Test {idx}: {description} - NOT DETECTED")
                failed += 1

    print("\n" + "=" * 80)
    print(f"Test Results: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print("=" * 80)

    return failed == 0


def test_file_filtering():
    """Test file filtering logic"""
    detector = SecretDetector()

    test_files = [
        ("src/main.py", True),
        ("src/config.json", True),
        ("node_modules/package/index.js", False),
        (".git/config", False),
        ("dist/bundle.js", False),
        ("image.png", False),
        ("document.pdf", False),
        ("test.env", True),
    ]

    print("\n" + "=" * 80)
    print("Testing File Filtering Logic")
    print("=" * 80 + "\n")

    passed = 0
    failed = 0

    for file_path, should_scan in test_files:
        result = detector.should_scan_file(file_path)
        if result == should_scan:
            status = "✓" if should_scan else "✓ (excluded)"
            print(f"{status} {file_path}: {result}")
            passed += 1
        else:
            print(f"✗ {file_path}: Expected {should_scan}, got {result}")
            failed += 1

    print(f"\nFile filtering: {passed} passed, {failed} failed")
    return failed == 0


def main():
    """Run all tests"""
    print("\n🧪 InCloud GitHub Scanner - Pattern Testing Suite\n")

    all_passed = True

    # Test pattern detection
    if not test_patterns():
        all_passed = False

    # Test file filtering
    if not test_file_filtering():
        all_passed = False

    print("\n" + "=" * 80)
    if all_passed:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed. Please review the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
