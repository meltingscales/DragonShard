#!/usr/bin/env python3
"""
CI/CD setup script for DragonShard.
Configures Travis CI, Codecov, and GitHub Actions.
"""

import os
import sys
import subprocess
from pathlib import Path


def check_requirements():
    """Check if required tools are available."""
    print("🔍 Checking CI/CD requirements...")
    
    required_tools = ['git', 'python', 'pip']
    missing_tools = []
    
    for tool in required_tools:
        try:
            subprocess.run([tool, '--version'], 
                         capture_output=True, check=True)
            print(f"✅ {tool} is available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing_tools.append(tool)
            print(f"❌ {tool} is not available")
    
    if missing_tools:
        print(f"\n❌ Missing required tools: {', '.join(missing_tools)}")
        return False
    
    return True


def setup_travis():
    """Set up Travis CI configuration."""
    print("\n🐳 Setting up Travis CI...")
    
    travis_file = Path('.travis.yml')
    if travis_file.exists():
        print("✅ Travis CI configuration already exists")
    else:
        print("❌ Travis CI configuration not found")
        return False
    
    print("📝 Travis CI configuration:")
    print("   - Python 3.10, 3.11, 3.12")
    print("   - Docker support")
    print("   - Caching enabled")
    print("   - Coverage reporting")
    print("   - Matrix testing (unit + Docker)")
    
    return True


def setup_codecov():
    """Set up Codecov configuration."""
    print("\n📊 Setting up Codecov...")
    
    codecov_file = Path('.codecov.yml')
    if codecov_file.exists():
        print("✅ Codecov configuration already exists")
    else:
        print("❌ Codecov configuration not found")
        return False
    
    print("📝 Codecov configuration:")
    print("   - 80% coverage target")
    print("   - HTML, XML, JSON reports")
    print("   - GitHub integration")
    print("   - PR comments enabled")
    
    return True


def setup_github_actions():
    """Set up GitHub Actions configuration."""
    print("\n⚡ Setting up GitHub Actions...")
    
    actions_dir = Path('.github/workflows')
    if actions_dir.exists() and list(actions_dir.glob('*.yml')):
        print("✅ GitHub Actions configuration already exists")
    else:
        print("❌ GitHub Actions configuration not found")
        return False
    
    print("📝 GitHub Actions configuration:")
    print("   - Multi-Python testing")
    print("   - Linting with Ruff")
    print("   - Security scanning")
    print("   - Docker image building")
    
    return True


def setup_security():
    """Set up security scanning."""
    print("\n🔒 Setting up security scanning...")
    
    bandit_file = Path('.bandit')
    if bandit_file.exists():
        print("✅ Bandit configuration already exists")
    else:
        print("❌ Bandit configuration not found")
        return False
    
    print("📝 Security configuration:")
    print("   - Bandit for security scanning")
    print("   - Safety for dependency checking")
    print("   - Excluded test files")
    print("   - JSON report output")
    
    return True


def install_ci_dependencies():
    """Install CI/CD dependencies."""
    print("\n📦 Installing CI/CD dependencies...")
    
    try:
        subprocess.run([
            'pip', 'install', 'pytest-cov', 'codecov', 'bandit', 'safety'
        ], check=True)
        print("✅ CI/CD dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install CI/CD dependencies: {e}")
        return False


def run_ci_checks():
    """Run CI checks locally."""
    print("\n🧪 Running CI checks locally...")
    
    checks = [
        ("Linting", ["ruff", "check", "dragonshard/"]),
        ("Security", ["bandit", "-r", "dragonshard/"]),
        ("Tests", ["pytest", "--cov=dragonshard", "--cov-report=term-missing"]),
    ]
    
    results = {}
    
    for name, command in checks:
        try:
            print(f"Running {name}...")
            subprocess.run(command, check=True, capture_output=True)
            print(f"✅ {name} passed")
            results[name] = True
        except subprocess.CalledProcessError as e:
            print(f"❌ {name} failed: {e}")
            results[name] = False
    
    return results


def main():
    """Main CI/CD setup function."""
    print("🐉 DragonShard CI/CD Setup")
    print("=" * 40)
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Set up configurations
    setup_travis()
    setup_codecov()
    setup_github_actions()
    setup_security()
    
    # Install dependencies
    if not install_ci_dependencies():
        sys.exit(1)
    
    # Run checks
    results = run_ci_checks()
    
    # Summary
    print("\n📋 CI/CD Setup Summary:")
    print("=" * 40)
    
    configs = [
        ("Travis CI", setup_travis()),
        ("Codecov", setup_codecov()),
        ("GitHub Actions", setup_github_actions()),
        ("Security", setup_security()),
    ]
    
    for name, status in configs:
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {name}")
    
    print("\n🧪 Local CI Checks:")
    for name, status in results.items():
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {name}")
    
    all_passed = all(results.values())
    if all_passed:
        print("\n🎉 CI/CD setup completed successfully!")
        print("\nNext steps:")
        print("1. Connect your repository to Travis CI")
        print("2. Connect your repository to Codecov")
        print("3. Enable GitHub Actions in your repository")
        print("4. Add your Codecov token to Travis CI")
    else:
        print("\n⚠️  Some checks failed. Please review the output above.")
        sys.exit(1)


if __name__ == '__main__':
    main() 