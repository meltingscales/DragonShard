#!/usr/bin/env python3
"""
Convenient linting script for DragonShard.
"""

import subprocess
import sys
import argparse
from pathlib import Path


def run_ruff_check(fix=False, unsafe_fixes=False, show_source=False):
    """Run ruff check with specified options."""
    cmd = ['ruff', 'check', 'dragonshard/']
    
    if fix:
        cmd.append('--fix')
    if unsafe_fixes:
        cmd.append('--unsafe-fixes')
    if show_source:
        cmd.append('--show-source')
    
    print(f"🔍 Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    return result.returncode == 0


def run_ruff_format(check_only=False):
    """Run ruff format with specified options."""
    cmd = ['ruff', 'format', 'dragonshard/']
    
    if check_only:
        cmd.append('--check')
    
    print(f"🎨 Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    return result.returncode == 0


def run_security_checks():
    """Run security-related checks."""
    print("🔒 Running security checks...")
    
    # Bandit security linter
    print("\n📦 Running Bandit...")
    bandit_result = subprocess.run([
        'bandit', '-r', 'dragonshard/', '-f', 'txt'
    ], capture_output=True, text=True)
    
    if bandit_result.stdout:
        print(bandit_result.stdout)
    if bandit_result.stderr:
        print(bandit_result.stderr)
    
    # Safety check for vulnerable dependencies
    print("\n🛡️ Running Safety...")
    safety_result = subprocess.run([
        'safety', 'check'
    ], capture_output=True, text=True)
    
    if safety_result.stdout:
        print(safety_result.stdout)
    if safety_result.stderr:
        print(safety_result.stderr)
    
    return bandit_result.returncode == 0 and safety_result.returncode == 0


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='DragonShard Linting Tool')
    parser.add_argument('--fix', action='store_true', 
                       help='Automatically fix issues')
    parser.add_argument('--unsafe-fixes', action='store_true',
                       help='Apply unsafe fixes')
    parser.add_argument('--format', action='store_true',
                       help='Format code with ruff')
    parser.add_argument('--format-check', action='store_true',
                       help='Check code formatting without fixing')
    parser.add_argument('--security', action='store_true',
                       help='Run security checks (bandit, safety)')
    parser.add_argument('--all', action='store_true',
                       help='Run all checks (lint, format, security)')
    parser.add_argument('--show-source', action='store_true',
                       help='Show source code for issues')
    
    args = parser.parse_args()
    
    # Change to project root
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    success = True
    
    if args.all or not any([args.fix, args.unsafe_fixes, args.format, 
                           args.format_check, args.security]):
        # Default: run lint check
        print("🐉 DragonShard Linting Tool")
        print("=" * 40)
        
        success &= run_ruff_check(fix=args.fix, unsafe_fixes=args.unsafe_fixes, 
                                 show_source=args.show_source)
        
        if args.all:
            success &= run_ruff_format(check_only=True)
            success &= run_security_checks()
    
    else:
        if args.fix or args.unsafe_fixes:
            success &= run_ruff_check(fix=args.fix, unsafe_fixes=args.unsafe_fixes,
                                    show_source=args.show_source)
        
        if args.format:
            success &= run_ruff_format()
        
        if args.format_check:
            success &= run_ruff_format(check_only=True)
        
        if args.security:
            success &= run_security_checks()
    
    if success:
        print("\n✅ All checks passed!")
        sys.exit(0)
    else:
        print("\n❌ Some checks failed!")
        sys.exit(1)


if __name__ == '__main__':
    main() 