#!/usr/bin/env python3
"""
DragonShard Diagram Generation Demo

This script demonstrates the automatic diagram generation capabilities
for the DragonShard codebase.
"""

import json
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, '.')

from scripts.generate_diagrams import DiagramGenerator


def main():
    """Demo the diagram generation functionality."""
    print("🐉 DragonShard Diagram Generation Demo")
    print("=" * 50)
    
    # Initialize the diagram generator
    generator = DiagramGenerator("dragonshard")
    
    print("📊 Analyzing DragonShard codebase...")
    
    # Generate all diagrams
    diagram_files = generator.generate_all_diagrams()
    
    print("\n✅ Diagram generation completed!")
    print(f"📁 Output directory: {generator.output_dir}")
    
    # Show summary
    summary_file = Path(diagram_files["summary"])
    if summary_file.exists():
        with open(summary_file, 'r') as f:
            summary = json.load(f)
        
        print("\n📈 Codebase Analysis Summary:")
        print(f"   📦 Modules analyzed: {summary['modules']}")
        print(f"   🏗️  Classes found: {summary['classes']}")
        print(f"   📋 Dataclasses: {summary['dataclasses']}")
        print(f"   🔢 Enums: {summary['enums']}")
        print(f"   🔗 Relationships: {summary['relationships']}")
    
    print("\n📊 Generated Files:")
    for file_type, file_path in diagram_files.items():
        if file_type != "summary":
            file_size = Path(file_path).stat().st_size if Path(file_path).exists() else 0
            print(f"   - {file_type}: {file_path} ({file_size} bytes)")
    
    print("\n🎯 Usage:")
    print("   - Run 'make diagrams' to generate diagrams")
    print("   - Run 'make diagrams-readme' to update README")
    print("   - View diagrams in docs/diagrams/")
    
    print("\n🔗 Diagram Types:")
    print("   - ER Diagram: Shows entity relationships and inheritance")
    print("   - Module Diagram: Shows module dependencies and structure")
    
    print("\n✨ Features:")
    print("   - Automatic code analysis using AST parsing")
    print("   - SVG and DOT format output")
    print("   - Integration with build process")
    print("   - README auto-update capability")
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 