#!/usr/bin/env python3
"""
DragonShard Diagram Generator

This script generates ER diagrams and module diagrams for the DragonShard codebase.
It can be run as part of the build process to automatically update documentation.
"""

import ast
import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Add the project root to the path
sys.path.insert(0, '.')

try:
    import graphviz
    GRAPHVIZ_AVAILABLE = True
except ImportError:
    GRAPHVIZ_AVAILABLE = False
    print("⚠️  graphviz not available. Install with: pip install graphviz")

try:
    import matplotlib.pyplot as plt
    import networkx as nx
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("⚠️  matplotlib/networkx not available. Install with: pip install matplotlib networkx")

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class ClassInfo:
    """Information about a Python class."""
    name: str
    file_path: str
    module: str
    base_classes: List[str]
    methods: List[str]
    attributes: List[str]
    docstring: Optional[str] = None
    is_dataclass: bool = False
    is_enum: bool = False


@dataclass
class ModuleInfo:
    """Information about a Python module."""
    name: str
    file_path: str
    classes: List[ClassInfo]
    functions: List[str]
    imports: List[str]


@dataclass
class ERRelationship:
    """Entity-Relationship relationship."""
    from_entity: str
    to_entity: str
    relationship_type: str  # "one-to-many", "many-to-many", "one-to-one"
    description: str


class CodeAnalyzer:
    """Analyzes Python code to extract class and module information."""
    
    def __init__(self, project_root: str = "dragonshard"):
        self.project_root = Path(project_root)
        self.modules: Dict[str, ModuleInfo] = {}
        self.classes: Dict[str, ClassInfo] = {}
        
    def analyze_project(self) -> Dict[str, ModuleInfo]:
        """Analyze the entire project and extract module/class information."""
        logger.info(f"Analyzing project: {self.project_root}")
        
        for py_file in self.project_root.rglob("*.py"):
            if "tests" in str(py_file) or "__pycache__" in str(py_file):
                continue
                
            try:
                module_info = self.analyze_file(py_file)
                if module_info:
                    self.modules[module_info.name] = module_info
                    for class_info in module_info.classes:
                        self.classes[class_info.name] = class_info
            except Exception as e:
                logger.warning(f"Error analyzing {py_file}: {e}")
        
        logger.info(f"Found {len(self.modules)} modules and {len(self.classes)} classes")
        return self.modules
    
    def analyze_file(self, file_path: Path) -> Optional[ModuleInfo]:
        """Analyze a single Python file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            # Extract module name
            module_name = file_path.stem
            if file_path.parent.name != "dragonshard":
                module_name = f"{file_path.parent.name}.{module_name}"
            
            # Extract imports
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        imports.append(f"{module}.{alias.name}")
            
            # Extract classes
            classes = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_info = self._extract_class_info(node, file_path, module_name)
                    classes.append(class_info)
            
            # Extract functions
            functions = []
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Simple check: if the function is at module level (not inside a class)
                    # We'll assume it's a top-level function if we can't determine otherwise
                    functions.append(node.name)
            
            return ModuleInfo(
                name=module_name,
                file_path=str(file_path),
                classes=classes,
                functions=functions,
                imports=imports
            )
            
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None
    
    def _extract_class_info(self, node: ast.ClassDef, file_path: Path, module_name: str) -> ClassInfo:
        """Extract information about a class."""
        # Check if it's a dataclass
        is_dataclass = any(
            decorator.id == "dataclass" 
            for decorator in node.decorator_list 
            if isinstance(decorator, ast.Name)
        )
        
        # Check if it's an enum
        is_enum = any(
            base.id in ["Enum", "IntEnum", "Flag"] 
            for base in node.bases 
            if isinstance(base, ast.Name)
        )
        
        # Extract base classes
        base_classes = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                base_classes.append(base.id)
            elif isinstance(base, ast.Attribute):
                base_classes.append(f"{base.value.id}.{base.attr}")
        
        # Extract methods
        methods = []
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                methods.append(item.name)
        
        # Extract attributes (for dataclasses)
        attributes = []
        if is_dataclass:
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    attributes.append(item.target.id)
        
        # Extract docstring
        docstring = ast.get_docstring(node)
        
        return ClassInfo(
            name=node.name,
            file_path=str(file_path),
            module=module_name,
            base_classes=base_classes,
            methods=methods,
            attributes=attributes,
            docstring=docstring,
            is_dataclass=is_dataclass,
            is_enum=is_enum
        )


class ERDiagramGenerator:
    """Generates Entity-Relationship diagrams from code analysis."""
    
    def __init__(self, classes: Dict[str, ClassInfo]):
        self.classes = classes
        self.relationships: List[ERRelationship] = []
        
    def generate_relationships(self) -> List[ERRelationship]:
        """Generate relationships between entities based on code analysis."""
        relationships = []
        
        # Find dataclass relationships
        dataclasses = {name: cls for name, cls in self.classes.items() if cls.is_dataclass}
        
        for name, cls in dataclasses.items():
            # Look for relationships in attributes
            for attr in cls.attributes:
                # Check if attribute references another class
                for other_name, other_cls in dataclasses.items():
                    if other_name.lower() in attr.lower() or attr.lower() in other_name.lower():
                        if name != other_name:
                            relationships.append(ERRelationship(
                                from_entity=name,
                                to_entity=other_name,
                                relationship_type="one-to-many",
                                description=f"{name} contains {other_name}"
                            ))
        
        # Find inheritance relationships
        for name, cls in self.classes.items():
            for base in cls.base_classes:
                if base in self.classes:
                    relationships.append(ERRelationship(
                        from_entity=name,
                        to_entity=base,
                        relationship_type="inherits",
                        description=f"{name} inherits from {base}"
                    ))
        
        self.relationships = relationships
        return relationships
    
    def generate_dot(self, output_file: str = "er_diagram.dot") -> str:
        """Generate a DOT file for the ER diagram."""
        if not GRAPHVIZ_AVAILABLE:
            logger.error("Graphviz not available")
            return ""
        
        dot = graphviz.Digraph(comment='DragonShard ER Diagram')
        dot.attr(rankdir='TB')
        
        # Add entities
        for name, cls in self.classes.items():
            if cls.is_dataclass:
                # Create entity label
                label = f"{name}\\n"
                if cls.attributes:
                    label += "\\n".join([f"  {attr}" for attr in cls.attributes[:5]])
                    if len(cls.attributes) > 5:
                        label += "\\n  ..."
                
                dot.node(name, label, shape='record')
        
        # Add relationships
        for rel in self.relationships:
            if rel.relationship_type == "inherits":
                dot.edge(rel.from_entity, rel.to_entity, label="inherits", arrowhead="empty")
            else:
                dot.edge(rel.from_entity, rel.to_entity, label=rel.description)
        
        # Save DOT file
        dot.save(output_file)
        logger.info(f"ER diagram DOT file saved: {output_file}")
        return output_file
    
    def generate_svg(self, output_file: str = "er_diagram.svg") -> str:
        """Generate an SVG file for the ER diagram."""
        dot_file = self.generate_dot("temp_er.dot")
        if dot_file and GRAPHVIZ_AVAILABLE:
            try:
                import subprocess
                subprocess.run(["dot", "-Tsvg", dot_file, "-o", output_file], check=True)
                os.remove(dot_file)  # Clean up temp file
                logger.info(f"ER diagram SVG saved: {output_file}")
                return output_file
            except Exception as e:
                logger.error(f"Error generating SVG: {e}")
        return ""


class ModuleDiagramGenerator:
    """Generates module dependency diagrams."""
    
    def __init__(self, modules: Dict[str, ModuleInfo]):
        self.modules = modules
        
    def generate_dot(self, output_file: str = "module_diagram.dot") -> str:
        """Generate a DOT file for the module diagram."""
        if not GRAPHVIZ_AVAILABLE:
            logger.error("Graphviz not available")
            return ""
        
        dot = graphviz.Digraph(comment='DragonShard Module Diagram')
        dot.attr(rankdir='LR')
        
        # Group modules by directory
        module_groups = {}
        for name, module in self.modules.items():
            group = module.file_path.split('/')[1] if '/' in module.file_path else "core"
            if group not in module_groups:
                module_groups[group] = []
            module_groups[group].append(module)
        
        # Create subgraphs for each group
        for group_name, group_modules in module_groups.items():
            with dot.subgraph(name=f"cluster_{group_name}") as c:
                c.attr(label=group_name.upper())
                c.attr(style='filled')
                c.attr(color='lightgrey')
                
                for module in group_modules:
                    # Create module label
                    label = f"{module.name}\\n"
                    if module.classes:
                        label += f"Classes: {len(module.classes)}\\n"
                    if module.functions:
                        label += f"Functions: {len(module.functions)}"
                    
                    c.node(module.name, label, shape='box')
        
        # Add dependencies based on imports
        for name, module in self.modules.items():
            for imp in module.imports:
                # Check if import is from our project
                for other_name, other_module in self.modules.items():
                    if other_name in imp or imp in other_name:
                        if name != other_name:
                            dot.edge(name, other_name, style='dashed')
        
        # Save DOT file
        dot.save(output_file)
        logger.info(f"Module diagram DOT file saved: {output_file}")
        return output_file
    
    def generate_svg(self, output_file: str = "module_diagram.svg") -> str:
        """Generate an SVG file for the module diagram."""
        dot_file = self.generate_dot("temp_module.dot")
        if dot_file and GRAPHVIZ_AVAILABLE:
            try:
                import subprocess
                subprocess.run(["dot", "-Tsvg", dot_file, "-o", output_file], check=True)
                os.remove(dot_file)  # Clean up temp file
                logger.info(f"Module diagram SVG saved: {output_file}")
                return output_file
            except Exception as e:
                logger.error(f"Error generating SVG: {e}")
        return ""


class DiagramGenerator:
    """Main class for generating all diagrams."""
    
    def __init__(self, project_root: str = "dragonshard"):
        self.project_root = project_root
        self.analyzer = CodeAnalyzer(project_root)
        self.output_dir = Path("docs/diagrams")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_all_diagrams(self) -> Dict[str, str]:
        """Generate all diagrams and return file paths."""
        logger.info("Starting diagram generation...")
        
        # Analyze the codebase
        modules = self.analyzer.analyze_project()
        classes = self.analyzer.classes
        
        results = {}
        
        # Generate ER diagram
        if classes:
            er_generator = ERDiagramGenerator(classes)
            er_generator.generate_relationships()
            
            er_dot = self.output_dir / "er_diagram.dot"
            er_svg = self.output_dir / "er_diagram.svg"
            
            er_generator.generate_dot(str(er_dot))
            er_generator.generate_svg(str(er_svg))
            
            results["er_dot"] = str(er_dot)
            results["er_svg"] = str(er_svg)
        
        # Generate module diagram
        if modules:
            module_generator = ModuleDiagramGenerator(modules)
            
            module_dot = self.output_dir / "module_diagram.dot"
            module_svg = self.output_dir / "module_diagram.svg"
            
            module_generator.generate_dot(str(module_dot))
            module_generator.generate_svg(str(module_svg))
            
            results["module_dot"] = str(module_dot)
            results["module_svg"] = str(module_svg)
        
        # Generate summary JSON
        summary = {
            "modules": len(modules),
            "classes": len(classes),
            "dataclasses": len([c for c in classes.values() if c.is_dataclass]),
            "enums": len([c for c in classes.values() if c.is_enum]),
            "relationships": len(er_generator.relationships) if 'er_generator' in locals() else 0
        }
        
        summary_file = self.output_dir / "diagram_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        results["summary"] = str(summary_file)
        
        logger.info(f"Generated {len(results)} diagram files")
        return results
    
    def update_readme(self, diagram_files: Dict[str, str]) -> None:
        """Update README.md with diagram references."""
        readme_path = Path("README.md")
        if not readme_path.exists():
            logger.warning("README.md not found")
            return
        
        with open(readme_path, 'r') as f:
            content = f.read()
        
        # Check if diagrams section exists
        if "## 📊 Architecture Diagrams" not in content:
            # Add diagrams section before the Testing section
            diagrams_section = """
## 📊 Architecture Diagrams

The following diagrams are auto-generated from the codebase:

### Entity-Relationship Diagram
![ER Diagram](docs/diagrams/er_diagram.svg)

### Module Dependency Diagram  
![Module Diagram](docs/diagrams/module_diagram.svg)

*Diagrams are automatically updated during the build process.*
"""
            
            # Insert before Testing section
            if "## Testing" in content:
                content = content.replace("## Testing", f"{diagrams_section}\n## Testing")
            else:
                content += diagrams_section
        
        with open(readme_path, 'w') as f:
            f.write(content)
        
        logger.info("Updated README.md with diagram references")


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate diagrams for DragonShard")
    parser.add_argument("--project-root", default="dragonshard", help="Project root directory")
    parser.add_argument("--update-readme", action="store_true", help="Update README.md with diagram references")
    parser.add_argument("--output-dir", default="docs/diagrams", help="Output directory for diagrams")
    
    args = parser.parse_args()
    
    # Check dependencies
    if not GRAPHVIZ_AVAILABLE:
        print("❌ Graphviz is required for diagram generation")
        print("Install with: pip install graphviz")
        print("Or install system package: sudo apt-get install graphviz")
        return 1
    
    # Generate diagrams
    generator = DiagramGenerator(args.project_root)
    generator.output_dir = Path(args.output_dir)
    
    try:
        diagram_files = generator.generate_all_diagrams()
        
        print("✅ Diagram generation completed!")
        print(f"📁 Output directory: {generator.output_dir}")
        print("📊 Generated files:")
        for file_type, file_path in diagram_files.items():
            print(f"  - {file_type}: {file_path}")
        
        # Update README if requested
        if args.update_readme:
            generator.update_readme(diagram_files)
            print("📝 Updated README.md with diagram references")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error generating diagrams: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 