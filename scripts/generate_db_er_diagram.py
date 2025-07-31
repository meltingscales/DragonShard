#!/usr/bin/env python3
"""
DragonShard Database ER Diagram Generator

This script generates Entity-Relationship diagrams specifically for the database schema
by analyzing SQLAlchemy models. It creates both DOT and SVG formats.
"""

import ast
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
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

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class ColumnInfo:
    """Information about a database column."""
    name: str
    type: str
    nullable: bool
    primary_key: bool
    foreign_key: Optional[str] = None
    default: Optional[str] = None
    unique: bool = False
    index: bool = False


@dataclass
class TableInfo:
    """Information about a database table."""
    name: str
    columns: List[ColumnInfo]
    relationships: List[str]  # List of relationship method names
    docstring: Optional[str] = None


@dataclass
class RelationshipInfo:
    """Information about a database relationship."""
    from_table: str
    to_table: str
    relationship_type: str  # "one-to-many", "many-to-many", "one-to-one"
    foreign_key: str
    description: str


class DatabaseModelAnalyzer:
    """Analyzes SQLAlchemy models to extract database schema information."""
    
    def __init__(self, models_file: str = "dragonshard/data/models.py"):
        self.models_file = Path(models_file)
        self.tables: Dict[str, TableInfo] = {}
        self.relationships: List[RelationshipInfo] = []
        
    def analyze_models(self) -> Dict[str, TableInfo]:
        """Analyze the SQLAlchemy models file and extract table information."""
        if not self.models_file.exists():
            logger.error(f"Models file not found: {self.models_file}")
            return {}
        
        try:
            with open(self.models_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            # Find all classes that inherit from Base
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    if self._is_sqlalchemy_model(node):
                        logger.debug(f"Found SQLAlchemy model: {node.name}")
                        table_info = self._extract_table_info(node)
                        if table_info:
                            self.tables[table_info.name] = table_info
                            logger.debug(f"Extracted table: {table_info.name} with {len(table_info.columns)} columns")
                        else:
                            logger.debug(f"Failed to extract table info for {node.name}")
            
            # Extract relationships
            self._extract_relationships()
            
            logger.info(f"Found {len(self.tables)} database tables")
            return self.tables
            
        except Exception as e:
            logger.error(f"Error analyzing models: {e}")
            return {}
    
    def _is_sqlalchemy_model(self, node: ast.ClassDef) -> bool:
        """Check if a class is a SQLAlchemy model (inherits from Base)."""
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id == "Base":
                return True
            elif isinstance(base, ast.Attribute) and base.attr == "Base":
                return True
        return False
    
    def _extract_table_info(self, node: ast.ClassDef) -> Optional[TableInfo]:
        """Extract table information from a SQLAlchemy model class."""
        # Get table name
        table_name = None
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and target.id == "__tablename__":
                        if isinstance(item.value, ast.Constant):
                            table_name = item.value.value
                            break
        
        if not table_name:
            return None
        
        # Extract columns
        columns = []
        relationships = []
        
        for item in node.body:
            if isinstance(item, ast.Assign):
                logger.debug(f"Found assignment: {item.targets[0].id} = {type(item.value).__name__}")
                # Look for Column definitions
                if isinstance(item.value, ast.Call):
                    func = item.value.func
                    logger.debug(f"Call function: {type(func).__name__} - {getattr(func, 'attr', getattr(func, 'id', 'unknown'))}")
                    if (isinstance(func, ast.Attribute) and func.attr == "Column") or (isinstance(func, ast.Name) and func.id == "Column"):
                        logger.debug(f"Found Column definition: {item.targets[0].id}")
                        column_info = self._extract_column_info(item)
                        if column_info:
                            columns.append(column_info)
                            logger.debug(f"Extracted column: {column_info.name} ({column_info.type})")
                        else:
                            logger.debug(f"Failed to extract column info for {item.targets[0].id}")
                # Also look for direct column assignments (like String(255))
                elif isinstance(item.value, ast.Call):
                    func = item.value.func
                    if isinstance(func, ast.Name) and func.id in ["String", "Integer", "Float", "Boolean", "Text", "DateTime"]:
                        column_info = self._extract_simple_column_info(item)
                        if column_info:
                            columns.append(column_info)
            
            elif isinstance(item, ast.FunctionDef):
                # Look for relationship methods
                if item.name.startswith("relationship") or "relationship" in ast.unparse(item):
                    relationships.append(item.name)
        
        # Extract docstring
        docstring = ast.get_docstring(node)
        
        return TableInfo(
            name=table_name,
            columns=columns,
            relationships=relationships,
            docstring=docstring
        )
    
    def _extract_column_info(self, item: ast.Assign) -> Optional[ColumnInfo]:
        """Extract column information from a Column definition."""
        try:
            # Get column name
            column_name = item.targets[0].id
            
            # Analyze Column arguments
            args = item.value.args
            kwargs = {}
            for keyword in item.value.keywords:
                kwargs[keyword.arg] = keyword.value
            
            # Determine column type from first argument
            column_type = "Unknown"
            if args:
                arg = args[0]
                if isinstance(arg, ast.Name):
                    column_type = arg.id
                elif isinstance(arg, ast.Attribute):
                    column_type = f"{arg.value.id}.{arg.attr}"
                elif isinstance(arg, ast.Call):
                    if isinstance(arg.func, ast.Name):
                        column_type = arg.func.id
                    elif isinstance(arg.func, ast.Attribute):
                        column_type = f"{arg.func.value.id}.{arg.func.attr}"
                elif isinstance(arg, ast.Constant):
                    column_type = str(arg.value)
            
            # Check for primary key
            primary_key = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in item.value.keywords
                if kw.arg == "primary_key"
            )
            
            # Check for nullable
            nullable = True
            for kw in item.value.keywords:
                if kw.arg == "nullable":
                    if isinstance(kw.value, ast.Constant):
                        nullable = kw.value.value
                    break
            
            # Check for foreign key
            foreign_key = None
            for kw in item.value.keywords:
                if kw.arg == "ForeignKey":
                    if isinstance(kw.value, ast.Constant):
                        foreign_key = kw.value.value
                    break
            
            # Check for unique
            unique = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in item.value.keywords
                if kw.arg == "unique"
            )
            
            # Check for index
            index = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in item.value.keywords
                if kw.arg == "index"
            )
            
            # Also check for ForeignKey in positional arguments
            if not foreign_key:
                for arg in args[1:]:  # Skip the first arg (type)
                    if isinstance(arg, ast.Call):
                        if isinstance(arg.func, ast.Name) and arg.func.id == "ForeignKey":
                            if arg.args and isinstance(arg.args[0], ast.Constant):
                                foreign_key = arg.args[0].value
            
            return ColumnInfo(
                name=column_name,
                type=column_type,
                nullable=nullable,
                primary_key=primary_key,
                foreign_key=foreign_key,
                unique=unique,
                index=index
            )
            
        except Exception as e:
            logger.warning(f"Error extracting column info: {e}")
            return None
    
    def _extract_simple_column_info(self, item: ast.Assign) -> Optional[ColumnInfo]:
        """Extract column information from a simple column definition (e.g., String(255))."""
        try:
            # Get column name
            column_name = item.targets[0].id
            
            # Get column type
            func = item.value.func
            if isinstance(func, ast.Name):
                column_type = func.id
            else:
                column_type = "Unknown"
            
            # Check for primary key (look for primary_key=True in the same class)
            primary_key = False
            nullable = True
            foreign_key = None
            unique = False
            index = False
            
            return ColumnInfo(
                name=column_name,
                type=column_type,
                nullable=nullable,
                primary_key=primary_key,
                foreign_key=foreign_key,
                unique=unique,
                index=index
            )
            
        except Exception as e:
            logger.warning(f"Error extracting simple column info: {e}")
            return None
    
    def _extract_relationships(self) -> None:
        """Extract relationships between tables based on foreign keys."""
        for table_name, table_info in self.tables.items():
            for column in table_info.columns:
                if column.foreign_key:
                    # Parse foreign key reference
                    # Format: "table.column" or just "table"
                    if "." in column.foreign_key:
                        ref_table, ref_column = column.foreign_key.split(".", 1)
                    else:
                        ref_table = column.foreign_key
                        ref_column = "id"  # Assume primary key
                    
                    # Determine relationship type
                    relationship_type = "many-to-one"
                    if column.primary_key:
                        relationship_type = "one-to-one"
                    
                    # Check if this is part of a many-to-many relationship
                    # Look for association tables
                    if "vulnerabilities" in table_name.lower() and "host" in ref_table.lower():
                        relationship_type = "many-to-many"
                    
                    self.relationships.append(RelationshipInfo(
                        from_table=table_name,
                        to_table=ref_table,
                        relationship_type=relationship_type,
                        foreign_key=column.name,
                        description=f"{table_name}.{column.name} -> {ref_table}.{ref_column}"
                    ))


class DatabaseERDiagramGenerator:
    """Generates ER diagrams specifically for database schemas."""
    
    def __init__(self, tables: Dict[str, TableInfo], relationships: List[RelationshipInfo]):
        self.tables = tables
        self.relationships = relationships
        
    def generate_dot(self, output_file: str = "db_er_diagram.dot") -> str:
        """Generate a DOT file for the database ER diagram."""
        if not GRAPHVIZ_AVAILABLE:
            logger.error("Graphviz not available")
            return ""
        
        dot = graphviz.Digraph(comment='DragonShard Database ER Diagram')
        dot.attr(rankdir='TB')
        dot.attr('node', shape='record', style='filled', fillcolor='lightblue')
        
        # Add tables
        for table_name, table_info in self.tables.items():
            # Create table label with columns
            label = f"{{ {table_name} |"
            
            # Add primary key columns first
            pk_columns = [col for col in table_info.columns if col.primary_key]
            for col in pk_columns:
                label += f" {col.name} ({col.type}) PK\\l"
            
            # Add foreign key columns
            fk_columns = [col for col in table_info.columns if col.foreign_key and not col.primary_key]
            for col in fk_columns:
                label += f" {col.name} ({col.type}) FK\\l"
            
            # Add other columns (limit to first 5 to keep diagram readable)
            other_columns = [col for col in table_info.columns 
                           if not col.primary_key and not col.foreign_key]
            for col in other_columns[:5]:
                nullable = "" if col.nullable else " NOT NULL"
                label += f" {col.name} ({col.type}){nullable}\\l"
            
            if len(other_columns) > 5:
                label += f" ... ({len(other_columns) - 5} more)\\l"
            
            label += "}"
            
            dot.node(table_name, label)
        
        # Add relationships
        for rel in self.relationships:
            if rel.from_table in self.tables and rel.to_table in self.tables:
                if rel.relationship_type == "many-to-one":
                    dot.edge(rel.from_table, rel.to_table, 
                            label=f"FK: {rel.foreign_key}", 
                            arrowhead="crow", arrowsize="2")
                elif rel.relationship_type == "one-to-one":
                    dot.edge(rel.from_table, rel.to_table, 
                            label=f"FK: {rel.foreign_key}", 
                            arrowhead="tee", arrowsize="2")
                elif rel.relationship_type == "many-to-many":
                    dot.edge(rel.from_table, rel.to_table, 
                            label=f"FK: {rel.foreign_key}", 
                            arrowhead="crow", arrowsize="2")
        
        # Save DOT file
        dot.save(output_file)
        logger.info(f"Database ER diagram DOT file saved: {output_file}")
        return output_file
    
    def generate_svg(self, output_file: str = "db_er_diagram.svg") -> str:
        """Generate an SVG file for the database ER diagram."""
        dot_file = self.generate_dot("temp_db_er.dot")
        if dot_file and GRAPHVIZ_AVAILABLE:
            try:
                import subprocess
                subprocess.run(["dot", "-Tsvg", dot_file, "-o", output_file], check=True)
                os.remove(dot_file)  # Clean up temp file
                logger.info(f"Database ER diagram SVG saved: {output_file}")
                return output_file
            except Exception as e:
                logger.error(f"Error generating SVG: {e}")
        return ""


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate database ER diagrams for DragonShard")
    parser.add_argument("--models-file", default="dragonshard/data/models.py", 
                       help="Path to SQLAlchemy models file")
    parser.add_argument("--output-dir", default="docs/diagrams", 
                       help="Output directory for diagrams")
    parser.add_argument("--update-readme", action="store_true", 
                       help="Update README.md with diagram references")
    
    args = parser.parse_args()
    
    # Check dependencies
    if not GRAPHVIZ_AVAILABLE:
        print("❌ Graphviz is required for diagram generation")
        print("Install with: pip install graphviz")
        print("Or install system package: sudo apt-get install graphviz")
        return 1
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Analyze database models
    analyzer = DatabaseModelAnalyzer(args.models_file)
    tables = analyzer.analyze_models()
    
    if not tables:
        print("❌ No database tables found")
        return 1
    
    # Generate ER diagram
    generator = DatabaseERDiagramGenerator(tables, analyzer.relationships)
    
    # Generate files
    dot_file = output_dir / "db_er_diagram.dot"
    svg_file = output_dir / "db_er_diagram.svg"
    
    generator.generate_dot(str(dot_file))
    generator.generate_svg(str(svg_file))
    
    # Generate summary
    summary = {
        "tables": len(tables),
        "relationships": len(analyzer.relationships),
        "columns": sum(len(table.columns) for table in tables.values()),
        "primary_keys": sum(len([col for col in table.columns if col.primary_key]) 
                          for table in tables.values()),
        "foreign_keys": sum(len([col for col in table.columns if col.foreign_key]) 
                          for table in tables.values())
    }
    
    summary_file = output_dir / "db_diagram_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("✅ Database ER diagram generation completed!")
    print(f"📁 Output directory: {output_dir}")
    print(f"📊 Generated files:")
    print(f"  - DOT: {dot_file}")
    print(f"  - SVG: {svg_file}")
    print(f"  - Summary: {summary_file}")
    print(f"📋 Database schema summary:")
    print(f"  - Tables: {summary['tables']}")
    print(f"  - Relationships: {summary['relationships']}")
    print(f"  - Columns: {summary['columns']}")
    print(f"  - Primary Keys: {summary['primary_keys']}")
    print(f"  - Foreign Keys: {summary['foreign_keys']}")
    
    # Update README if requested
    if args.update_readme:
        update_readme_with_db_diagram(svg_file)
        print("📝 Updated README.md with database diagram reference")
    
    return 0


def update_readme_with_db_diagram(svg_file: Path) -> None:
    """Update README.md with database ER diagram reference."""
    readme_path = Path("README.md")
    if not readme_path.exists():
        logger.warning("README.md not found")
        return
    
    with open(readme_path, 'r') as f:
        content = f.read()
    
    # Check if database diagram section exists
    if "### Database Schema Diagram" not in content:
        # Add database diagram section after the existing diagrams
        db_diagram_section = """
### Database Schema Diagram
![Database ER Diagram](docs/diagrams/db_er_diagram.svg)

*Database schema diagram showing tables, relationships, and constraints.*
"""
        
        # Insert after existing diagrams section
        if "### Module Dependency Diagram" in content:
            content = content.replace(
                "### Module Dependency Diagram", 
                "### Module Dependency Diagram" + db_diagram_section
            )
        else:
            # Add to the end if no existing diagrams section
            content += db_diagram_section
    
    with open(readme_path, 'w') as f:
        f.write(content)
    
    logger.info("Updated README.md with database diagram reference")


if __name__ == "__main__":
    sys.exit(main()) 