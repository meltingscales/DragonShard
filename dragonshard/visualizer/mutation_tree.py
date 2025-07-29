#!/usr/bin/env python3
"""
Mutation Tree Visualization Module

Provides a tree-based visualization showing the evolutionary relationships between
genetic algorithm payloads, with edges representing mutations and nodes showing
payload characteristics.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import networkx as nx
from typing import Dict, List, Any, Optional, Tuple
import json
import time
from datetime import datetime

from ..fuzzing import GeneticPayload, PayloadType, ResponseAnalyzer


class MutationNode:
    """Represents a node in the mutation tree."""
    
    def __init__(self, payload: GeneticPayload, parent_id: Optional[str] = None):
        self.payload = payload
        self.id = f"node_{payload.mutation_count}_{int(time.time() * 1000) % 10000}"
        self.parent_id = parent_id
        self.children: List[str] = []
        self.fitness_score: float = 0.0
        self.response_type: str = "unknown"
        self.mutation_type: str = "unknown"
        self.generation: int = 0
        self.successful: bool = False
        self.vulnerability_detected: bool = False
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary for serialization."""
        return {
            'id': self.id,
            'parent_id': self.parent_id,
            'payload': self.payload.payload,
            'payload_type': self.payload.payload_type.value,
            'mutation_count': self.payload.mutation_count,
            'fitness_score': self.fitness_score,
            'response_type': self.response_type,
            'mutation_type': self.mutation_type,
            'generation': self.generation,
            'successful': self.successful,
            'vulnerability_detected': self.vulnerability_detected,
            'children': self.children
        }


class MutationTreeVisualizer:
    """Tree-based visualization of genetic algorithm mutations."""
    
    def __init__(self, root: tk.Tk):
        """Initialize the mutation tree visualizer."""
        self.root = root
        self.root.title("DragonShard - Mutation Tree Visualizer")
        self.root.geometry("1400x900")
        
        # Tree data structure
        self.nodes: Dict[str, MutationNode] = {}
        self.root_node: Optional[MutationNode] = None
        self.current_generation = 0
        
        # Visualization settings
        self.layout_type = "spring"  # spring, circular, hierarchical
        self.node_size = 300
        self.edge_width = 2
        self.show_fitness = True
        self.show_vulnerabilities = True
        self.show_generations = True
        
        # Performance optimizations
        self.max_nodes_display = 200  # Limit nodes for performance
        self.update_throttle = 0.2  # seconds between updates
        self.last_update_time = 0
        self.pending_updates = False
        
        # UI components
        self.setup_ui()
        self.setup_tree_view()
        self.setup_controls()
        
        # Matplotlib figure
        self.setup_plot()
        
    def setup_ui(self):
        """Setup the main user interface."""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top control panel
        control_frame = ttk.LabelFrame(main_frame, text="Tree Controls", padding=10)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Layout selection
        ttk.Label(control_frame, text="Layout:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.layout_var = tk.StringVar(value="spring")
        layout_combo = ttk.Combobox(
            control_frame,
            textvariable=self.layout_var,
            values=["spring", "circular", "hierarchical", "kamada_kawai"],
            state="readonly",
            width=15
        )
        layout_combo.grid(row=0, column=1, padx=(0, 10))
        layout_combo.bind("<<ComboboxSelected>>", self.on_layout_change)
        
        # Display options
        ttk.Label(control_frame, text="Display:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        
        self.show_fitness_var = tk.BooleanVar(value=True)
        fitness_check = ttk.Checkbutton(
            control_frame, 
            text="Fitness", 
            variable=self.show_fitness_var,
            command=self.update_visualization
        )
        fitness_check.grid(row=0, column=3, padx=(0, 5))
        
        self.show_vuln_var = tk.BooleanVar(value=True)
        vuln_check = ttk.Checkbutton(
            control_frame, 
            text="Vulnerabilities", 
            variable=self.show_vuln_var,
            command=self.update_visualization
        )
        vuln_check.grid(row=0, column=4, padx=(0, 5))
        
        self.show_gen_var = tk.BooleanVar(value=True)
        gen_check = ttk.Checkbutton(
            control_frame, 
            text="Generations", 
            variable=self.show_gen_var,
            command=self.update_visualization
        )
        gen_check.grid(row=0, column=5, padx=(0, 10))
        
        # Performance controls
        ttk.Label(control_frame, text="Max Nodes:").grid(row=0, column=6, sticky=tk.W, padx=(0, 5))
        self.max_nodes_var = tk.StringVar(value=str(self.max_nodes_display))
        max_nodes_entry = ttk.Entry(control_frame, textvariable=self.max_nodes_var, width=8)
        max_nodes_entry.grid(row=0, column=7, padx=(0, 10))
        
        # Action buttons
        ttk.Button(control_frame, text="Clear Tree", command=self.clear_tree).grid(row=0, column=8, padx=(0, 5))
        ttk.Button(control_frame, text="Export Tree", command=self.export_tree).grid(row=0, column=9, padx=(0, 5))
        ttk.Button(control_frame, text="Find Path", command=self.find_best_path).grid(row=0, column=10, padx=(0, 5))
        
        # Split pane for tree view and visualization
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Tree view
        left_frame = ttk.Frame(paned_window)
        paned_window.add(left_frame, weight=1)
        
        # Right panel - Graph visualization
        right_frame = ttk.Frame(paned_window)
        paned_window.add(right_frame, weight=2)
        
        self.left_frame = left_frame
        self.right_frame = right_frame
        
    def setup_tree_view(self):
        """Setup the tree view panel."""
        # Tree view frame
        tree_frame = ttk.LabelFrame(self.left_frame, text="Mutation Tree", padding=5)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Tree view
        columns = ("ID", "Payload", "Type", "Fitness", "Vuln", "Gen")
        self.tree_view = ttk.Treeview(tree_frame, columns=columns, show="tree headings", height=20)
        
        # Configure columns
        self.tree_view.heading("#0", text="Tree")
        self.tree_view.column("#0", width=150)
        
        for col in columns:
            self.tree_view.heading(col, text=col)
            self.tree_view.column(col, width=80)
        
        # Scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree_view.yview)
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree_view.xview)
        self.tree_view.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        # Pack tree view and scrollbars
        self.tree_view.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind selection event
        self.tree_view.bind("<<TreeviewSelect>>", self.on_node_select)
        
    def setup_controls(self):
        """Setup additional controls."""
        # Control panel below tree view
        control_panel = ttk.Frame(self.left_frame)
        control_panel.pack(fill=tk.X, pady=(5, 0))
        
        # Statistics
        stats_frame = ttk.LabelFrame(control_panel, text="Statistics", padding=5)
        stats_frame.pack(fill=tk.X)
        
        self.stats_text = tk.Text(stats_frame, height=8, width=50)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
    def setup_plot(self):
        """Setup the matplotlib plot."""
        # Create figure
        self.fig = Figure(figsize=(10, 8), dpi=100)
        self.ax = self.fig.add_subplot(111)
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, self.right_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initial plot
        self.update_visualization()
        
    def add_node(self, payload: GeneticPayload, parent_id: Optional[str] = None, 
                 fitness_score: float = 0.0, response_type: str = "unknown",
                 mutation_type: str = "unknown", successful: bool = False,
                 vulnerability_detected: bool = False) -> str:
        """Add a new node to the mutation tree."""
        node = MutationNode(payload, parent_id)
        node.fitness_score = fitness_score
        node.response_type = response_type
        node.mutation_type = mutation_type
        node.generation = self.current_generation
        node.successful = successful
        node.vulnerability_detected = vulnerability_detected
        
        # Add to nodes dictionary
        self.nodes[node.id] = node
        
        # Set as root if no parent
        if parent_id is None:
            self.root_node = node
        else:
            # Add to parent's children
            if parent_id in self.nodes:
                self.nodes[parent_id].children.append(node.id)
        
        # Throttled updates for performance
        current_time = time.time()
        if current_time - self.last_update_time > self.update_throttle:
            self.update_tree_view()
            self.update_visualization()
            self.last_update_time = current_time
            self.pending_updates = False
        else:
            # Schedule update if not already pending
            if not self.pending_updates:
                self.root.after(int(self.update_throttle * 1000), self._perform_pending_updates)
                self.pending_updates = True
        
        return node.id
        
    def _perform_pending_updates(self):
        """Perform pending updates after throttling."""
        self.update_tree_view()
        self.update_visualization()
        self.last_update_time = time.time()
        self.pending_updates = False
        
    def update_tree_view(self):
        """Update the tree view with current nodes."""
        # Clear existing items
        for item in self.tree_view.get_children():
            self.tree_view.delete(item)
        
        # Add nodes to tree view
        for node_id, node in self.nodes.items():
            parent = "" if node.parent_id is None else node.parent_id
            
            # Truncate payload for display
            payload_display = node.payload.payload[:30] + "..." if len(node.payload.payload) > 30 else node.payload.payload
            
            # Color coding for vulnerabilities
            tags = ()
            if node.vulnerability_detected:
                tags = ("vulnerable",)
            elif node.successful:
                tags = ("successful",)
            
            self.tree_view.insert(
                parent, "end", node_id,
                text=f"{node_id}",
                values=(
                    node_id,
                    payload_display,
                    node.payload.payload_type.value,
                    f"{node.fitness_score:.3f}",
                    "✓" if node.vulnerability_detected else "",
                    node.generation
                ),
                tags=tags
            )
        
        # Configure tag colors
        self.tree_view.tag_configure("vulnerable", background="red")
        self.tree_view.tag_configure("successful", background="green")
        
    def update_visualization(self):
        """Update the graph visualization."""
        if not self.nodes:
            self.ax.clear()
            self.ax.text(0.5, 0.5, "No mutations to display", 
                        ha='center', va='center', transform=self.ax.transAxes)
            self.canvas.draw()
            return
        
        # Limit nodes for performance
        max_nodes = int(self.max_nodes_var.get())
        if len(self.nodes) > max_nodes:
            # Show only the most recent nodes
            sorted_nodes = sorted(self.nodes.values(), key=lambda n: n.generation, reverse=True)
            display_nodes = sorted_nodes[:max_nodes]
        else:
            display_nodes = list(self.nodes.values())
        
        # Create NetworkX graph
        G = nx.DiGraph()
        
        # Add nodes
        for node in display_nodes:
            G.add_node(node.id, 
                      payload=node.payload.payload,
                      fitness=node.fitness_score,
                      generation=node.generation,
                      vulnerable=node.vulnerability_detected,
                      successful=node.successful,
                      mutation_type=node.mutation_type)
        
        # Add edges (only for displayed nodes)
        for node in display_nodes:
            if node.parent_id and node.parent_id in self.nodes:
                G.add_edge(node.parent_id, node.id)
        
        # Clear plot
        self.ax.clear()
        
        # Choose layout
        layout_type = self.layout_var.get()
        try:
            if layout_type == "spring":
                pos = nx.spring_layout(G, k=1, iterations=30)  # Reduced iterations for speed
            elif layout_type == "circular":
                pos = nx.circular_layout(G)
            elif layout_type == "hierarchical":
                pos = nx.kamada_kawai_layout(G)
            else:
                pos = nx.kamada_kawai_layout(G)
        except ImportError:
            # Fallback to spring layout if scipy is not available
            pos = nx.spring_layout(G, k=1, iterations=30)
        except Exception as e:
            # Fallback to circular layout for any other errors
            pos = nx.circular_layout(G)
        
        # Node colors based on characteristics
        node_colors = []
        node_sizes = []
        
        for node_id in G.nodes():
            node_data = G.nodes[node_id]
            
            # Color based on vulnerability detection
            if node_data['vulnerable']:
                node_colors.append('red')
                node_sizes.append(500)
            elif node_data['successful']:
                node_colors.append('green')
                node_sizes.append(400)
            else:
                node_colors.append('lightblue')
                node_sizes.append(300)
        
        # Draw the graph
        nx.draw(G, pos, ax=self.ax,
                node_color=node_colors,
                node_size=node_sizes,
                edge_color='gray',
                width=1,
                arrows=True,
                arrowsize=10,
                with_labels=True,
                font_size=8,
                font_weight='bold')
        
        # Add labels if requested
        if self.show_fitness_var.get():
            labels = {node: f"{G.nodes[node]['fitness']:.2f}" for node in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels, font_size=6, font_color='black')
        
        self.ax.set_title(f"Mutation Tree (Generation {self.current_generation}) - {len(display_nodes)}/{len(self.nodes)} nodes")
        self.canvas.draw()
        
        # Update statistics
        self.update_statistics()
        
    def update_statistics(self):
        """Update the statistics display."""
        if not self.nodes:
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, "No mutations recorded")
            return
        
        # Calculate statistics
        total_nodes = len(self.nodes)
        vulnerable_nodes = sum(1 for node in self.nodes.values() if node.vulnerability_detected)
        successful_nodes = sum(1 for node in self.nodes.values() if node.successful)
        max_generation = max(node.generation for node in self.nodes.values())
        
        # Fitness statistics
        fitness_scores = [node.fitness_score for node in self.nodes.values()]
        avg_fitness = sum(fitness_scores) / len(fitness_scores) if fitness_scores else 0
        max_fitness = max(fitness_scores) if fitness_scores else 0
        
        # Mutation type distribution
        mutation_types = {}
        for node in self.nodes.values():
            mutation_types[node.mutation_type] = mutation_types.get(node.mutation_type, 0) + 1
        
        # Generate statistics text
        stats_text = f"""Mutation Tree Statistics
=======================

Total Nodes: {total_nodes}
Generations: {max_generation + 1}
Vulnerable Nodes: {vulnerable_nodes}
Successful Nodes: {successful_nodes}

Fitness Statistics:
- Average: {avg_fitness:.3f}
- Maximum: {max_fitness:.3f}

Mutation Types:
"""
        for mutation_type, count in mutation_types.items():
            stats_text += f"- {mutation_type}: {count}\n"
        
        # Clear and update
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text)
        
    def on_layout_change(self, event=None):
        """Handle layout change."""
        self.update_visualization()
        
    def on_node_select(self, event=None):
        """Handle node selection in tree view."""
        selection = self.tree_view.selection()
        if selection:
            node_id = selection[0]
            if node_id in self.nodes:
                node = self.nodes[node_id]
                self.show_node_details(node)
                
    def show_node_details(self, node: MutationNode):
        """Show detailed information about a selected node."""
        details = f"""Node Details: {node.id}
====================

Payload: {node.payload.payload}
Type: {node.payload.payload_type.value}
Generation: {node.generation}
Fitness Score: {node.fitness_score:.3f}
Response Type: {node.response_type}
Mutation Type: {node.mutation_type}
Successful: {node.successful}
Vulnerability Detected: {node.vulnerability_detected}

Parent: {node.parent_id or "Root"}
Children: {len(node.children)}
"""
        
        # Create a new window for details
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Node Details - {node.id}")
        detail_window.geometry("600x400")
        
        text_widget = tk.Text(detail_window, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, details)
        text_widget.config(state=tk.DISABLED)
        
    def clear_tree(self):
        """Clear the mutation tree."""
        self.nodes.clear()
        self.root_node = None
        self.current_generation = 0
        self.update_tree_view()
        self.update_visualization()
        
    def export_tree(self):
        """Export the mutation tree to JSON."""
        if not self.nodes:
            messagebox.showwarning("Export", "No tree data to export")
            return
            
        # Convert tree to dictionary
        tree_data = {
            'timestamp': datetime.now().isoformat(),
            'total_nodes': len(self.nodes),
            'generations': self.current_generation + 1,
            'nodes': {node_id: node.to_dict() for node_id, node in self.nodes.items()}
        }
        
        # Save to file
        filename = f"mutation_tree_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(tree_data, f, indent=2)
            
        messagebox.showinfo("Export", f"Tree exported to {filename}")
        
    def find_best_path(self):
        """Find and highlight the best path to a vulnerable node."""
        if not self.nodes:
            messagebox.showwarning("Path Finding", "No tree data available")
            return
            
        # Find vulnerable nodes
        vulnerable_nodes = [node_id for node_id, node in self.nodes.items() 
                          if node.vulnerability_detected]
        
        if not vulnerable_nodes:
            messagebox.showinfo("Path Finding", "No vulnerable nodes found")
            return
            
        # Find the best vulnerable node (highest fitness)
        best_vulnerable = max(vulnerable_nodes, 
                            key=lambda node_id: self.nodes[node_id].fitness_score)
        
        # Find path to root
        path = []
        current = best_vulnerable
        while current in self.nodes:
            path.append(current)
            current = self.nodes[current].parent_id
            if current is None:
                break
                
        path.reverse()
        
        # Highlight path in tree view
        self.tree_view.selection_set(path)
        
        # Show path details
        path_details = f"Best Path to Vulnerability:\n"
        path_details += f"Target Node: {best_vulnerable}\n"
        path_details += f"Fitness: {self.nodes[best_vulnerable].fitness_score:.3f}\n"
        path_details += f"Path Length: {len(path)}\n\n"
        path_details += "Path:\n"
        
        for i, node_id in enumerate(path):
            node = self.nodes[node_id]
            path_details += f"{i+1}. {node_id} -> {node.payload.payload[:50]}...\n"
            
        messagebox.showinfo("Best Path", path_details)
        
    def next_generation(self):
        """Move to the next generation."""
        self.current_generation += 1


def main():
    """Main function to run the mutation tree visualizer."""
    root = tk.Tk()
    app = MutationTreeVisualizer(root)
    root.mainloop()


if __name__ == "__main__":
    main() 