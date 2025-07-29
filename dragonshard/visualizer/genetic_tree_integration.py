#!/usr/bin/env python3
"""
Genetic Algorithm Tree Integration

Connects the genetic algorithm to the mutation tree visualizer for real-time
visualization of the evolutionary process.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from typing import Dict, List, Any, Optional
import queue

from .mutation_tree import MutationTreeVisualizer, MutationNode
from ..fuzzing import GeneticMutator, GeneticPayload, PayloadType, ResponseAnalyzer


class GeneticTreeIntegration:
    """Integrates genetic algorithm with tree visualization."""
    
    def __init__(self, root: tk.Tk):
        """Initialize the genetic tree integration."""
        self.root = root
        self.root.title("DragonShard - Genetic Algorithm Tree Integration")
        self.root.geometry("1600x1000")
        
        # Genetic algorithm components
        self.mutator: Optional[GeneticMutator] = None
        self.response_analyzer: Optional[ResponseAnalyzer] = None
        
        # Tree visualizer
        self.tree_visualizer: Optional[MutationTreeVisualizer] = None
        
        # Control variables
        self.running = False
        self.target_url = "http://localhost:8082"
        self.payload_type = PayloadType.SQL_INJECTION
        self.population_size = 20
        self.max_generations = 10
        
        # Threading
        self.evolution_thread: Optional[threading.Thread] = None
        self.update_queue = queue.Queue()
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface."""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Genetic Algorithm Controls", padding=10)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Target URL
        ttk.Label(control_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.url_var = tk.StringVar(value=self.target_url)
        self.url_entry = ttk.Entry(control_frame, textvariable=self.url_var, width=40)
        self.url_entry.grid(row=0, column=1, padx=(0, 10))
        
        # Payload type
        ttk.Label(control_frame, text="Payload Type:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.payload_type_var = tk.StringVar(value="SQL_INJECTION")
        payload_combo = ttk.Combobox(
            control_frame,
            textvariable=self.payload_type_var,
            values=["SQL_INJECTION", "XSS", "COMMAND_INJECTION", "PATH_TRAVERSAL"],
            state="readonly",
            width=15
        )
        payload_combo.grid(row=0, column=3, padx=(0, 10))
        
        # Population size
        ttk.Label(control_frame, text="Population:").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        self.population_var = tk.StringVar(value=str(self.population_size))
        population_entry = ttk.Entry(control_frame, textvariable=self.population_var, width=8)
        population_entry.grid(row=0, column=5, padx=(0, 10))
        
        # Max generations
        ttk.Label(control_frame, text="Generations:").grid(row=0, column=6, sticky=tk.W, padx=(0, 5))
        self.generations_var = tk.StringVar(value=str(self.max_generations))
        generations_entry = ttk.Entry(control_frame, textvariable=self.generations_var, width=8)
        generations_entry.grid(row=0, column=7, padx=(0, 10))
        
        # Control buttons
        self.start_button = ttk.Button(control_frame, text="Start Evolution", command=self.start_evolution)
        self.start_button.grid(row=0, column=8, padx=(0, 5))
        
        self.stop_button = ttk.Button(control_frame, text="Stop Evolution", command=self.stop_evolution, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=9, padx=(0, 5))
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(control_frame, textvariable=self.status_var, foreground="blue")
        status_label.grid(row=0, column=10, padx=(10, 0))
        
        # Progress frame
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Progress bar
        ttk.Label(progress_frame, text="Progress:").pack(side=tk.LEFT)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        # Split pane for tree and details
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Tree visualizer
        left_frame = ttk.Frame(paned_window)
        paned_window.add(left_frame, weight=2)
        
        # Right panel - Details and logs
        right_frame = ttk.Frame(paned_window)
        paned_window.add(right_frame, weight=1)
        
        # Initialize tree visualizer
        self.tree_visualizer = MutationTreeVisualizer(left_frame)
        
        # Setup details panel
        self.setup_details_panel(right_frame)
        
    def setup_details_panel(self, parent):
        """Setup the details and logs panel."""
        # Details frame
        details_frame = ttk.LabelFrame(parent, text="Evolution Details", padding=5)
        details_frame.pack(fill=tk.BOTH, expand=True)
        
        # Current generation
        gen_frame = ttk.Frame(details_frame)
        gen_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(gen_frame, text="Generation:").pack(side=tk.LEFT)
        self.gen_var = tk.StringVar(value="0")
        ttk.Label(gen_frame, textvariable=self.gen_var, font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=(5, 0))
        
        # Best fitness
        fitness_frame = ttk.Frame(details_frame)
        fitness_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(fitness_frame, text="Best Fitness:").pack(side=tk.LEFT)
        self.best_fitness_var = tk.StringVar(value="0.000")
        ttk.Label(fitness_frame, textvariable=self.best_fitness_var, font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=(5, 0))
        
        # Vulnerabilities found
        vuln_frame = ttk.Frame(details_frame)
        vuln_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(vuln_frame, text="Vulnerabilities:").pack(side=tk.LEFT)
        self.vuln_count_var = tk.StringVar(value="0")
        ttk.Label(vuln_frame, textvariable=self.vuln_count_var, font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=(5, 0))
        
        # Log frame
        log_frame = ttk.LabelFrame(details_frame, text="Evolution Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        # Log text widget
        self.log_text = tk.Text(log_frame, height=15, width=50)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
    def log_message(self, message: str):
        """Add a message to the log."""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Update log in main thread
        self.root.after(0, lambda: self._update_log(log_entry))
        
    def _update_log(self, message: str):
        """Update the log text widget (called in main thread)."""
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)
        
    def start_evolution(self):
        """Start the genetic evolution process."""
        if self.running:
            return
            
        # Get parameters
        try:
            self.target_url = self.url_var.get()
            payload_type_str = self.payload_type_var.get()
            self.payload_type = PayloadType[payload_type_str]
            self.population_size = int(self.population_var.get())
            self.max_generations = int(self.generations_var.get())
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid parameter: {e}")
            return
            
        # Initialize components
        self.response_analyzer = ResponseAnalyzer()
        self.mutator = GeneticMutator(
            population_size=self.population_size,
            max_generations=self.max_generations,
            response_analyzer=self.response_analyzer
        )
        
        # Clear tree
        self.tree_visualizer.clear_tree()
        
        # Update UI
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set("Running")
        self.progress_var.set(0)
        
        # Start evolution thread
        self.evolution_thread = threading.Thread(target=self.run_evolution, daemon=True)
        self.evolution_thread.start()
        
        # Start update loop
        self.update_loop()
        
    def stop_evolution(self):
        """Stop the genetic evolution process."""
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Stopped")
        
    def run_evolution(self):
        """Run the genetic evolution in a separate thread."""
        try:
            self.log_message("Starting genetic evolution...")
            
            # Initialize population
            base_payloads = self.get_base_payloads(self.payload_type)
            self.mutator.initialize_population(base_payloads)
            
            # Add initial population to tree
            for payload in self.mutator.population:
                self.add_payload_to_tree(payload, parent_id=None)
            
            self.log_message(f"Initialized population with {len(self.mutator.population)} individuals")
            
            # Run evolution
            for generation in range(self.max_generations):
                if not self.running:
                    break
                    
                self.log_message(f"Starting generation {generation + 1}")
                
                # Evaluate current population
                self.evaluate_population()
                
                # Get best payloads
                best_payloads = self.mutator.get_best_payloads()
                if best_payloads:
                    best_fitness = max(p.fitness_score for p in best_payloads)
                    self.log_message(f"Best fitness: {best_fitness:.3f}")
                
                # Evolve population
                self.mutator.evolve()
                
                # Update tree with new population
                for payload in self.mutator.population:
                    self.add_payload_to_tree(payload, parent_id=None)
                
                # Update progress
                progress = ((generation + 1) / self.max_generations) * 100
                self.root.after(0, lambda p=progress: self.progress_var.set(p))
                
                # Update generation counter
                self.tree_visualizer.next_generation()
                
                time.sleep(0.1)  # Small delay for visualization
                
            self.log_message("Evolution completed")
            
        except Exception as e:
            self.log_message(f"Error during evolution: {e}")
            
        finally:
            self.root.after(0, self.stop_evolution)
            
    def evaluate_population(self):
        """Evaluate the current population."""
        for payload in self.mutator.population:
            # Simulate evaluation (in real implementation, this would make HTTP requests)
            # For now, we'll use a simple fitness function
            payload.fitness_score = self.calculate_fitness(payload)
            
            # Determine response type and vulnerability detection
            if payload.fitness_score > 0.8:
                payload.response_type = "vulnerability"
                payload.vulnerability_detected = True
            elif payload.fitness_score > 0.5:
                payload.response_type = "anomaly"
                payload.vulnerability_detected = False
            else:
                payload.response_type = "normal"
                payload.vulnerability_detected = False
                
    def calculate_fitness(self, payload: GeneticPayload) -> float:
        """Calculate fitness for a payload."""
        # Simple fitness function based on payload characteristics
        fitness = 0.0
        
        # Base fitness from payload type
        if payload.payload_type == PayloadType.SQL_INJECTION:
            if any(keyword in payload.payload.lower() for keyword in ['union', 'select', 'or', 'and']):
                fitness += 0.3
        elif payload.payload_type == PayloadType.XSS:
            if any(keyword in payload.payload.lower() for keyword in ['script', 'alert', 'onload']):
                fitness += 0.3
                
        # Fitness based on mutation count (more mutations = potentially more interesting)
        fitness += min(payload.mutation_count * 0.1, 0.3)
        
        # Add some randomness
        import random
        fitness += random.random() * 0.2
        
        return min(fitness, 1.0)
        
    def add_payload_to_tree(self, payload: GeneticPayload, parent_id: Optional[str] = None):
        """Add a payload to the mutation tree."""
        # Determine mutation type
        mutation_type = "initial"
        if payload.mutation_count > 0:
            if payload.payload_type == PayloadType.SQL_INJECTION:
                mutation_type = "sql_mutation"
            elif payload.payload_type == PayloadType.XSS:
                mutation_type = "xss_mutation"
            else:
                mutation_type = "general_mutation"
                
        # Add to tree
        node_id = self.tree_visualizer.add_node(
            payload=payload,
            parent_id=parent_id,
            fitness_score=payload.fitness_score,
            response_type=getattr(payload, 'response_type', 'unknown'),
            mutation_type=mutation_type,
            successful=payload.fitness_score > 0.5,
            vulnerability_detected=getattr(payload, 'vulnerability_detected', False)
        )
        
        return node_id
        
    def get_base_payloads(self, payload_type: PayloadType) -> List[str]:
        """Get base payloads for the specified type."""
        if payload_type == PayloadType.SQL_INJECTION:
            return [
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' OR '1'='1",
                "'; DROP TABLE users--",
                "' OR 1=1#"
            ]
        elif payload_type == PayloadType.XSS:
            return [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'><script>alert('XSS')</script>"
            ]
        elif payload_type == PayloadType.COMMAND_INJECTION:
            return [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "; id",
                "| uname -a"
            ]
        elif payload_type == PayloadType.PATH_TRAVERSAL:
            return [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts"
            ]
        else:
            return ["test payload"]
            
    def update_loop(self):
        """Main update loop for UI updates."""
        if self.running:
            # Update generation counter
            if self.tree_visualizer:
                self.gen_var.set(str(self.tree_visualizer.current_generation))
                
            # Update best fitness
            if self.mutator and self.mutator.population:
                best_fitness = max(p.fitness_score for p in self.mutator.population)
                self.best_fitness_var.set(f"{best_fitness:.3f}")
                
            # Update vulnerability count
            if self.tree_visualizer and self.tree_visualizer.nodes:
                vuln_count = sum(1 for node in self.tree_visualizer.nodes.values() 
                               if node.vulnerability_detected)
                self.vuln_count_var.set(str(vuln_count))
                
        # Schedule next update
        self.root.after(100, self.update_loop)


def main():
    """Main function to run the genetic tree integration."""
    root = tk.Tk()
    app = GeneticTreeIntegration(root)
    root.mainloop()


if __name__ == "__main__":
    main() 