#!/usr/bin/env python3
"""
Genetic Algorithm Visualization Module

Provides real-time visualization of genetic algorithm evolution and mutation processes.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
from typing import List, Dict, Any, Optional
import queue

from ..fuzzing import GeneticMutator, GeneticPayload, PayloadType, ResponseAnalyzer


class GeneticAlgorithmVisualizer:
    """Real-time visualization of genetic algorithm evolution."""

    def __init__(self, root: tk.Tk):
        """Initialize the genetic algorithm visualizer."""
        self.root = root
        self.root.title("DragonShard - Genetic Algorithm Visualizer")
        self.root.geometry("1200x800")
        
        # Data storage for visualization
        self.generation_data = []
        self.fitness_history = []
        self.mutation_history = []
        self.population_history = []
        
        # Threading for real-time updates
        self.update_queue = queue.Queue()
        self.running = False
        self.mutator = None
        self.fitness_function = None
        
        # Setup UI
        self.setup_ui()
        self.setup_charts()
        
        # Start update thread
        self.update_thread = threading.Thread(target=self.update_loop, daemon=True)
        self.update_thread.start()

    def setup_ui(self):
        """Setup the main user interface."""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding=10)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Target URL
        ttk.Label(control_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.url_var = tk.StringVar(value="http://localhost:8082")
        self.url_entry = ttk.Entry(control_frame, textvariable=self.url_var, width=40)
        self.url_entry.grid(row=0, column=1, padx=(0, 10))
        
        # Payload type
        ttk.Label(control_frame, text="Payload Type:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.payload_type_var = tk.StringVar(value="SQL_INJECTION")
        payload_type_combo = ttk.Combobox(control_frame, textvariable=self.payload_type_var, 
                                         values=["SQL_INJECTION", "XSS", "COMMAND_INJECTION", "PATH_TRAVERSAL"],
                                         state="readonly", width=15)
        payload_type_combo.grid(row=0, column=3, padx=(0, 10))
        
        # Start/Stop button
        self.start_button = ttk.Button(control_frame, text="Start Evolution", command=self.start_evolution)
        self.start_button.grid(row=0, column=4, padx=(0, 10))
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(control_frame, textvariable=self.status_var, foreground="blue")
        status_label.grid(row=0, column=5, padx=(10, 0))
        
        # Charts frame
        charts_frame = ttk.Frame(main_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Charts
        left_frame = ttk.Frame(charts_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Fitness chart
        fitness_frame = ttk.LabelFrame(left_frame, text="Fitness Evolution", padding=5)
        fitness_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Mutation chart
        mutation_frame = ttk.LabelFrame(left_frame, text="Mutation History", padding=5)
        mutation_frame.pack(fill=tk.BOTH, expand=True)
        
        # Right panel - Details
        right_frame = ttk.Frame(charts_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        
        # Current generation info
        info_frame = ttk.LabelFrame(right_frame, text="Current Generation", padding=10)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.generation_var = tk.StringVar(value="0")
        ttk.Label(info_frame, text="Generation:").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(info_frame, textvariable=self.generation_var).grid(row=0, column=1, sticky=tk.W, padx=(5, 0))
        
        self.population_var = tk.StringVar(value="0")
        ttk.Label(info_frame, text="Population:").grid(row=1, column=0, sticky=tk.W)
        ttk.Label(info_frame, textvariable=self.population_var).grid(row=1, column=1, sticky=tk.W, padx=(5, 0))
        
        self.best_fitness_var = tk.StringVar(value="0.0")
        ttk.Label(info_frame, text="Best Fitness:").grid(row=2, column=0, sticky=tk.W)
        ttk.Label(info_frame, textvariable=self.best_fitness_var).grid(row=2, column=1, sticky=tk.W, padx=(5, 0))
        
        # Best payloads
        payloads_frame = ttk.LabelFrame(right_frame, text="Best Payloads", padding=10)
        payloads_frame.pack(fill=tk.BOTH, expand=True)
        
        self.payloads_text = tk.Text(payloads_frame, height=15, width=50)
        payloads_scrollbar = ttk.Scrollbar(payloads_frame, orient=tk.VERTICAL, command=self.payloads_text.yview)
        self.payloads_text.configure(yscrollcommand=payloads_scrollbar.set)
        
        self.payloads_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        payloads_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Store frame references for charts
        self.fitness_frame = fitness_frame
        self.mutation_frame = mutation_frame

    def setup_charts(self):
        """Setup matplotlib charts."""
        # Fitness chart
        self.fitness_fig = Figure(figsize=(6, 4), dpi=100)
        self.fitness_ax = self.fitness_fig.add_subplot(111)
        self.fitness_ax.set_title("Fitness Evolution")
        self.fitness_ax.set_xlabel("Generation")
        self.fitness_ax.set_ylabel("Fitness Score")
        self.fitness_canvas = FigureCanvasTkAgg(self.fitness_fig, self.fitness_frame)
        self.fitness_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Mutation chart
        self.mutation_fig = Figure(figsize=(6, 4), dpi=100)
        self.mutation_ax = self.mutation_fig.add_subplot(111)
        self.mutation_ax.set_title("Mutation Types")
        self.mutation_ax.set_xlabel("Generation")
        self.mutation_ax.set_ylabel("Mutation Count")
        self.mutation_canvas = FigureCanvasTkAgg(self.mutation_fig, self.mutation_frame)
        self.mutation_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def start_evolution(self):
        """Start the genetic algorithm evolution."""
        if self.running:
            self.stop_evolution()
            return
        
        try:
            # Get parameters
            target_url = self.url_var.get()
            payload_type_str = self.payload_type_var.get()
            payload_type = PayloadType[payload_type_str]
            
            # Initialize genetic mutator
            self.mutator = GeneticMutator(
                population_size=20,
                mutation_rate=0.2,
                crossover_rate=0.8,
                max_generations=10,
                response_analyzer=ResponseAnalyzer()
            )
            
            # Base payloads based on type
            base_payloads = self.get_base_payloads(payload_type)
            
            # Initialize population
            self.mutator.initialize_population(base_payloads, payload_type)
            
            # Create fitness function
            self.fitness_function = self.create_fitness_function(target_url)
            
            # Start evolution in separate thread
            self.running = True
            self.start_button.config(text="Stop Evolution")
            self.status_var.set("Running...")
            
            evolution_thread = threading.Thread(target=self.run_evolution, daemon=True)
            evolution_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start evolution: {e}")

    def stop_evolution(self):
        """Stop the genetic algorithm evolution."""
        self.running = False
        self.start_button.config(text="Start Evolution")
        self.status_var.set("Stopped")

    def get_base_payloads(self, payload_type: PayloadType) -> List[str]:
        """Get base payloads for the specified type."""
        if payload_type == PayloadType.SQL_INJECTION:
            return [
                "1' OR '1'='1",
                "admin'--",
                "1' UNION SELECT 1,2,3--",
                "1' AND 1=1--",
                "1' OR 1=1#"
            ]
        elif payload_type == PayloadType.XSS:
            return [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>"
            ]
        elif payload_type == PayloadType.COMMAND_INJECTION:
            return [
                "127.0.0.1; ls",
                "127.0.0.1 && whoami",
                "127.0.0.1 | cat /etc/passwd",
                "127.0.0.1; id",
                "127.0.0.1 && pwd"
            ]
        elif payload_type == PayloadType.PATH_TRAVERSAL:
            return [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts"
            ]
        else:
            return ["test"]

    def create_fitness_function(self, target_url: str):
        """Create a fitness function for the target URL."""
        def fitness_function(payload: GeneticPayload) -> float:
            try:
                import requests
                
                # Simulate request with delay for visualization
                time.sleep(0.1)  # Small delay for visualization
                
                # Simple fitness based on payload characteristics
                fitness = 0.0
                
                # Length factor
                fitness += min(len(payload.payload) / 100.0, 0.3)
                
                # Complexity factor
                special_chars = sum(1 for c in payload.payload if c in "'\"<>()[]{}|&;")
                fitness += min(special_chars / 10.0, 0.3)
                
                # Random factor for demonstration
                import random
                fitness += random.random() * 0.4
                
                return min(fitness, 1.0)
                
            except Exception as e:
                print(f"Fitness evaluation error: {e}")
                return 0.0
        
        return fitness_function

    def run_evolution(self):
        """Run the genetic algorithm evolution."""
        try:
            for generation in range(self.mutator.max_generations):
                if not self.running:
                    break
                
                # Evolve population
                best_payloads = self.mutator.evolve(self.fitness_function)
                
                # Update data for visualization
                generation_data = {
                    'generation': generation,
                    'best_fitness': max(p.fitness for p in best_payloads) if best_payloads else 0.0,
                    'avg_fitness': sum(p.fitness for p in best_payloads) / len(best_payloads) if best_payloads else 0.0,
                    'population_size': len(best_payloads),
                    'best_payloads': best_payloads[:5]  # Top 5
                }
                
                # Queue update for UI thread
                self.update_queue.put(generation_data)
                
                # Update generation counter
                self.mutator.generation = generation + 1
                
        except Exception as e:
            print(f"Evolution error: {e}")
        finally:
            self.running = False
            self.root.after(0, lambda: self.stop_evolution())

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
                print(f"Update loop error: {e}")

    def update_visualization(self, data: Dict[str, Any]):
        """Update the visualization with new data."""
        # Update generation info
        self.generation_var.set(str(data['generation']))
        self.population_var.set(str(data['population_size']))
        self.best_fitness_var.set(f"{data['best_fitness']:.3f}")
        
        # Update payloads text
        self.payloads_text.delete(1.0, tk.END)
        for i, payload in enumerate(data['best_payloads'], 1):
            self.payloads_text.insert(tk.END, f"{i}. {payload.payload[:50]}... (fitness: {payload.fitness:.3f})\n")
        
        # Update charts
        self.update_fitness_chart(data)
        self.update_mutation_chart(data)

    def update_fitness_chart(self, data: Dict[str, Any]):
        """Update the fitness evolution chart."""
        self.generation_data.append(data['generation'])
        self.fitness_history.append(data['best_fitness'])
        
        # Clear and redraw
        self.fitness_ax.clear()
        self.fitness_ax.plot(self.generation_data, self.fitness_history, 'b-', linewidth=2)
        self.fitness_ax.set_title("Fitness Evolution")
        self.fitness_ax.set_xlabel("Generation")
        self.fitness_ax.set_ylabel("Fitness Score")
        self.fitness_ax.grid(True, alpha=0.3)
        
        # Update canvas
        if self.fitness_canvas:
            self.fitness_canvas.draw()

    def update_mutation_chart(self, data: Dict[str, Any]):
        """Update the mutation history chart."""
        # Simulate mutation data for demonstration
        mutation_types = ['encoding', 'tag', 'protocol', 'general']
        mutation_counts = [np.random.randint(1, 10) for _ in mutation_types]
        
        # Clear and redraw
        self.mutation_ax.clear()
        bars = self.mutation_ax.bar(mutation_types, mutation_counts, color=['red', 'blue', 'green', 'orange'])
        self.mutation_ax.set_title("Mutation Types")
        self.mutation_ax.set_ylabel("Mutation Count")
        
        # Add value labels on bars
        for bar, count in zip(bars, mutation_counts):
            self.mutation_ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                                str(count), ha='center', va='bottom')
        
        # Update canvas
        if self.mutation_canvas:
            self.mutation_canvas.draw()


def main():
    """Main function to run the genetic algorithm visualizer."""
    root = tk.Tk()
    app = GeneticAlgorithmVisualizer(root)
    root.mainloop()


if __name__ == "__main__":
    main() 