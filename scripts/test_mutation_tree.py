#!/usr/bin/env python3
"""
Test script for the mutation tree visualization.

This script demonstrates the mutation tree visualization by creating
a simulated genetic algorithm evolution and visualizing the results.
"""

import tkinter as tk
from tkinter import ttk
import time
import threading
from typing import List, Dict, Any

from dragonshard.visualizer.mutation_tree import MutationTreeVisualizer, MutationNode
from dragonshard.fuzzing import GeneticPayload, PayloadType


def create_simulated_evolution():
    """Create a simulated evolution for demonstration."""
    
    # Create root window
    root = tk.Tk()
    root.title("DragonShard - Mutation Tree Demo")
    root.geometry("1400x900")
    
    # Create tree visualizer
    tree_viz = MutationTreeVisualizer(root)
    
    # Simulate evolution
    def run_simulation():
        """Run the simulation."""
        
        # Base payloads
        base_payloads = [
            "'; DROP TABLE users--",
            "' OR 1=1--", 
            "' UNION SELECT NULL--",
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>"
        ]
        
        # Create initial population
        initial_population = []
        for i, payload in enumerate(base_payloads):
            genetic_payload = GeneticPayload(payload, PayloadType.SQL_INJECTION if i < 3 else PayloadType.XSS)
            genetic_payload.mutation_count = 0
            genetic_payload.fitness_score = 0.3 + (i * 0.1)
            initial_population.append(genetic_payload)
            
        # Add initial population to tree and store their IDs
        initial_node_ids = []
        for payload in initial_population:
            node_id = tree_viz.add_node(
                payload=payload,
                fitness_score=payload.fitness_score,
                response_type="normal",
                mutation_type="initial",
                successful=False,
                vulnerability_detected=False
            )
            initial_node_ids.append(node_id)
            root.update()  # Update GUI
        
        # Simulate generations
        for generation in range(5):
            print(f"Generation {generation + 1}")
            
            # Create mutated payloads
            new_node_ids = []
            for i, parent_payload in enumerate(initial_population):
                # Create mutations
                for mutation_num in range(3):
                    # Create mutated payload
                    mutated_payload = GeneticPayload(
                        f"{parent_payload.payload} mutated_{mutation_num}",
                        parent_payload.payload_type
                    )
                    mutated_payload.mutation_count = parent_payload.mutation_count + 1
                    
                    # Simulate fitness based on mutation
                    base_fitness = parent_payload.fitness_score
                    mutation_bonus = (mutation_num + 1) * 0.1
                    mutated_payload.fitness_score = min(base_fitness + mutation_bonus, 1.0)
                    
                    # Determine if vulnerable
                    vulnerability_detected = mutated_payload.fitness_score > 0.7
                    successful = mutated_payload.fitness_score > 0.5
                    
                    # Determine response type
                    if vulnerability_detected:
                        response_type = "vulnerability"
                    elif successful:
                        response_type = "anomaly"
                    else:
                        response_type = "normal"
                    
                    # Determine mutation type
                    if mutated_payload.payload_type == PayloadType.SQL_INJECTION:
                        mutation_type = "sql_mutation"
                    elif mutated_payload.payload_type == PayloadType.XSS:
                        mutation_type = "xss_mutation"
                    else:
                        mutation_type = "general_mutation"
                    
                    # Get parent node ID (use the corresponding initial node)
                    parent_id = initial_node_ids[i] if i < len(initial_node_ids) else None
                    
                    # Add to tree
                    node_id = tree_viz.add_node(
                        payload=mutated_payload,
                        parent_id=parent_id,  # Now properly specifying parent
                        fitness_score=mutated_payload.fitness_score,
                        response_type=response_type,
                        mutation_type=mutation_type,
                        successful=successful,
                        vulnerability_detected=vulnerability_detected
                    )
                    new_node_ids.append(node_id)
                    root.update()  # Update GUI
                    
                    # Small delay between mutations
                    time.sleep(0.1)
            
            # Update initial population for next generation
            initial_population = [tree_viz.nodes[node_id].payload for node_id in new_node_ids]
            initial_node_ids = new_node_ids
            
            # Move to next generation
            tree_viz.next_generation()
            
            # Small delay for visualization
            time.sleep(1)
            
        print("Simulation completed!")
    
    # Start simulation after a short delay
    root.after(1000, run_simulation)
    
    # Run the GUI
    root.mainloop()


def create_interactive_demo():
    """Create an interactive demo with manual node addition."""
    
    root = tk.Tk()
    root.title("DragonShard - Interactive Mutation Tree Demo")
    root.geometry("1400x900")
    
    # Create tree visualizer
    tree_viz = MutationTreeVisualizer(root)
    
    # Add control panel for manual testing
    control_frame = ttk.LabelFrame(root, text="Manual Controls", padding=10)
    control_frame.pack(fill=tk.X, padx=10, pady=5)
    
    # Payload entry
    ttk.Label(control_frame, text="Payload:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
    payload_var = tk.StringVar(value="'; DROP TABLE users--")
    payload_entry = ttk.Entry(control_frame, textvariable=payload_var, width=40)
    payload_entry.grid(row=0, column=1, padx=(0, 10))
    
    # Payload type
    ttk.Label(control_frame, text="Type:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
    type_var = tk.StringVar(value="SQL_INJECTION")
    type_combo = ttk.Combobox(
        control_frame,
        textvariable=type_var,
        values=["SQL_INJECTION", "XSS", "COMMAND_INJECTION", "PATH_TRAVERSAL"],
        state="readonly",
        width=15
    )
    type_combo.grid(row=0, column=3, padx=(0, 10))
    
    # Fitness score
    ttk.Label(control_frame, text="Fitness:").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
    fitness_var = tk.StringVar(value="0.5")
    fitness_entry = ttk.Entry(control_frame, textvariable=fitness_var, width=8)
    fitness_entry.grid(row=0, column=5, padx=(0, 10))
    
    # Vulnerability checkbox
    vuln_var = tk.BooleanVar(value=False)
    vuln_check = ttk.Checkbutton(control_frame, text="Vulnerable", variable=vuln_var)
    vuln_check.grid(row=0, column=6, padx=(0, 10))
    
    # Add node button
    def add_node():
        """Add a node to the tree."""
        try:
            payload = payload_var.get()
            payload_type = PayloadType[type_var.get()]
            fitness = float(fitness_var.get())
            vulnerable = vuln_var.get()
            
            genetic_payload = GeneticPayload(payload, payload_type)
            genetic_payload.mutation_count = len(tree_viz.nodes)  # Simple mutation count
            
            tree_viz.add_node(
                payload=genetic_payload,
                fitness_score=fitness,
                response_type="vulnerability" if vulnerable else "normal",
                mutation_type="manual",
                successful=fitness > 0.5,
                vulnerability_detected=vulnerable
            )
            
        except Exception as e:
            print(f"Error adding node: {e}")
    
    add_button = ttk.Button(control_frame, text="Add Node", command=add_node)
    add_button.grid(row=0, column=7, padx=(0, 10))
    
    # Clear button
    clear_button = ttk.Button(control_frame, text="Clear Tree", command=tree_viz.clear_tree)
    clear_button.grid(row=0, column=8, padx=(0, 10))
    
    # Find path button
    path_button = ttk.Button(control_frame, text="Find Best Path", command=tree_viz.find_best_path)
    path_button.grid(row=0, column=9, padx=(0, 10))
    
    # Run the GUI
    root.mainloop()


if __name__ == "__main__":
    print("DragonShard Mutation Tree Visualization Demo")
    print("=" * 50)
    print("1. Simulated Evolution Demo")
    print("2. Interactive Demo")
    print()
    
    choice = input("Choose demo type (1 or 2): ").strip()
    
    if choice == "1":
        create_simulated_evolution()
    elif choice == "2":
        create_interactive_demo()
    else:
        print("Invalid choice. Running simulated evolution demo...")
        create_simulated_evolution() 