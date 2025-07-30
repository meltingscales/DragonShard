#!/usr/bin/env python3
"""
DragonShard Performance Metrics Module

Provides real-time performance monitoring and analysis for genetic algorithms.
"""

import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .genetic_mutator import GeneticMutator, GeneticPayload


@dataclass
class PerformanceMetrics:
    """Real-time performance metrics for genetic algorithms."""

    # Timing metrics
    start_time: float = field(default_factory=time.time)
    generation_times: deque = field(default_factory=lambda: deque(maxlen=100))
    total_requests: int = 0
    avg_request_time: float = 0.0

    # Fitness metrics
    best_fitness_history: deque = field(default_factory=lambda: deque(maxlen=100))
    avg_fitness_history: deque = field(default_factory=lambda: deque(maxlen=100))
    fitness_improvement_rate: float = 0.0

    # Population metrics
    population_diversity: deque = field(default_factory=lambda: deque(maxlen=100))
    convergence_score: float = 0.0

    # Success metrics
    vulnerabilities_found: int = 0
    success_rate: float = 0.0
    high_fitness_count: int = 0

    # Resource metrics
    memory_usage: float = 0.0
    cpu_usage: float = 0.0

    def update_generation_metrics(
        self,
        generation: int,
        population: List[GeneticPayload],
        generation_time: float,
        request_count: int = 0,
        request_time: float = 0.0,
    ) -> None:
        """Update metrics for a new generation."""
        # Timing metrics
        self.generation_times.append(generation_time)

        if request_count > 0:
            self.total_requests += request_count
            self.avg_request_time = (
                self.avg_request_time * (self.total_requests - request_count) + request_time
            ) / self.total_requests

        # Fitness metrics
        fitnesses = [p.fitness for p in population]
        avg_fitness = statistics.mean(fitnesses)
        best_fitness = max(fitnesses)

        self.avg_fitness_history.append(avg_fitness)
        self.best_fitness_history.append(best_fitness)

        # Calculate fitness improvement rate
        if len(self.best_fitness_history) >= 2:
            recent_improvement = self.best_fitness_history[-1] - self.best_fitness_history[-2]
            self.fitness_improvement_rate = recent_improvement

        # Population diversity
        diversity = self._calculate_diversity(population)
        self.population_diversity.append(diversity)

        # Convergence score
        if len(self.avg_fitness_history) >= 5:
            recent_fitness = list(self.avg_fitness_history)[-5:]
            self.convergence_score = max(recent_fitness) - min(recent_fitness)

        # Success metrics
        high_fitness_payloads = [p for p in population if p.fitness > 0.7]
        self.high_fitness_count = len(high_fitness_payloads)
        self.success_rate = self.high_fitness_count / len(population)

        # Vulnerability count
        vulnerable_payloads = [p for p in population if p.vulnerability_score > 0.5]
        self.vulnerabilities_found = len(vulnerable_payloads)

    def _calculate_diversity(self, population: List[GeneticPayload]) -> float:
        """Calculate population diversity."""
        if len(population) < 2:
            return 1.0

        # Calculate payload similarities
        similarities = []
        for i in range(len(population)):
            for j in range(i + 1, len(population)):
                similarity = self._payload_similarity(population[i].payload, population[j].payload)
                similarities.append(similarity)

        if not similarities:
            return 1.0

        avg_similarity = statistics.mean(similarities)
        diversity = 1.0 - avg_similarity
        return max(0.0, min(1.0, diversity))

    def _payload_similarity(self, payload1: str, payload2: str) -> float:
        """Calculate similarity between two payloads."""
        set1 = set(payload1)
        set2 = set(payload2)

        if not set1 and not set2:
            return 1.0

        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))

        return intersection / union if union > 0 else 0.0

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of current metrics."""
        return {
            "elapsed_time": time.time() - self.start_time,
            "total_generations": len(self.generation_times),
            "avg_generation_time": statistics.mean(self.generation_times)
            if self.generation_times
            else 0.0,
            "total_requests": self.total_requests,
            "avg_request_time": self.avg_request_time,
            "current_best_fitness": self.best_fitness_history[-1]
            if self.best_fitness_history
            else 0.0,
            "current_avg_fitness": self.avg_fitness_history[-1]
            if self.avg_fitness_history
            else 0.0,
            "fitness_improvement_rate": self.fitness_improvement_rate,
            "current_diversity": self.population_diversity[-1]
            if self.population_diversity
            else 1.0,
            "convergence_score": self.convergence_score,
            "vulnerabilities_found": self.vulnerabilities_found,
            "success_rate": self.success_rate,
            "high_fitness_count": self.high_fitness_count,
        }

    def is_converged(self, threshold: float = 0.05) -> bool:
        """Check if the algorithm has converged."""
        return self.convergence_score < threshold

    def is_stagnant(self, generations: int = 10, threshold: float = 0.01) -> bool:
        """Check if the algorithm is stagnant."""
        if len(self.best_fitness_history) < generations:
            return False

        recent_fitness = list(self.best_fitness_history)[-generations:]
        improvement = max(recent_fitness) - min(recent_fitness)
        return improvement < threshold


class PerformanceMonitor:
    """Real-time performance monitoring for genetic algorithms."""

    def __init__(self, mutator: GeneticMutator):
        """Initialize the performance monitor."""
        self.mutator = mutator
        self.metrics = PerformanceMetrics()
        self.monitoring = False
        self.monitor_thread = None

    def start_monitoring(self) -> None:
        """Start real-time monitoring."""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self) -> None:
        """Stop real-time monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self.monitoring:
            try:
                # Update metrics every second
                time.sleep(1.0)

                # Get current population metrics
                if hasattr(self.mutator, "population") and self.mutator.population:
                    self.metrics.update_generation_metrics(
                        generation=self.mutator.generation,
                        population=self.mutator.population,
                        generation_time=0.0,  # Will be updated by the mutator
                    )

            except Exception as e:
                print(f"Monitoring error: {e}")

    def get_performance_report(self) -> str:
        """Generate a performance report."""
        summary = self.metrics.get_summary()

        report = []
        report.append("📊 Genetic Algorithm Performance Report")
        report.append("=" * 50)
        report.append("")

        # Timing section
        report.append("⏱️  Timing Metrics:")
        report.append(f"  Elapsed Time: {summary['elapsed_time']:.2f}s")
        report.append(f"  Total Generations: {summary['total_generations']}")
        report.append(f"  Avg Generation Time: {summary['avg_generation_time']:.3f}s")
        report.append(f"  Total Requests: {summary['total_requests']}")
        report.append(f"  Avg Request Time: {summary['avg_request_time']:.3f}s")
        report.append("")

        # Fitness section
        report.append("🎯 Fitness Metrics:")
        report.append(f"  Current Best Fitness: {summary['current_best_fitness']:.3f}")
        report.append(f"  Current Avg Fitness: {summary['current_avg_fitness']:.3f}")
        report.append(f"  Fitness Improvement Rate: {summary['fitness_improvement_rate']:.3f}")
        report.append("")

        # Population section
        report.append("👥 Population Metrics:")
        report.append(f"  Current Diversity: {summary['current_diversity']:.3f}")
        report.append(f"  Convergence Score: {summary['convergence_score']:.3f}")
        report.append(f"  High Fitness Count: {summary['high_fitness_count']}")
        report.append(f"  Success Rate: {summary['success_rate']:.2%}")
        report.append("")

        # Success section
        report.append("🎉 Success Metrics:")
        report.append(f"  Vulnerabilities Found: {summary['vulnerabilities_found']}")
        report.append("")

        # Status indicators
        report.append("📈 Status Indicators:")
        if self.metrics.is_converged():
            report.append("  ✅ Algorithm has converged")
        else:
            report.append("  🔄 Algorithm still evolving")

        if self.metrics.is_stagnant():
            report.append("  ⚠️  Algorithm may be stagnant")
        else:
            report.append("  ✅ Algorithm showing progress")

        return "\n".join(report)

    def export_metrics(self, filename: str) -> None:
        """Export metrics to JSON file."""
        import json

        data = {
            "summary": self.metrics.get_summary(),
            "fitness_history": list(self.metrics.best_fitness_history),
            "diversity_history": list(self.metrics.population_diversity),
            "generation_times": list(self.metrics.generation_times),
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
