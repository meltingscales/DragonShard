#!/usr/bin/env python3
"""
DragonShard Genetic Algorithm Benchmarking Framework

Provides comprehensive benchmarking capabilities for genetic algorithm performance,
including speed, effectiveness, and comparison with other fuzzing approaches.
"""

import time
import json
import statistics
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import logging

from .genetic_mutator import GeneticMutator, GeneticPayload, PayloadType
from .response_analyzer import ResponseAnalyzer

logger = logging.getLogger(__name__)


class BenchmarkType(Enum):
    """Types of benchmarks to run."""

    SPEED = "speed"
    EFFECTIVENESS = "effectiveness"
    CONVERGENCE = "convergence"
    DIVERSITY = "diversity"
    COMPARISON = "comparison"


@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""

    benchmark_type: str
    target_url: str
    payload_type: str
    population_size: int
    generations: int
    total_time: float
    avg_fitness: float
    best_fitness: float
    vulnerabilities_found: int
    success_rate: float
    convergence_generation: Optional[int] = None
    diversity_score: Optional[float] = None
    mutation_rate: float = 0.1
    crossover_rate: float = 0.8
    selection_method: str = "tournament"
    fitness_function: str = "single_objective"


class GeneticAlgorithmBenchmarker:
    """Comprehensive benchmarking framework for genetic algorithms."""

    def __init__(self):
        """Initialize the benchmarker."""
        self.results: List[BenchmarkResult] = []
        self.baseline_results: Dict[str, Any] = {}

    def run_speed_benchmark(
        self,
        target_url: str,
        payload_type: PayloadType,
        population_size: int = 50,
        generations: int = 20,
        **kwargs,
    ) -> BenchmarkResult:
        """Benchmark genetic algorithm speed and performance."""
        logger.info(f"Running speed benchmark for {payload_type.value} on {target_url}")

        start_time = time.time()

        # Initialize genetic mutator
        mutator = GeneticMutator(
            population_size=population_size,
            max_generations=generations,
            response_analyzer=ResponseAnalyzer(),
            **kwargs,
        )

        # Initialize population
        base_payloads = self._get_base_payloads(payload_type)
        mutator.initialize_population(base_payloads, payload_type)

        # Create fitness function
        fitness_function = mutator.create_response_based_fitness(target_url)

        # Run evolution
        best_payloads = []
        avg_fitness_history = []
        best_fitness_history = []

        for generation in range(generations):
            generation_start = time.time()

            # Evolve population
            evolved = mutator.evolve(fitness_function)

            # Calculate metrics
            avg_fitness = sum(p.fitness for p in evolved) / len(evolved)
            best_fitness = max(p.fitness for p in evolved)

            avg_fitness_history.append(avg_fitness)
            best_fitness_history.append(best_fitness)

            # Get best payloads
            best_payloads = mutator.get_best_payloads(5)

            generation_time = time.time() - generation_start
            logger.debug(
                f"Generation {generation}: avg_fitness={avg_fitness:.3f}, "
                f"best_fitness={best_fitness:.3f}, time={generation_time:.2f}s"
            )

        total_time = time.time() - start_time

        # Calculate success rate (payloads with fitness > 0.7)
        high_fitness_count = sum(1 for p in best_payloads if p.fitness > 0.7)
        success_rate = high_fitness_count / len(best_payloads) if best_payloads else 0.0

        # Count vulnerabilities found
        vulnerabilities_found = sum(1 for p in best_payloads if p.vulnerability_score > 0.5)

        result = BenchmarkResult(
            benchmark_type=BenchmarkType.SPEED.value,
            target_url=target_url,
            payload_type=payload_type.value,
            population_size=population_size,
            generations=generations,
            total_time=total_time,
            avg_fitness=statistics.mean(avg_fitness_history),
            best_fitness=max(best_fitness_history),
            vulnerabilities_found=vulnerabilities_found,
            success_rate=success_rate,
            mutation_rate=kwargs.get("mutation_rate", 0.1),
            crossover_rate=kwargs.get("crossover_rate", 0.8),
        )

        self.results.append(result)
        return result

    def run_effectiveness_benchmark(
        self,
        target_url: str,
        payload_type: PayloadType,
        known_vulnerabilities: List[str],
        population_size: int = 50,
        generations: int = 30,
        **kwargs,
    ) -> BenchmarkResult:
        """Benchmark effectiveness in finding known vulnerabilities."""
        logger.info(f"Running effectiveness benchmark for {payload_type.value}")

        start_time = time.time()

        # Initialize mutator
        mutator = GeneticMutator(
            population_size=population_size,
            max_generations=generations,
            response_analyzer=ResponseAnalyzer(),
            **kwargs,
        )

        # Initialize population
        base_payloads = self._get_base_payloads(payload_type)
        mutator.initialize_population(base_payloads, payload_type)

        # Create fitness function
        fitness_function = mutator.create_response_based_fitness(target_url)

        # Run evolution
        found_vulnerabilities = set()
        generation_found = {}

        for generation in range(generations):
            evolved = mutator.evolve(fitness_function)
            best_payloads = mutator.get_best_payloads(10)

            # Check if any payloads match known vulnerabilities
            for payload in best_payloads:
                for vuln in known_vulnerabilities:
                    if vuln.lower() in payload.payload.lower():
                        found_vulnerabilities.add(vuln)
                        if vuln not in generation_found:
                            generation_found[vuln] = generation

        total_time = time.time() - start_time

        # Calculate effectiveness metrics
        detection_rate = len(found_vulnerabilities) / len(known_vulnerabilities)
        avg_generation_found = statistics.mean(generation_found.values()) if generation_found else 0

        result = BenchmarkResult(
            benchmark_type=BenchmarkType.EFFECTIVENESS.value,
            target_url=target_url,
            payload_type=payload_type.value,
            population_size=population_size,
            generations=generations,
            total_time=total_time,
            avg_fitness=0.0,  # Will be calculated from evolution
            best_fitness=0.0,  # Will be calculated from evolution
            vulnerabilities_found=len(found_vulnerabilities),
            success_rate=detection_rate,
            convergence_generation=int(avg_generation_found) if avg_generation_found > 0 else None,
        )

        self.results.append(result)
        return result

    def run_convergence_benchmark(
        self,
        target_url: str,
        payload_type: PayloadType,
        population_size: int = 50,
        generations: int = 50,
        **kwargs,
    ) -> BenchmarkResult:
        """Benchmark convergence speed and stability."""
        logger.info(f"Running convergence benchmark for {payload_type.value}")

        start_time = time.time()

        # Initialize mutator
        mutator = GeneticMutator(
            population_size=population_size,
            max_generations=generations,
            response_analyzer=ResponseAnalyzer(),
            **kwargs,
        )

        # Initialize population
        base_payloads = self._get_base_payloads(payload_type)
        mutator.initialize_population(base_payloads, payload_type)

        # Create fitness function
        fitness_function = mutator.create_response_based_fitness(target_url)

        # Track convergence metrics
        fitness_history = []
        diversity_history = []
        convergence_generation = None

        for generation in range(generations):
            evolved = mutator.evolve(fitness_function)

            # Calculate metrics
            avg_fitness = sum(p.fitness for p in evolved) / len(evolved)
            diversity = mutator._calculate_population_diversity()

            fitness_history.append(avg_fitness)
            diversity_history.append(diversity)

            # Check for convergence (fitness stabilizes)
            if len(fitness_history) >= 5:
                recent_fitness = fitness_history[-5:]
                if max(recent_fitness) - min(recent_fitness) < 0.05:
                    if convergence_generation is None:
                        convergence_generation = generation

        total_time = time.time() - start_time

        # Calculate convergence metrics
        final_diversity = diversity_history[-1] if diversity_history else 0.0
        fitness_improvement = fitness_history[-1] - fitness_history[0] if fitness_history else 0.0

        result = BenchmarkResult(
            benchmark_type=BenchmarkType.CONVERGENCE.value,
            target_url=target_url,
            payload_type=payload_type.value,
            population_size=population_size,
            generations=generations,
            total_time=total_time,
            avg_fitness=statistics.mean(fitness_history),
            best_fitness=max(fitness_history),
            vulnerabilities_found=0,  # Not tracking in convergence benchmark
            success_rate=fitness_improvement,
            convergence_generation=convergence_generation,
            diversity_score=final_diversity,
        )

        self.results.append(result)
        return result

    def run_comparison_benchmark(
        self, target_url: str, payload_type: PayloadType, comparison_methods: List[str] = None
    ) -> Dict[str, BenchmarkResult]:
        """Compare different genetic algorithm configurations."""
        if comparison_methods is None:
            comparison_methods = [
                "tournament_selection",
                "rank_based_selection",
                "fitness_proportionate_selection",
                "adaptive_mutation",
                "multi_objective",
            ]

        logger.info(f"Running comparison benchmark for {payload_type.value}")

        comparison_results = {}

        for method in comparison_methods:
            logger.info(f"Testing method: {method}")

            kwargs = {
                "population_size": 50,
                "generations": 20,
                "mutation_rate": 0.1,
                "crossover_rate": 0.8,
            }

            if method == "adaptive_mutation":
                kwargs["adaptive_mutation"] = True
            elif method == "multi_objective":
                # Use multi-objective fitness
                pass  # Will be handled in the benchmark

            result = self.run_speed_benchmark(target_url, payload_type, **kwargs)
            result.selection_method = method
            comparison_results[method] = result

        return comparison_results

    def _get_base_payloads(self, payload_type: PayloadType) -> List[str]:
        """Get base payloads for the specified type."""
        if payload_type == PayloadType.SQL_INJECTION:
            return [
                "1' OR '1'='1",
                "admin'--",
                "1' UNION SELECT 1,2,3--",
                "1' AND 1=1--",
                "1' OR 1=1#",
            ]
        elif payload_type == PayloadType.XSS:
            return [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
            ]
        elif payload_type == PayloadType.COMMAND_INJECTION:
            return [
                "127.0.0.1; ls",
                "127.0.0.1 && whoami",
                "127.0.0.1 | cat /etc/passwd",
                "127.0.0.1; id",
                "127.0.0.1 && pwd",
            ]
        else:
            return ["test"]

    def export_results(self, filename: str) -> None:
        """Export benchmark results to JSON file."""
        results_data = [asdict(result) for result in self.results]

        with open(filename, "w") as f:
            json.dump(results_data, f, indent=2)

        logger.info(f"Benchmark results exported to {filename}")

    def generate_report(self) -> str:
        """Generate a comprehensive benchmark report."""
        if not self.results:
            return "No benchmark results available."

        report = []
        report.append("🐉 DragonShard Genetic Algorithm Benchmark Report")
        report.append("=" * 60)
        report.append("")

        # Summary statistics
        total_benchmarks = len(self.results)
        avg_time = statistics.mean(r.total_time for r in self.results)
        avg_success_rate = statistics.mean(r.success_rate for r in self.results)
        total_vulnerabilities = sum(r.vulnerabilities_found for r in self.results)

        report.append(f"📊 Summary Statistics:")
        report.append(f"  Total Benchmarks: {total_benchmarks}")
        report.append(f"  Average Time: {avg_time:.2f}s")
        report.append(f"  Average Success Rate: {avg_success_rate:.2%}")
        report.append(f"  Total Vulnerabilities Found: {total_vulnerabilities}")
        report.append("")

        # Results by type
        for benchmark_type in BenchmarkType:
            type_results = [r for r in self.results if r.benchmark_type == benchmark_type.value]
            if type_results:
                report.append(f"🔍 {benchmark_type.value.title()} Benchmarks:")
                for result in type_results:
                    report.append(
                        f"  - {result.payload_type}: {result.success_rate:.2%} success rate, "
                        f"{result.total_time:.2f}s"
                    )
                report.append("")

        return "\n".join(report)
