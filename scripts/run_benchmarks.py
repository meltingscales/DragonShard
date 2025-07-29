#!/usr/bin/env python3
"""
DragonShard Genetic Algorithm Benchmark Runner

Runs comprehensive benchmarks and outputs both JSON results and summary to stdout.
"""

import sys
import os
import json
import datetime
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dragonshard.fuzzing.benchmark import GeneticAlgorithmBenchmarker
from dragonshard.fuzzing import PayloadType


def main():
    """Run the benchmark suite."""
    print('🧬 DragonShard Genetic Algorithm Benchmark Suite')
    print('=' * 60)
    print(f'Started at: {datetime.datetime.now()}')
    print('')

    # Initialize benchmarker
    benchmarker = GeneticAlgorithmBenchmarker()

    # Test targets
    targets = [
        ('http://localhost:8082', PayloadType.SQL_INJECTION),
        ('http://localhost:8082', PayloadType.XSS),
        ('http://localhost:8082', PayloadType.COMMAND_INJECTION),
    ]

    # Known vulnerabilities for effectiveness testing
    known_vulnerabilities = {
        'SQL_INJECTION': [
            "1' OR '1'='1",
            "admin'--",
            "1' UNION SELECT 1,2,3--",
            "1' AND 1=1--",
            "1' OR 1=1#"
        ],
        'XSS': [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>"
        ],
        'COMMAND_INJECTION': [
            "127.0.0.1; ls",
            "127.0.0.1 && whoami",
            "127.0.0.1 | cat /etc/passwd",
            "127.0.0.1; id",
            "127.0.0.1 && pwd"
        ]
    }

    print('🏃 Running Speed Benchmarks...')
    for target_url, payload_type in targets:
        print(f'  Testing {payload_type.value} on {target_url}...')
        try:
            result = benchmarker.run_speed_benchmark(
                target_url=target_url,
                payload_type=payload_type,
                population_size=30,
                generations=15
            )
            print(f'    ✅ Completed: {result.success_rate:.2%} success rate, {result.total_time:.2f}s')
        except Exception as e:
            print(f'    ❌ Failed: {e}')

    print('')
    print('🎯 Running Effectiveness Benchmarks...')
    for target_url, payload_type in targets:
        print(f'  Testing {payload_type.value} effectiveness...')
        try:
            vulns = known_vulnerabilities.get(payload_type.value.upper(), [])
            result = benchmarker.run_effectiveness_benchmark(
                target_url=target_url,
                payload_type=payload_type,
                known_vulnerabilities=vulns,
                population_size=30,
                generations=20
            )
            print(f'    ✅ Completed: {result.vulnerabilities_found}/{len(vulns)} vulnerabilities found')
        except Exception as e:
            print(f'    ❌ Failed: {e}')

    print('')
    print('🔄 Running Convergence Benchmarks...')
    for target_url, payload_type in targets:
        print(f'  Testing {payload_type.value} convergence...')
        try:
            result = benchmarker.run_convergence_benchmark(
                target_url=target_url,
                payload_type=payload_type,
                population_size=30,
                generations=25
            )
            conv_gen = result.convergence_generation or 'N/A'
            print(f'    ✅ Completed: converged at generation {conv_gen}, diversity: {result.diversity_score:.3f}')
        except Exception as e:
            print(f'    ❌ Failed: {e}')

    print('')
    print('⚖️  Running Comparison Benchmarks...')
    for target_url, payload_type in targets[:1]:  # Just test first target for comparison
        print(f'  Comparing methods for {payload_type.value}...')
        try:
            comparison_results = benchmarker.run_comparison_benchmark(
                target_url=target_url,
                payload_type=payload_type
            )
            for method, result in comparison_results.items():
                print(f'    {method}: {result.success_rate:.2%} success, {result.total_time:.2f}s')
        except Exception as e:
            print(f'    ❌ Failed: {e}')

    print('')
    print('📊 Generating Summary Report...')
    report = benchmarker.generate_report()
    print(report)

    print('')
    print('💾 Exporting Results...')
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    json_filename = f'benchmark_results_{timestamp}.json'
    benchmarker.export_results(json_filename)
    print(f'  Results saved to: {json_filename}')

    print('')
    print('✅ Benchmark suite completed!')
    print(f'Finished at: {datetime.datetime.now()}')


if __name__ == "__main__":
    main() 