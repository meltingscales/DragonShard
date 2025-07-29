#!/usr/bin/env python3
"""
Secure PRNG (Pseudo-Random Number Generator) for fuzzing operations.

This module provides cryptographically secure random number generation
for fuzzing operations while maintaining performance for non-security-critical
operations.
"""

import hashlib
import logging
import random as std_random
import secrets
import time
from dataclasses import dataclass
from typing import Any, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PRNGConfig:
    """Configuration for PRNG operations."""

    # Use cryptographically secure random for security-critical operations
    use_secure_random: bool = True

    # Seed for reproducible results (useful for testing)
    seed: Optional[int] = None

    # Mix secure and fast random for better performance
    hybrid_mode: bool = True


class SecurePRNG:
    """
    Secure Pseudo-Random Number Generator for fuzzing operations.

    This class provides both cryptographically secure random numbers
    and fast pseudo-random numbers, choosing the appropriate method
    based on the operation's security requirements.
    """

    def __init__(self, config: Optional[PRNGConfig] = None):
        """Initialize the PRNG with configuration."""
        self.config = config or PRNGConfig()

        # Initialize secure random generator
        self._secure_random = secrets.SystemRandom()

        # Initialize fast random generator
        if self.config.seed is not None:
            std_random.seed(self.config.seed)

        # Mix entropy sources for better randomness
        self._entropy_pool = []
        self._update_entropy_pool()

    def _update_entropy_pool(self) -> None:
        """Update the entropy pool with system entropy."""
        entropy_sources = [
            str(time.time()),
            str(std_random.getrandbits(64)),
            str(secrets.randbelow(1000000)),
            str(hashlib.sha256(str(time.perf_counter()).encode()).hexdigest()[:16]),
        ]

        combined = "".join(entropy_sources).encode()
        self._entropy_pool.append(hashlib.sha256(combined).digest())

        # Keep only last 10 entropy samples
        if len(self._entropy_pool) > 10:
            self._entropy_pool.pop(0)

    def _get_hybrid_random(self) -> float:
        """Get a random number using hybrid approach."""
        if self.config.hybrid_mode:
            # Mix secure and fast random
            secure_part = self._secure_random.random()
            fast_part = std_random.random()

            # Combine with entropy
            self._update_entropy_pool()
            entropy_part = int.from_bytes(self._entropy_pool[-1][:8], "big") / (2**64)

            # Weighted combination
            return secure_part * 0.4 + fast_part * 0.4 + entropy_part * 0.2
        else:
            return self._secure_random.random()

    def random_float(self, security_critical: bool = False) -> float:
        """
        Generate a random float between 0.0 and 1.0.

        Args:
            security_critical: If True, use cryptographically secure random

        Returns:
            Random float between 0.0 and 1.0
        """
        if security_critical or self.config.use_secure_random:
            return self._secure_random.random()
        else:
            return self._get_hybrid_random()

    def choice(self, sequence: List[Any], security_critical: bool = False) -> Any:
        """
        Choose a random element from a sequence.

        Args:
            sequence: List of items to choose from
            security_critical: If True, use cryptographically secure random

        Returns:
            Randomly chosen element
        """
        if security_critical or self.config.use_secure_random:
            return self._secure_random.choice(sequence)
        else:
            return std_random.choice(sequence)

    def randint(self, a: int, b: int, security_critical: bool = False) -> int:
        """
        Generate a random integer between a and b (inclusive).

        Args:
            a: Lower bound (inclusive)
            b: Upper bound (inclusive)
            security_critical: If True, use cryptographically secure random

        Returns:
            Random integer between a and b
        """
        if security_critical or self.config.use_secure_random:
            return self._secure_random.randint(a, b)
        else:
            return std_random.randint(a, b)

    def randbelow(self, n: int, security_critical: bool = False) -> int:
        """
        Generate a random integer below n.

        Args:
            n: Upper bound (exclusive)
            security_critical: If True, use cryptographically secure random

        Returns:
            Random integer below n
        """
        if security_critical or self.config.use_secure_random:
            return self._secure_random.randbelow(n)
        else:
            return std_random.randrange(n)

    def sample(self, population: List[Any], k: int, security_critical: bool = False) -> List[Any]:
        """
        Generate a random sample of k items from population.

        Args:
            population: List of items to sample from
            k: Number of items to sample
            security_critical: If True, use cryptographically secure random

        Returns:
            List of k randomly chosen items
        """
        if security_critical or self.config.use_secure_random:
            return self._secure_random.sample(population, k)
        else:
            return std_random.sample(population, k)

    def choices(
        self,
        population: List[Any],
        weights: Optional[List[float]] = None,
        k: int = 1,
        security_critical: bool = False,
    ) -> List[Any]:
        """
        Generate a list of k choices from population with optional weights.

        Args:
            population: List of items to choose from
            weights: Optional list of weights for each item
            k: Number of choices to make
            security_critical: If True, use cryptographically secure random

        Returns:
            List of k randomly chosen items
        """
        if security_critical or self.config.use_secure_random:
            return self._secure_random.choices(population, weights=weights, k=k)
        else:
            return std_random.choices(population, weights=weights, k=k)

    def shuffle(self, sequence: List[Any], security_critical: bool = False) -> None:
        """
        Shuffle a sequence in place.

        Args:
            sequence: List to shuffle
            security_critical: If True, use cryptographically secure random
        """
        if security_critical or self.config.use_secure_random:
            self._secure_random.shuffle(sequence)
        else:
            std_random.shuffle(sequence)

    def getrandbits(self, n: int, security_critical: bool = False) -> int:
        """
        Generate a random integer with n bits.

        Args:
            n: Number of bits
            security_critical: If True, use cryptographically secure random

        Returns:
            Random integer with n bits
        """
        if security_critical or self.config.use_secure_random:
            return self._secure_random.getrandbits(n)
        else:
            return std_random.getrandbits(n)


# Global PRNG instance for convenience
_global_prng = SecurePRNG()


def get_prng(config: Optional[PRNGConfig] = None) -> SecurePRNG:
    """
    Get a PRNG instance.

    Args:
        config: Optional configuration for the PRNG

    Returns:
        SecurePRNG instance
    """
    if config is None:
        return _global_prng
    return SecurePRNG(config)


def random_float(security_critical: bool = False) -> float:
    """Convenience function for random float generation."""
    return _global_prng.random_float(security_critical)


def choice(sequence: List[Any], security_critical: bool = False) -> Any:
    """Convenience function for random choice."""
    return _global_prng.choice(sequence, security_critical)


def randint(a: int, b: int, security_critical: bool = False) -> int:
    """Convenience function for random integer generation."""
    return _global_prng.randint(a, b, security_critical)


def sample(population: List[Any], k: int, security_critical: bool = False) -> List[Any]:
    """Convenience function for random sampling."""
    return _global_prng.sample(population, k, security_critical)


def choices(
    population: List[Any],
    weights: Optional[List[float]] = None,
    k: int = 1,
    security_critical: bool = False,
) -> List[Any]:
    """Convenience function for weighted random choices."""
    return _global_prng.choices(
        population, weights=weights, k=k, security_critical=security_critical
    )
