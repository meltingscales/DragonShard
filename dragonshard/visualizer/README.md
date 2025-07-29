# DragonShard Visualization Module

This module provides comprehensive visualization tools for attack analysis and monitoring, with a focus on real-time genetic algorithm evolution tracking.

## 🎨 Features

### Genetic Algorithm Visualization
- **Real-time Evolution Tracking**: Watch genetic algorithm evolution in real-time
- **Fitness Charts**: Visualize fitness scores over generations
- **Mutation History**: Track mutation types and frequencies
- **Payload Evolution**: See how payloads evolve and improve
- **Interactive Controls**: Start/stop evolution, change parameters

### Planned Visualizations
- **Site Traversal Maps**: Interactive site crawling visualization
- **Vulnerability Heatmaps**: Color-coded vulnerability distribution
- **Attack Chain Mapping**: Visual attack strategy representation
- **Response Analysis Charts**: Visual response differential analysis
- **Performance Metrics**: CPU, memory, and network usage

## 🚀 Quick Start

### Prerequisites
```bash
# Install dependencies
make setup

# Start test environment (optional, for real vulnerability testing)
make test-env-start
```

### Run Visualization
```bash
# Run the genetic algorithm visualizer
make test-visualization

# Or run directly
python scripts/test_visualization.py
```

## 🎯 Usage

### Basic Usage
1. **Start the GUI**: Run `make test-visualization`
2. **Select Target**: Choose target URL and payload type
3. **Start Evolution**: Click "Start Evolution" to begin
4. **Watch Charts**: Observe real-time fitness and mutation charts
5. **Analyze Results**: View best payloads and their fitness scores

### Advanced Usage
- **Target Selection**: Choose from vulnerable containers (vuln-php, vuln-node, etc.)
- **Payload Types**: Test SQL Injection, XSS, Command Injection, Path Traversal, etc.
- **Real HTTP Testing**: The visualizer makes real HTTP requests to test vulnerabilities
- **Complex Vulnerabilities**: Test against advanced multi-vector attacks

## 📊 Visualization Components

### Fitness Evolution Chart
- Shows fitness scores over generations
- Tracks best, average, and worst fitness
- Real-time updates during evolution

### Mutation History Chart
- Displays mutation type distribution
- Shows mutation frequency over time
- Helps understand algorithm behavior

### Payload Display
- Shows top 5 best payloads
- Displays fitness scores for each
- Real-time updates as evolution progresses

### Generation Information
- Current generation number
- Population size
- Best fitness score
- Status indicators

## 🔧 Configuration

### Target URLs
- **vuln-php**: `http://localhost:8082` - PHP vulnerabilities
- **vuln-node**: `http://localhost:8083` - Node.js vulnerabilities  
- **vuln-python**: `http://localhost:8084` - Python vulnerabilities
- **dvwa**: `http://localhost:8080` - Damn Vulnerable Web App
- **juice-shop**: `http://localhost:3000` - OWASP Juice Shop

### Payload Types
- **SQL_INJECTION**: Database injection attacks
- **XSS**: Cross-site scripting attacks
- **COMMAND_INJECTION**: Command execution attacks
- **PATH_TRAVERSAL**: Directory traversal attacks
- **LFI**: Local file inclusion
- **RFI**: Remote file inclusion
- **XXE**: XML external entity injection
- **SSRF**: Server-side request forgery
- **TEMPLATE_INJECTION**: Template engine injection
- **NOSQL_INJECTION**: NoSQL database injection

## 🛠️ Technical Details

### Technology Stack
- **GUI Framework**: Tkinter (Python-native, cross-platform)
- **Charts**: matplotlib for data visualization
- **Real-time Updates**: Threading for live data updates
- **HTTP Requests**: requests library for vulnerability testing

### Architecture
```
dragonshard/visualizer/
├── __init__.py              # Module initialization
├── genetic_viz.py           # Genetic algorithm visualization
├── main_window.py           # Main application window (planned)
├── widgets/                 # Custom widgets (planned)
└── modules/                 # Visualization modules (planned)
```

### Threading Model
- **Main Thread**: Tkinter GUI and user interactions
- **Evolution Thread**: Genetic algorithm execution
- **Update Thread**: Real-time data processing
- **HTTP Thread**: Vulnerability testing requests

## 🎨 Customization

### Adding New Visualizations
1. Create new visualization class
2. Inherit from base visualizer
3. Implement update methods
4. Add to main window

### Custom Fitness Functions
```python
def custom_fitness_function(payload: GeneticPayload) -> float:
    # Your custom fitness logic here
    return fitness_score
```

### Custom Payload Types
```python
# Add to PayloadType enum
NEW_VULNERABILITY = "new_vulnerability"

# Add payloads to get_base_payloads method
elif payload_type == PayloadType.NEW_VULNERABILITY:
    return ["payload1", "payload2", "payload3"]
```

## 🔍 Troubleshooting

### Common Issues
- **Import Errors**: Make sure you're running from project root
- **GUI Not Starting**: Check Tkinter installation
- **No Test Environment**: Run `make test-env-start` first
- **Chart Not Updating**: Check threading and queue operations

### Debug Mode
```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🚀 Future Enhancements

### Planned Features
- **3D Visualizations**: Fitness landscape visualization
- **Network Graphs**: Attack chain visualization
- **Heatmaps**: Vulnerability distribution maps
- **Export Capabilities**: PNG, SVG, HTML export
- **Plugin System**: Extensible visualization framework

### Advanced Visualizations
- **Attack Flow Diagrams**: Visual attack strategies
- **Dependency Graphs**: Vulnerability relationships
- **Timeline Views**: Chronological attack progression
- **Performance Dashboards**: Real-time metrics

## 📝 Examples

### Basic Visualization
```python
from dragonshard.visualizer import GeneticAlgorithmVisualizer
import tkinter as tk

root = tk.Tk()
app = GeneticAlgorithmVisualizer(root)
root.mainloop()
```

### Custom Configuration
```python
# Custom genetic mutator configuration
mutator = GeneticMutator(
    population_size=30,
    mutation_rate=0.2,
    crossover_rate=0.8,
    max_generations=15
)
```

## 🤝 Contributing

### Adding New Visualizations
1. Create new visualization module
2. Add to `__init__.py` exports
3. Update main window integration
4. Add tests and documentation

### Code Style
- Follow project linting rules
- Add type hints
- Include docstrings
- Write unit tests

## 📄 License

This module is part of DragonShard and follows the same license terms. 