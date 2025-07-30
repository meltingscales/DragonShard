# DragonShard Frontend

Modern React-based frontend for the DragonShard offensive security tool. This frontend provides real-time visualization and control interfaces for all DragonShard components.

## Features

- **Real-time Dashboard**: Live monitoring of attacks, vulnerabilities, and network topology
- **Interactive Visualizations**: Network graphs, genetic algorithm progress, and mutation trees
- **WebSocket Integration**: Real-time updates from the DragonShard API
- **Responsive Design**: Works on desktop and mobile devices
- **Dark Theme**: Optimized for security professionals

## Tech Stack

- **React 18** with TypeScript
- **Vite** for fast development and building
- **Tailwind CSS** for styling
- **Cytoscape.js** for network visualizations
- **Chart.js** for data charts
- **WebSocket** for real-time communication

## Development

### Prerequisites

- Node.js 18+ 
- pnpm (recommended) or npm

### Setup

```bash
# Install dependencies
pnpm install

# Start development server
pnpm run dev
# or
make start-frontend
```

The frontend will be available at `http://localhost:5173`

### Building for Production

```bash
# Build the frontend
pnpm run build
# or
make build-frontend
```

## Project Structure

```
frontend/
├── src/
│   ├── components/          # React components
│   │   ├── Dashboard.tsx    # Main dashboard
│   │   ├── NetworkGraph.tsx # Network topology visualization
│   │   ├── MutationTree.tsx # Genetic algorithm mutation tree
│   │   └── ...              # Other components
│   ├── services/            # API and WebSocket services
│   ├── types/               # TypeScript type definitions
│   └── App.tsx              # Main app component
├── public/                  # Static assets
└── package.json            # Dependencies and scripts
```

## API Integration

The frontend connects to the DragonShard API running on `http://localhost:8000` and uses WebSocket for real-time updates.

### Key Endpoints

- `/api/v1/attacks/*` - Attack monitoring and control
- `/api/v1/vulnerabilities/*` - Vulnerability management
- `/api/v1/network/*` - Network topology
- `/api/v1/fuzzing/*` - Genetic algorithm and fuzzing
- `/api/v1/sessions/*` - Session management
- `/ws` - WebSocket for real-time updates

## Development Commands

```bash
# Start development server
pnpm run dev

# Build for production
pnpm run build

# Preview production build
pnpm run preview

# Lint code
pnpm run lint
```

## Contributing

1. Follow the existing code style and TypeScript patterns
2. Add proper TypeScript types for new features
3. Test components with the DragonShard API
4. Update this README for new features
