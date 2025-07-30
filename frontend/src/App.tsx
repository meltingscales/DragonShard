import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Homepage from './components/Homepage';
import VisualizationsPage from './components/VisualizationsPage';
import AttacksPage from './components/AttacksPage';
import NetworkPage from './components/NetworkPage';
import ReverseShellManager from './components/ReverseShellManager';
import './App.css';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-dark">
        <Navbar />
        <Routes>
          <Route path="/" element={<Homepage />} />
          <Route path="/visualizations" element={<VisualizationsPage />} />
          <Route path="/attacks" element={<AttacksPage />} />
          <Route path="/network" element={<NetworkPage />} />
          <Route path="/reverse-shell" element={<ReverseShellManager />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
