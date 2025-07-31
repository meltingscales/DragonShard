import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Homepage from './components/Homepage';
import TargetsPage from './components/TargetsPage';
import AddTargetPage from './components/AddTargetPage';
import TargetDetailsPage from './components/TargetDetailsPage';
import VisualizationsPage from './components/VisualizationsPage';
import AttacksPage from './components/AttacksPage';
import NetworkPage from './components/NetworkPage';
import ReverseShellManager from './components/ReverseShellManager';
import WebsitesPage from './components/WebsitesPage';
import WebsiteDetailsPage from './components/WebsiteDetailsPage';
import FormsAndEndpointsPage from './components/FormsAndEndpointsPage';
import './App.css';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-dark">
        <Navbar />
        <Routes>
          <Route path="/" element={<Homepage />} />
          <Route path="/targets" element={<TargetsPage />} />
          <Route path="/targets/add" element={<AddTargetPage />} />
          <Route path="/targets/:id" element={<TargetDetailsPage />} />
          <Route path="/visualizations" element={<VisualizationsPage />} />
          <Route path="/attacks" element={<AttacksPage />} />
          <Route path="/network" element={<NetworkPage />} />
          <Route path="/reverse-shell" element={<ReverseShellManager />} />
          <Route path="/websites" element={<WebsitesPage />} />
          <Route path="/websites/:id" element={<WebsiteDetailsPage />} />
          <Route path="/fuzzing-targets" element={<FormsAndEndpointsPage />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
