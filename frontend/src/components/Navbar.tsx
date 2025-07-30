import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, BarChart3, Network, Zap, Home, Menu, X, Terminal, FileText } from 'lucide-react';

const Navbar: React.FC = () => {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const isActive = (path: string) => {
    return location.pathname === path;
  };

  const navLinks = [
    { path: '/', label: 'Home', icon: Home },
    { path: '/visualizations', label: 'Visualizations', icon: BarChart3 },
    { path: '/attacks', label: 'Attacks', icon: Zap },
    { path: '/network', label: 'Network', icon: Network },
    { path: '/reverse-shell', label: 'Reverse Shell', icon: Terminal },
  ];

  return (
    <div className="bg-card border-b border-primary shadow-lg sticky top-0 z-50">
      <div className="container">
        <div className="flex justify-between items-center py-4">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-3 text-white hover:opacity-80 transition">
            <Shield size={32} color="#667eea" />
            <span className="text-xl font-bold">DragonShard</span>
          </Link>
          
          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center gap-8">
            {navLinks.map((link) => {
              const Icon = link.icon;
              return (
                <Link
                  key={link.path}
                  to={link.path}
                  className={`flex items-center gap-2 px-4 py-2 rounded text-white font-medium transition-colors ${
                    isActive(link.path) 
                      ? 'bg-primary text-white' 
                      : 'hover:bg-dark'
                  }`}
                >
                  <Icon size={20} />
                  <span>{link.label}</span>
                </Link>
              );
            })}
          </div>
          
          {/* Status and Mobile Menu */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 bg-dark px-3 py-1 rounded">
              <div className="status-dot success"></div>
              <span className="text-sm text-gray-300 hidden sm:inline">API Connected</span>
            </div>
            
            {/* API Documentation Link */}
            <a
              href="http://localhost:8000/api/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden md:flex items-center gap-2 px-3 py-1 bg-primary text-white rounded hover:bg-primary/80 transition-colors"
            >
              <FileText size={16} />
              <span className="text-sm">API Docs</span>
            </a>
            
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 text-gray-300 hover:text-white hover:bg-dark rounded cursor-pointer"
            >
              {mobileMenuOpen ? (
                <X size={24} />
              ) : (
                <Menu size={24} />
              )}
            </button>
          </div>
        </div>
        
        {/* Mobile Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-primary bg-card">
            <div className="px-4 py-4 space-y-2">
              {navLinks.map((link) => {
                const Icon = link.icon;
                return (
                  <Link
                    key={link.path}
                    to={link.path}
                    onClick={() => setMobileMenuOpen(false)}
                    className={`flex items-center gap-3 px-4 py-3 rounded text-white font-medium transition-colors ${
                      isActive(link.path) 
                        ? 'bg-primary text-white' 
                        : 'hover:bg-dark'
                    }`}
                  >
                    <Icon size={20} />
                    <span>{link.label}</span>
                  </Link>
                );
              })}
              
              {/* API Documentation Link in Mobile Menu */}
              <a
                href="http://localhost:8000/api/docs"
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center gap-3 px-4 py-3 rounded text-white font-medium transition-colors hover:bg-dark"
              >
                <FileText size={20} />
                <span>API Documentation</span>
              </a>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Navbar; 