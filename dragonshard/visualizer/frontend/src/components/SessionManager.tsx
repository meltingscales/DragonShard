import React, { useState, useEffect } from 'react';
import { ApiService } from '../services/api';
import type { Session, SessionSummary } from '../types/api';

const SessionManager: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [summary, setSummary] = useState<SessionSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadSessions();
    const interval = setInterval(loadSessions, 25000); // Refresh every 25 seconds
    return () => clearInterval(interval);
  }, []);

  const loadSessions = async () => {
    try {
      setError(null);
      const [sessionData, summaryData] = await Promise.all([
        ApiService.getSessions(),
        ApiService.getSessionSummary(),
      ]);
      setSessions(sessionData);
      setSummary(summaryData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load sessions');
    } finally {
      setLoading(false);
    }
  };

  const getAuthStatusColor = (authenticated: boolean) => {
    return authenticated ? 'bg-green-500' : 'bg-red-500';
  };

  if (loading) {
    return (
      <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
        <h3 className="text-dragon-primary font-semibold mb-4">🔐 Session Manager</h3>
        <div className="text-center text-gray-400">Loading...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
        <h3 className="text-dragon-primary font-semibold mb-4">🔐 Session Manager</h3>
        <div className="text-red-400">{error}</div>
      </div>
    );
  }

  return (
    <div className="bg-dragon-card border border-dragon-border rounded-lg p-6">
      <h3 className="text-dragon-primary font-semibold mb-4">🔐 Session Manager</h3>
      
      {/* Summary */}
      {summary && (
        <div className="grid grid-cols-4 gap-4 mb-6">
          <div className="bg-dragon-dark rounded-lg p-3 text-center">
            <div className="text-xl font-bold text-blue-400">{summary.total_sessions}</div>
            <div className="text-xs text-gray-400">Total Sessions</div>
          </div>
          <div className="bg-dragon-dark rounded-lg p-3 text-center">
            <div className="text-xl font-bold text-green-400">{summary.authenticated_sessions}</div>
            <div className="text-xs text-gray-400">Authenticated</div>
          </div>
          <div className="bg-dragon-dark rounded-lg p-3 text-center">
            <div className="text-xl font-bold text-yellow-400">{summary.active_sessions}</div>
            <div className="text-xs text-gray-400">Active</div>
          </div>
          <div className="bg-dragon-dark rounded-lg p-3 text-center">
            <div className="text-xl font-bold text-purple-400">{Object.keys(summary.by_target).length}</div>
            <div className="text-xs text-gray-400">Targets</div>
          </div>
        </div>
      )}

      {/* Sessions */}
      {sessions.length === 0 ? (
        <div className="text-center text-gray-400 py-8">
          No sessions found
        </div>
      ) : (
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {sessions.map((session) => (
            <div key={session.id} className="bg-dragon-dark border border-dragon-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h4 className="font-semibold text-white">{session.target}</h4>
                  <p className="text-sm text-gray-400">ID: {session.id}</p>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-1 rounded text-xs font-semibold ${getAuthStatusColor(session.authenticated)}`}>
                    {session.authenticated ? 'AUTH' : 'UNAUTH'}
                  </span>
                  {session.auth_method && (
                    <span className="px-2 py-1 rounded text-xs bg-gray-600">
                      {session.auth_method}
                    </span>
                  )}
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4 text-sm mb-3">
                <div>
                  <span className="text-gray-400">Requests:</span>
                  <div className="text-white">{session.requests_count}</div>
                </div>
                <div>
                  <span className="text-gray-400">Created:</span>
                  <div className="text-white">{new Date(session.created_at).toLocaleString()}</div>
                </div>
              </div>
              
              {/* Cookies */}
              {Object.keys(session.cookies).length > 0 && (
                <div className="mb-3">
                  <h5 className="text-sm font-semibold text-gray-300 mb-1">Cookies:</h5>
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(session.cookies).map(([key, value]) => (
                      <div key={key} className="bg-gray-700 px-2 py-1 rounded text-xs">
                        {key}: {value.substring(0, 10)}...
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              {/* Headers */}
              {Object.keys(session.headers).length > 0 && (
                <div>
                  <h5 className="text-sm font-semibold text-gray-300 mb-1">Headers:</h5>
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(session.headers).map(([key, value]) => (
                      <div key={key} className="bg-gray-700 px-2 py-1 rounded text-xs">
                        {key}: {value.substring(0, 15)}...
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              <div className="mt-2 text-xs text-gray-500">
                Last used: {new Date(session.last_used).toLocaleString()}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SessionManager; 