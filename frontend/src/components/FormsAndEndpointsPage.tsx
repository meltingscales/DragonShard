import React, { useState, useEffect } from 'react';
import { ApiService } from '../services/api';
import type { WebsitePageForm, WebsitePageEndpoint } from '../types/api';
import Button from './ui/Button';

const FormsAndEndpointsPage: React.FC = () => {
  const [forms, setForms] = useState<WebsitePageForm[]>([]);
  const [endpoints, setEndpoints] = useState<WebsitePageEndpoint[]>([]);
  const [activeTab, setActiveTab] = useState<'forms' | 'endpoints'>('forms');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [formsData, endpointsData] = await Promise.all([
        ApiService.getAllForms(),
        ApiService.getAllEndpoints(),
      ]);
      setForms(formsData.forms);
      setEndpoints(endpointsData.endpoints);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const filteredForms = forms.filter(form => 
    form.form_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    form.form_action?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    form.form_method.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredEndpoints = endpoints.filter(endpoint => 
    endpoint.endpoint_path?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    endpoint.method.toLowerCase().includes(searchTerm.toLowerCase()) ||
    endpoint.content_type?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-dark text-white p-6">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-dark text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-4">🎯 Fuzzing Targets</h1>
          <p className="text-gray-300 mb-6">
            Discovered forms and endpoints across all websites for fuzzing attacks.
          </p>
        </div>

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-lg font-semibold text-gray-300 mb-2">Total Forms</h3>
            <p className="text-3xl font-bold text-green-500">{forms.length}</p>
            <div className="mt-2 text-sm text-gray-400">
              {forms.filter(f => f.is_login_form).length} login forms
            </div>
          </div>
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-lg font-semibold text-gray-300 mb-2">Total Endpoints</h3>
            <p className="text-3xl font-bold text-blue-500">{endpoints.length}</p>
            <div className="mt-2 text-sm text-gray-400">
              {endpoints.filter(e => e.is_api_endpoint).length} API endpoints
            </div>
          </div>
        </div>

        {/* Search and Tabs */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 mb-8">
          <div className="p-6 border-b border-gray-700">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex-1">
                <input
                  type="text"
                  placeholder="Search forms and endpoints..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={() => setActiveTab('forms')}
                  variant={activeTab === 'forms' ? 'primary' : 'secondary'}
                  size="md"
                >
                  📝 Forms ({filteredForms.length})
                </Button>
                <Button
                  onClick={() => setActiveTab('endpoints')}
                  variant={activeTab === 'endpoints' ? 'primary' : 'secondary'}
                  size="md"
                >
                  🔗 Endpoints ({filteredEndpoints.length})
                </Button>
              </div>
            </div>
          </div>

          <div className="p-6">
            {/* Error Display */}
            {error && (
              <div className="bg-red-900 border border-red-700 text-red-200 px-4 py-3 rounded-lg mb-6">
                <strong>Error:</strong> {error}
              </div>
            )}

            {/* Forms Tab */}
            {activeTab === 'forms' && (
              <div>
                <h3 className="text-xl font-semibold mb-4">Discovered Forms</h3>
                <div className="space-y-4">
                  {filteredForms.length === 0 ? (
                    <div className="text-center text-gray-400 py-8">
                      <p>No forms found.</p>
                      {searchTerm && <p className="mt-2">Try adjusting your search terms.</p>}
                    </div>
                  ) : (
                    filteredForms.map((form) => (
                      <div key={form.form_id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                        <div className="flex items-start justify-between mb-3">
                          <div>
                            <h4 className="font-semibold text-green-400 mb-1">
                              {form.form_name || form.form_id}
                            </h4>
                            <p className="text-gray-400 text-sm">{form.form_action || 'No action'}</p>
                          </div>
                          <div className="flex gap-2">
                            {form.is_login_form && (
                              <span className="px-2 py-1 bg-blue-600 text-white text-xs rounded">Login</span>
                            )}
                            {form.is_search_form && (
                              <span className="px-2 py-1 bg-yellow-600 text-white text-xs rounded">Search</span>
                            )}
                            <span className="px-2 py-1 bg-gray-600 text-white text-xs rounded">
                              {form.form_method}
                            </span>
                          </div>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm mb-3">
                          <div>
                            <span className="text-gray-500">Fields:</span>
                            <span className="ml-2 text-white">{form.form_fields.length}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Class:</span>
                            <span className="ml-2 text-white">{form.form_class || 'N/A'}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Discovered:</span>
                            <span className="ml-2 text-white">{formatDate(form.discovered_at)}</span>
                          </div>
                        </div>
                        {form.form_fields.length > 0 && (
                          <div>
                            <h5 className="font-medium text-gray-300 mb-2">Form Fields:</h5>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                              {form.form_fields.map((field, index) => (
                                <div key={index} className="bg-gray-800 rounded p-2 text-xs">
                                  <div className="flex justify-between">
                                    <span className="text-gray-400">Name:</span>
                                    <span className="text-white">{field.name}</span>
                                  </div>
                                  <div className="flex justify-between">
                                    <span className="text-gray-400">Type:</span>
                                    <span className="text-white">{field.type}</span>
                                  </div>
                                  {field.required && (
                                    <div className="flex justify-between">
                                      <span className="text-gray-400">Required:</span>
                                      <span className="text-red-400">Yes</span>
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        <div className="mt-4 flex gap-2">
                          <Button variant="info" size="sm">
                            Test Form
                          </Button>
                          <Button variant="success" size="sm">
                            Stage Fuzzing
                          </Button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* Endpoints Tab */}
            {activeTab === 'endpoints' && (
              <div>
                <h3 className="text-xl font-semibold mb-4">Discovered Endpoints</h3>
                <div className="space-y-4">
                  {filteredEndpoints.length === 0 ? (
                    <div className="text-center text-gray-400 py-8">
                      <p>No endpoints found.</p>
                      {searchTerm && <p className="mt-2">Try adjusting your search terms.</p>}
                    </div>
                  ) : (
                    filteredEndpoints.map((endpoint) => (
                      <div key={endpoint.endpoint_id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                        <div className="flex items-start justify-between mb-3">
                          <div>
                            <h4 className="font-semibold text-purple-400 mb-1">
                              {endpoint.endpoint_path || endpoint.endpoint_id}
                            </h4>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                              <div>
                                <span className="text-gray-500">Method:</span>
                                <span className="ml-2 text-white">{endpoint.method}</span>
                              </div>
                              <div>
                                <span className="text-gray-500">Content Type:</span>
                                <span className="ml-2 text-white">{endpoint.content_type || 'N/A'}</span>
                              </div>
                              <div>
                                <span className="text-gray-500">API Endpoint:</span>
                                <span className={`ml-2 ${endpoint.is_api_endpoint ? 'text-green-500' : 'text-gray-400'}`}>
                                  {endpoint.is_api_endpoint ? 'Yes' : 'No'}
                                </span>
                              </div>
                            </div>
                          </div>
                          <div className="text-xs text-gray-500">
                            {formatDate(endpoint.discovered_at)}
                          </div>
                        </div>
                        <div className="mt-4 flex gap-2">
                          <Button variant="info" size="sm">
                            Test Endpoint
                          </Button>
                          <Button variant="success" size="sm">
                            Stage Fuzzing
                          </Button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default FormsAndEndpointsPage; 