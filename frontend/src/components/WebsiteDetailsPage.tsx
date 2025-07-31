import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { ApiService } from '../services/api';
import type { Website, WebsitePage, WebsitePageForm, WebsitePageEndpoint } from '../types/api';

const WebsiteDetailsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [website, setWebsite] = useState<Website | null>(null);
  const [pages, setPages] = useState<WebsitePage[]>([]);
  const [forms, setForms] = useState<WebsitePageForm[]>([]);
  const [endpoints, setEndpoints] = useState<WebsitePageEndpoint[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'pages' | 'forms' | 'endpoints'>('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (id) {
      loadWebsiteData();
    }
  }, [id]);

  const loadWebsiteData = async () => {
    if (!id) return;
    
    try {
      setLoading(true);
      const [websiteData, pagesData, formsData, endpointsData] = await Promise.all([
        ApiService.getWebsite(id),
        ApiService.getWebsitePages(id),
        ApiService.getWebsiteForms(id),
        ApiService.getWebsiteEndpoints(id),
      ]);
      
      setWebsite(websiteData);
      setPages(pagesData.pages);
      setForms(formsData.forms);
      setEndpoints(endpointsData.endpoints);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load website data');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'text-green-500';
      case 'crawling':
        return 'text-yellow-500';
      case 'failed':
        return 'text-red-500';
      case 'pending':
        return 'text-gray-500';
      default:
        return 'text-gray-400';
    }
  };

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

  if (error || !website) {
    return (
      <div className="min-h-screen bg-dark text-white p-6">
        <div className="max-w-7xl mx-auto">
          <div className="bg-red-900 border border-red-700 text-red-200 px-4 py-3 rounded-lg">
            <strong>Error:</strong> {error || 'Website not found'}
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
          <div className="flex items-center gap-4 mb-4">
            <button
              onClick={() => window.history.back()}
              className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors"
            >
              ← Back
            </button>
            <h1 className="text-4xl font-bold">🌐 Website Details</h1>
          </div>
          <div className="flex items-center gap-3 mb-2">
            <h2 className="text-2xl font-semibold text-blue-400">
              {website.title || website.base_url}
            </h2>
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(website.crawl_status)}`}>
              {website.crawl_status}
            </span>
          </div>
          <p className="text-gray-400">{website.base_url}</p>
        </div>

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-lg font-semibold text-gray-300 mb-2">Pages</h3>
            <p className="text-3xl font-bold text-blue-500">{website.total_pages}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-lg font-semibold text-gray-300 mb-2">Forms</h3>
            <p className="text-3xl font-bold text-green-500">{website.total_forms}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-lg font-semibold text-gray-300 mb-2">Endpoints</h3>
            <p className="text-3xl font-bold text-yellow-500">{website.total_endpoints}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-lg font-semibold text-gray-300 mb-2">Crawl Depth</h3>
            <p className="text-3xl font-bold text-purple-500">{website.crawl_depth}</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 mb-8">
          <div className="border-b border-gray-700">
            <nav className="flex space-x-8 px-6">
              {[
                { id: 'overview', label: 'Overview', icon: '📊' },
                { id: 'pages', label: 'Pages', icon: '📄' },
                { id: 'forms', label: 'Forms', icon: '📝' },
                { id: 'endpoints', label: 'Endpoints', icon: '🔗' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-400'
                      : 'border-transparent text-gray-400 hover:text-gray-300'
                  }`}
                >
                  <span className="mr-2">{tab.icon}</span>
                  {tab.label}
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div>
                <h3 className="text-xl font-semibold mb-4">Website Overview</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="bg-gray-750 rounded-lg p-4">
                    <h4 className="font-semibold mb-3">Basic Information</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Base URL:</span>
                        <span className="text-white">{website.base_url}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Title:</span>
                        <span className="text-white">{website.title || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Status:</span>
                        <span className={`${getStatusColor(website.crawl_status)}`}>
                          {website.crawl_status}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Discovered:</span>
                        <span className="text-white">{formatDate(website.discovered_at)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Last Crawled:</span>
                        <span className="text-white">{formatDate(website.last_crawled_at)}</span>
                      </div>
                    </div>
                  </div>
                  <div className="bg-gray-750 rounded-lg p-4">
                    <h4 className="font-semibold mb-3">Crawl Settings</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Max Pages:</span>
                        <span className="text-white">{website.max_pages}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Crawl Depth:</span>
                        <span className="text-white">{website.crawl_depth}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Pages Tab */}
            {activeTab === 'pages' && (
              <div>
                <h3 className="text-xl font-semibold mb-4">Discovered Pages ({pages.length})</h3>
                <div className="space-y-4">
                  {pages.map((page) => (
                    <div key={page.page_id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <h4 className="font-semibold text-blue-400 mb-1">{page.title || page.url}</h4>
                          <p className="text-gray-400 text-sm mb-2">{page.url}</p>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                            <div>
                              <span className="text-gray-500">Method:</span>
                              <span className="ml-2 text-white">{page.method}</span>
                            </div>
                            <div>
                              <span className="text-gray-500">Status:</span>
                              <span className={`ml-2 ${page.status_code && page.status_code < 400 ? 'text-green-500' : 'text-red-500'}`}>
                                {page.status_code || 'N/A'}
                              </span>
                            </div>
                            <div>
                              <span className="text-gray-500">Size:</span>
                              <span className="ml-2 text-white">{page.response_size ? `${page.response_size} bytes` : 'N/A'}</span>
                            </div>
                            <div>
                              <span className="text-gray-500">Depth:</span>
                              <span className="ml-2 text-white">{page.depth}</span>
                            </div>
                          </div>
                        </div>
                        <div className="text-xs text-gray-500">
                          {formatDate(page.discovered_at)}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Forms Tab */}
            {activeTab === 'forms' && (
              <div>
                <h3 className="text-xl font-semibold mb-4">Discovered Forms ({forms.length})</h3>
                <div className="space-y-4">
                  {forms.map((form) => (
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
                        </div>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm mb-3">
                        <div>
                          <span className="text-gray-500">Method:</span>
                          <span className="ml-2 text-white">{form.form_method}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Fields:</span>
                          <span className="ml-2 text-white">{form.form_fields.length}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Class:</span>
                          <span className="ml-2 text-white">{form.form_class || 'N/A'}</span>
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
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Endpoints Tab */}
            {activeTab === 'endpoints' && (
              <div>
                <h3 className="text-xl font-semibold mb-4">Discovered Endpoints ({endpoints.length})</h3>
                <div className="space-y-4">
                  {endpoints.map((endpoint) => (
                    <div key={endpoint.endpoint_id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
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
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default WebsiteDetailsPage; 