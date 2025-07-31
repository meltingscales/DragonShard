import React, { useState, useEffect } from 'react';
import { ApiService } from '../services/api';
import type { Website, WebsiteStatistics } from '../types/api';
import Button from './ui/Button';

const WebsitesPage: React.FC = () => {
  const [websites, setWebsites] = useState<Website[]>([]);
  const [statistics, setStatistics] = useState<WebsiteStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [crawling, setCrawling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [websitesData, statsData] = await Promise.all([
        ApiService.getWebsites(),
        ApiService.getWebsiteStatistics(),
      ]);
      setWebsites(websitesData.websites);
      setStatistics(statsData.statistics);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleCrawlAll = async () => {
    try {
      setCrawling(true);
      setError(null);
      const result = await ApiService.crawlAllWebsites();
      console.log('Crawl result:', result);
      await loadData(); // Reload data after crawling
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to crawl websites');
    } finally {
      setCrawling(false);
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

  return (
    <div className="min-h-screen bg-dark text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-4">🌐 Website Crawling</h1>
          <p className="text-gray-300 mb-6">
            Discover and analyze websites from HTTP/HTTPS services for form enumeration and fuzzing targets.
          </p>
        </div>

        {/* Statistics Cards */}
        {statistics && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold text-gray-300 mb-2">Total Websites</h3>
              <p className="text-3xl font-bold text-blue-500">{statistics.total_websites}</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold text-gray-300 mb-2">Total Pages</h3>
              <p className="text-3xl font-bold text-green-500">{statistics.total_pages}</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold text-gray-300 mb-2">Total Forms</h3>
              <p className="text-3xl font-bold text-yellow-500">{statistics.total_forms}</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold text-gray-300 mb-2">Total Endpoints</h3>
              <p className="text-3xl font-bold text-purple-500">{statistics.total_endpoints}</p>
            </div>
          </div>
        )}

        {/* Status Distribution */}
        {statistics && (
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 mb-8">
            <h3 className="text-xl font-semibold mb-4">Website Status Distribution</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Object.entries(statistics.websites_by_status).map(([status, count]) => (
                <div key={status} className="text-center">
                  <p className="text-2xl font-bold text-blue-500">{count}</p>
                  <p className="text-sm text-gray-400 capitalize">{status}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 mb-8">
          <h3 className="text-xl font-semibold mb-4">Actions</h3>
          <div className="flex flex-wrap gap-4">
            <Button
              onClick={handleCrawlAll}
              disabled={crawling}
              variant="primary"
              size="lg"
            >
              {crawling ? (
                <span className="flex items-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Crawling...
                </span>
              ) : (
                '🕷️ Crawl All Websites'
              )}
            </Button>
            <Button
              onClick={loadData}
              variant="secondary"
              size="lg"
            >
              🔄 Refresh Data
            </Button>
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-900 border border-red-700 text-red-200 px-4 py-3 rounded-lg mb-6">
            <strong>Error:</strong> {error}
          </div>
        )}

        {/* Websites List */}
        <div className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="p-6 border-b border-gray-700">
            <h3 className="text-xl font-semibold">Discovered Websites</h3>
            <p className="text-gray-400 mt-1">
              {websites.length} website{websites.length !== 1 ? 's' : ''} found
            </p>
          </div>
          <div className="divide-y divide-gray-700">
            {websites.length === 0 ? (
              <div className="p-6 text-center text-gray-400">
                <p>No websites discovered yet.</p>
                <p className="mt-2">Click "Crawl All Websites" to start discovering websites.</p>
              </div>
            ) : (
              websites.map((website) => (
                <div key={website.website_id} className="p-6 hover:bg-gray-750 transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h4 className="text-lg font-semibold text-blue-400">
                          {website.title || website.base_url}
                        </h4>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(website.crawl_status)}`}>
                          {website.crawl_status}
                        </span>
                      </div>
                      <p className="text-gray-400 text-sm mb-3">{website.base_url}</p>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <span className="text-gray-500">Pages:</span>
                          <span className="ml-2 text-white">{website.total_pages}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Forms:</span>
                          <span className="ml-2 text-white">{website.total_forms}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Endpoints:</span>
                          <span className="ml-2 text-white">{website.total_endpoints}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Depth:</span>
                          <span className="ml-2 text-white">{website.crawl_depth}</span>
                        </div>
                      </div>
                      <div className="mt-3 text-xs text-gray-500">
                        <span>Discovered: {formatDate(website.discovered_at)}</span>
                        {website.last_crawled_at !== website.discovered_at && (
                          <span className="ml-4">Last crawled: {formatDate(website.last_crawled_at)}</span>
                        )}
                      </div>
                    </div>
                    <div className="flex flex-col gap-2">
                      <Button variant="info" size="sm">
                        View Details
                      </Button>
                      <Button variant="success" size="sm">
                        View Forms
                      </Button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default WebsitesPage; 