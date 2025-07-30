import React, { useState } from 'react';
import { ArrowLeft, Save, X } from 'lucide-react';
import { ApiService } from '../services/api';

interface TargetFormData {
  ip_address: string;
  hostname?: string;
  description?: string;
}

const AddTargetPage: React.FC = () => {
  const [formData, setFormData] = useState<TargetFormData>({
    ip_address: '',
    hostname: '',
    description: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await ApiService.addTarget(formData);
      setSuccess(true);
      setTimeout(() => {
        window.close();
      }, 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add target');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    window.close();
  };

  return (
    <div className="min-h-screen bg-dark text-white">
      {/* Header */}
      <div className="bg-primary p-6">
        <div className="container">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <button
                onClick={handleClose}
                className="mr-4 text-white hover:text-gray-200"
              >
                <X className="w-6 h-6" />
              </button>
              <h1 className="text-2xl font-bold">Add New Target</h1>
            </div>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="container p-6">
        {error && (
          <div className="bg-danger text-white p-4 rounded mb-6">
            <div className="flex items-center">
              <span>{error}</span>
            </div>
          </div>
        )}

        {success && (
          <div className="bg-success text-white p-4 rounded mb-6">
            <div className="flex items-center">
              <span>Target added successfully! Window will close automatically.</span>
            </div>
          </div>
        )}

        <div className="card max-w-md mx-auto">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                IP Address *
              </label>
              <input
                type="text"
                required
                value={formData.ip_address}
                onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
                className="w-full bg-card border border-border rounded px-4 py-3 text-white"
                placeholder="192.168.1.1"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Hostname (Optional)
              </label>
              <input
                type="text"
                value={formData.hostname}
                onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                className="w-full bg-card border border-border rounded px-4 py-3 text-white"
                placeholder="target.example.com"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Description (Optional)
              </label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="w-full bg-card border border-border rounded px-4 py-3 text-white"
                rows={4}
                placeholder="Target description..."
              />
            </div>

            <div className="flex gap-4">
              <button
                type="submit"
                disabled={loading}
                className="btn btn-primary flex-1 flex items-center justify-center"
              >
                {loading ? (
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                ) : (
                  <>
                    <Save className="w-5 h-5 mr-2" />
                    Add Target
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={handleClose}
                className="btn btn-secondary flex-1"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default AddTargetPage; 