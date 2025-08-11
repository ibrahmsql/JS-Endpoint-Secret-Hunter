import React, { useState, useEffect, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

// Caido SDK types for frontend
interface CaidoUI {
  addTab(options: {
    id: string;
    label: string;
    content: React.ReactElement;
  }): void;
}

interface CaidoCommands {
  run(id: string, ...args: any[]): Promise<any>;
}

interface CaidoConsole {
  log(...args: any[]): void;
  error(...args: any[]): void;
}

interface Caido {
  ui: CaidoUI;
  commands: CaidoCommands;
  console: CaidoConsole;
}

declare global {
  const caido: Caido;
}

export interface ScanResult {
  id: string;
  type: 'endpoint' | 'secret' | 'email' | 'ip';
  value: string;
  source: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: number;
  context?: string;
}

interface Statistics {
  total: number;
  endpoints: number;
  secrets: number;
  emails: number;
  ips: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

const JSHunterUI: React.FC = () => {
  const [results, setResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<keyof ScanResult>('timestamp');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [showExportModal, setShowExportModal] = useState(false);

  // Load results on component mount
  useEffect(() => {
    loadResults();
    // Auto-refresh every 5 seconds
    const interval = setInterval(loadResults, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadResults = async () => {
    try {
      const data = await caido.commands.run('js-hunter.get-results');
      setResults(data || []);
    } catch (error) {
      caido.console.error('Failed to load results:', error);
    }
  };

  const clearResults = async () => {
    if (confirm('Are you sure you want to clear all scan results?')) {
      try {
        setLoading(true);
        await caido.commands.run('js-hunter.clear-results');
        setResults([]);
        caido.console.log('Results cleared successfully');
      } catch (error) {
        caido.console.error('Failed to clear results:', error);
      } finally {
        setLoading(false);
      }
    }
  };

  const exportResults = async (format: 'json' | 'csv') => {
    try {
      setLoading(true);
      const exportData = await caido.commands.run('js-hunter.export-results', format);
      
      // Create download link
      const blob = new Blob([exportData], {
        type: format === 'json' ? 'application/json' : 'text/csv'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `js-hunter-results-${new Date().toISOString().split('T')[0]}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      setShowExportModal(false);
      caido.console.log(`Results exported as ${format.toUpperCase()}`);
    } catch (error) {
      caido.console.error('Failed to export results:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleScanner = async () => {
    try {
      await caido.commands.run('js-hunter.toggle-scanner');
      caido.console.log('Scanner toggled');
    } catch (error) {
      caido.console.error('Failed to toggle scanner:', error);
    }
  };

  // Filter and sort results
  const filteredResults = useMemo(() => {
    let filtered = results.filter((result: ScanResult) => {
      const matchesSearch = result.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           result.source.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesType = typeFilter === 'all' || result.type === typeFilter;
      const matchesSeverity = severityFilter === 'all' || result.severity === severityFilter;
      
      return matchesSearch && matchesType && matchesSeverity;
    });

    // Sort results
    filtered.sort((a: ScanResult, b: ScanResult) => {
      const aVal = a[sortBy];
      const bVal = b[sortBy];
      
      if (typeof aVal === 'string' && typeof bVal === 'string') {
        return sortOrder === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      }
      
      if (typeof aVal === 'number' && typeof bVal === 'number') {
        return sortOrder === 'asc' ? aVal - bVal : bVal - aVal;
      }
      
      return 0;
    });

    return filtered;
  }, [results, searchTerm, typeFilter, severityFilter, sortBy, sortOrder]);

  // Calculate statistics
  const statistics: Statistics = useMemo(() => {
    const stats: Statistics = {
      total: results.length,
      endpoints: 0,
      secrets: 0,
      emails: 0,
      ips: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    results.forEach((result: ScanResult) => {
      (stats as any)[result.type]++;
      (stats as any)[result.severity]++;
    });

    return stats;
  }, [results]);

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#d97706';
      case 'low': return '#65a30d';
      default: return '#6b7280';
    }
  };

  const getTypeColor = (type: string): string => {
    switch (type) {
      case 'endpoint': return '#2563eb';
      case 'secret': return '#dc2626';
      case 'email': return '#7c3aed';
      case 'ip': return '#059669';
      default: return '#6b7280';
    }
  };

  const formatTimestamp = (timestamp: number): string => {
    return new Date(timestamp).toLocaleString('en-US');
  };

  const handleSort = (column: keyof ScanResult) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(column);
      setSortOrder('desc');
    }
  };

  return (
    <div className="js-hunter-container">
      {/* Header */}
      <div className="js-hunter-header">
        <div className="header-title">
          <h2>🔍 JS Endpoint & Secret Hunter</h2>
          <span className="version">v2.0.0</span>
        </div>
        
        {/* Statistics */}
        <div className="statistics">
          <div className="stat-item">
            <span className="stat-label">Total:</span>
            <span className="stat-value">{statistics.total}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Endpoint:</span>
            <span className="stat-value" style={{ color: getTypeColor('endpoint') }}>
              {statistics.endpoints}
            </span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Secret:</span>
            <span className="stat-value" style={{ color: getTypeColor('secret') }}>
              {statistics.secrets}
            </span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Email:</span>
            <span className="stat-value" style={{ color: getTypeColor('email') }}>
              {statistics.emails}
            </span>
          </div>
          <div className="stat-item">
            <span className="stat-label">IP:</span>
            <span className="stat-value" style={{ color: getTypeColor('ip') }}>
              {statistics.ips}
            </span>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="js-hunter-controls">
        <div className="controls-left">
          <input
            type="text"
            placeholder="Search..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
          
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="filter-select"
          >
            <option value="all">All Types</option>
            <option value="endpoint">Endpoint</option>
            <option value="secret">Secret</option>
            <option value="email">Email</option>
            <option value="ip">IP</option>
          </select>
          
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="filter-select"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        
        <div className="controls-right">
          <button
            onClick={toggleScanner}
            className="btn btn-secondary"
            disabled={loading}
          >
            🔄 Toggle Scanner
          </button>
          
          <button
            onClick={() => setShowExportModal(true)}
            className="btn btn-primary"
            disabled={loading || results.length === 0}
          >
            📤 Export
          </button>
          
          <button
            onClick={clearResults}
            className="btn btn-danger"
            disabled={loading || results.length === 0}
          >
            🗑️ Clear
          </button>
          
          <button
            onClick={loadResults}
            className="btn btn-secondary"
            disabled={loading}
          >
            {loading ? '⏳' : '🔄'} Refresh
          </button>
        </div>
      </div>

      {/* Results Table */}
      <div className="js-hunter-results">
        {filteredResults.length === 0 ? (
          <div className="empty-state">
            {results.length === 0 ? (
              <p>No scan results found yet. Make sure the scanner is active and requests are being made within scope.</p>
            ) : (
              <p>No results match the current filters.</p>
            )}
          </div>
        ) : (
          <table className="results-table">
            <thead>
              <tr>
                <th onClick={() => handleSort('type')} className="sortable">
                  Type {sortBy === 'type' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('severity')} className="sortable">
                  Severity {sortBy === 'severity' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('value')} className="sortable">
                  Value {sortBy === 'value' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('source')} className="sortable">
                  Source {sortBy === 'source' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
                <th onClick={() => handleSort('timestamp')} className="sortable">
                  Time {sortBy === 'timestamp' && (sortOrder === 'asc' ? '↑' : '↓')}
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredResults.map((result) => (
                <tr key={result.id}>
                  <td>
                    <span
                      className="type-badge"
                      style={{ backgroundColor: getTypeColor(result.type) }}
                    >
                      {result.type.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <span
                      className="severity-badge"
                      style={{ backgroundColor: getSeverityColor(result.severity) }}
                    >
                      {result.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="value-cell">
                    <code>{result.value}</code>
                    {result.context && (
                      <div className="context">
                        <small>{result.context}</small>
                      </div>
                    )}
                  </td>
                  <td className="source-cell">
                    <a
                      href={result.source}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="source-link"
                    >
                      {result.source}
                    </a>
                  </td>
                  <td className="timestamp-cell">
                    {formatTimestamp(result.timestamp)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Export Modal */}
      {showExportModal && (
        <div className="modal-overlay" onClick={() => setShowExportModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Export Results</h3>
              <button
                onClick={() => setShowExportModal(false)}
                className="modal-close"
              >
                ✕
              </button>
            </div>
            <div className="modal-body">
              <p>Which format would you like to export?</p>
              <div className="export-options">
                <button
                  onClick={() => exportResults('json')}
                  className="btn btn-primary"
                  disabled={loading}
                >
                  📄 JSON Format
                </button>
                <button
                  onClick={() => exportResults('csv')}
                  className="btn btn-primary"
                  disabled={loading}
                >
                  📊 CSV Format
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Loading Overlay */}
      {loading && (
        <div className="loading-overlay">
          <div className="loading-spinner">⏳ Processing...</div>
        </div>
      )}


    </div>
  );
};

// Initialize the plugin UI
export function init() {
  try {
    caido.ui.addTab({
      id: 'js-hunter',
      label: '🔍 JS Hunter',
      content: <JSHunterUI />
    });
    
    caido.console.log('JS Endpoint & Secret Hunter UI initialized successfully');
  } catch (error) {
    caido.console.error('Failed to initialize JS Hunter UI:', error);
  }
}

// Auto-initialize when loaded
if (typeof window !== 'undefined' && window.document) {
  init();
}