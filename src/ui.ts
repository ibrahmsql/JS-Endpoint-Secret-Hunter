import { ScanResult } from './scanner';
import { getMatchTypeColor } from './patterns';

export interface PluginStats {
  totalResults: number;
  secretsCount: number;
  endpointsCount: number;
  emailsCount: number;
  ipsCount: number;
  filesScanned: number;
  lastScanTime?: Date;
}

export class PluginUI {
  private container: HTMLElement;
  private resultsTable!: HTMLTableElement;
  private resultsBody!: HTMLTableSectionElement;
  private statusElement!: HTMLElement;
  private statsContainer!: HTMLElement;
  private searchInput!: HTMLInputElement;
  private filterSelect!: HTMLSelectElement;
  private severityFilter!: HTMLSelectElement;
  private results: ScanResult[] = [];
  private stats: PluginStats = {
    totalResults: 0,
    secretsCount: 0,
    endpointsCount: 0,
    emailsCount: 0,
    ipsCount: 0,
    filesScanned: 0
  };
  private onExportCallback?: (format: 'json' | 'csv') => string;
  private onClearCallback?: () => void;
  private onResultClickCallback?: (result: ScanResult) => void;

  constructor(container: HTMLElement) {
    this.container = container;
    this.createUI();
  }

  private createUI(): void {
    this.container.innerHTML = `
      <div class="js-hunter-plugin">
        <div class="plugin-header">
          <div class="header-content">
            <h1>🔍 JS Endpoint & Secret Hunter</h1>
            <div class="header-subtitle">JavaScript Security Analysis Tool</div>
          </div>
          <div class="plugin-warning">
            ⚠️ <strong>Ethical Use Warning:</strong> Only use this plugin on authorized targets within your defined scope.
          </div>
        </div>
        
        <div class="stats-dashboard" id="stats-container">
          <div class="stats-grid">
            <div class="stat-card total">
              <div class="stat-icon">📊</div>
              <div class="stat-content">
                <div class="stat-number" id="total-count">0</div>
                <div class="stat-label">Total Findings</div>
              </div>
            </div>
            <div class="stat-card secrets">
              <div class="stat-icon">🔑</div>
              <div class="stat-content">
                <div class="stat-number" id="secrets-count">0</div>
                <div class="stat-label">Secrets & Keys</div>
              </div>
            </div>
            <div class="stat-card endpoints">
              <div class="stat-icon">🌐</div>
              <div class="stat-content">
                <div class="stat-number" id="endpoints-count">0</div>
                <div class="stat-label">API Endpoints</div>
              </div>
            </div>
            <div class="stat-card emails">
              <div class="stat-icon">📧</div>
              <div class="stat-content">
                <div class="stat-number" id="emails-count">0</div>
                <div class="stat-label">Email Addresses</div>
              </div>
            </div>
            <div class="stat-card ips">
              <div class="stat-icon">🖥️</div>
              <div class="stat-content">
                <div class="stat-number" id="ips-count">0</div>
                <div class="stat-label">IP Addresses</div>
              </div>
            </div>
            <div class="stat-card files">
              <div class="stat-icon">📁</div>
              <div class="stat-content">
                <div class="stat-number" id="files-count">0</div>
                <div class="stat-label">Files Scanned</div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="plugin-controls">
          <div class="controls-row">
            <div class="search-group">
              <input type="text" id="search-input" class="search-input" placeholder="🔍 Search results...">
            </div>
            <div class="filter-group">
              <select id="filter-select" class="filter-select">
                <option value="all">All Types</option>
                <option value="secret">🔑 Secrets/Keys</option>
                <option value="endpoint">🌐 Endpoints</option>
                <option value="email">📧 Emails</option>
                <option value="ip">🖥️ IP Addresses</option>
              </select>
              <select id="severity-filter" class="filter-select">
                <option value="all">All Severity</option>
                <option value="high">🔴 High Risk</option>
                <option value="medium">🟡 Medium Risk</option>
                <option value="low">🟢 Low Risk</option>
              </select>
            </div>
            <div class="action-group">
              <button id="export-json-btn" class="btn btn-secondary">📄 Export JSON</button>
              <button id="export-csv-btn" class="btn btn-secondary">📊 Export CSV</button>
              <button id="clear-btn" class="btn btn-danger">🗑️ Clear All</button>
            </div>
          </div>
        </div>
        
        <div class="plugin-status">
          <div class="status-content">
            <div class="status-indicator" id="status-indicator">🟢</div>
            <span id="status-text">Ready to scan - Monitoring HTTP traffic...</span>
            <div class="status-time" id="last-scan-time"></div>
          </div>
        </div>
        
        <div class="results-container">
          <div class="results-header">
            <h3>🔍 Detection Results</h3>
            <div class="results-info">
              <span id="results-count">0 results</span>
            </div>
          </div>
          <div class="table-container">
            <table class="results-table">
              <thead>
                <tr>
                  <th class="col-severity">Risk</th>
                  <th class="col-type">Type</th>
                  <th class="col-value">Value</th>
                  <th class="col-file">File</th>
                  <th class="col-source">Source</th>
                  <th class="col-time">Time</th>
                  <th class="col-actions">Actions</th>
                </tr>
              </thead>
              <tbody id="results-body">
                <tr class="no-results">
                  <td colspan="7">
                    <div class="empty-state">
                      <div class="empty-icon">🔍</div>
                      <div class="empty-title">No findings yet</div>
                      <div class="empty-description">Start browsing to detect JavaScript files and security findings</div>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    // Add CSS styles
    this.addStyles();

    // Get references to elements
    this.resultsTable = this.container.querySelector('.results-table') as HTMLTableElement;
    this.resultsBody = this.container.querySelector('#results-body') as HTMLTableSectionElement;
    this.statusElement = this.container.querySelector('#status-text') as HTMLElement;
    this.filterSelect = this.container.querySelector('#filter-select') as HTMLSelectElement;

    // Setup event listeners
    this.setupEventListeners();
  }

  private addStyles(): void {
    const style = document.createElement('style');
    style.textContent = `
      .js-hunter-plugin {
        padding: 24px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
        background: linear-gradient(135deg, #0f0f0f 0%, #1a1a1a 100%);
        color: #e8e8e8;
        min-height: 100vh;
        line-height: 1.6;
      }
      
      /* Header Styles */
      .plugin-header {
        margin-bottom: 32px;
      }
      
      .header-content {
        margin-bottom: 16px;
      }
      
      .header-content h1 {
        margin: 0;
        color: #00d4aa;
        font-size: 32px;
        font-weight: 700;
        background: linear-gradient(135deg, #00d4aa 0%, #00a693 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
      }
      
      .header-subtitle {
        color: #a0a0a0;
        font-size: 16px;
        font-weight: 400;
        margin-top: 8px;
      }
      
      .plugin-warning {
        background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
        color: #000;
        padding: 16px 20px;
        border-radius: 12px;
        font-size: 14px;
        font-weight: 500;
        box-shadow: 0 4px 12px rgba(255, 107, 53, 0.2);
        border-left: 4px solid #ff4500;
      }
      
      /* Stats Dashboard */
      .stats-dashboard {
        margin-bottom: 32px;
      }
      
      .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 16px;
      }
      
      .stat-card {
        background: linear-gradient(135deg, #2a2a2a 0%, #1f1f1f 100%);
        border: 1px solid #333;
        border-radius: 16px;
        padding: 20px;
        display: flex;
        align-items: center;
        gap: 16px;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
      }
      
      .stat-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: var(--accent-color);
      }
      
      .stat-card.total { --accent-color: #00d4aa; }
      .stat-card.secrets { --accent-color: #ff6b6b; }
      .stat-card.endpoints { --accent-color: #4ecdc4; }
      .stat-card.emails { --accent-color: #45b7d1; }
      .stat-card.ips { --accent-color: #96ceb4; }
      .stat-card.files { --accent-color: #feca57; }
      
      .stat-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
        border-color: var(--accent-color);
      }
      
      .stat-icon {
        font-size: 24px;
        opacity: 0.8;
      }
      
      .stat-content {
        flex: 1;
      }
      
      .stat-number {
        font-size: 28px;
        font-weight: 700;
        color: var(--accent-color);
        line-height: 1;
      }
      
      .stat-label {
        font-size: 13px;
        color: #a0a0a0;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 4px;
      }
      
      /* Controls */
      .plugin-controls {
        margin-bottom: 24px;
      }
      
      .controls-row {
        display: flex;
        gap: 20px;
        align-items: center;
        padding: 20px;
        background: linear-gradient(135deg, #2a2a2a 0%, #1f1f1f 100%);
        border: 1px solid #333;
        border-radius: 16px;
        flex-wrap: wrap;
      }
      
      .search-group {
        flex: 1;
        min-width: 250px;
      }
      
      .search-input {
        width: 100%;
        padding: 12px 16px;
        background: #1a1a1a;
        border: 2px solid #333;
        border-radius: 12px;
        color: #e8e8e8;
        font-size: 14px;
        transition: all 0.3s ease;
      }
      
      .search-input:focus {
        outline: none;
        border-color: #00d4aa;
        box-shadow: 0 0 0 3px rgba(0, 212, 170, 0.1);
      }
      
      .filter-group {
        display: flex;
        gap: 12px;
      }
      
      .filter-select {
        padding: 12px 16px;
        background: #1a1a1a;
        color: #e8e8e8;
        border: 2px solid #333;
        border-radius: 12px;
        font-size: 14px;
        cursor: pointer;
        transition: all 0.3s ease;
        min-width: 140px;
      }
      
      .filter-select:focus {
        outline: none;
        border-color: #00d4aa;
      }
      
      .action-group {
        display: flex;
        gap: 8px;
      }
      
      .btn {
        padding: 12px 20px;
        border: none;
        border-radius: 12px;
        cursor: pointer;
        font-size: 14px;
        font-weight: 600;
        transition: all 0.3s ease;
        display: flex;
        align-items: center;
        gap: 8px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }
      
      .btn-secondary {
        background: linear-gradient(135deg, #4a5568 0%, #2d3748 100%);
        color: #e8e8e8;
        border: 1px solid #4a5568;
      }
      
      .btn-secondary:hover {
        background: linear-gradient(135deg, #5a6578 0%, #3d4758 100%);
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(74, 85, 104, 0.3);
      }
      
      .btn-danger {
        background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);
        color: white;
        border: 1px solid #e53e3e;
      }
      
      .btn-danger:hover {
        background: linear-gradient(135deg, #f56565 0%, #e53e3e 100%);
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(229, 62, 62, 0.3);
      }
      
      /* Status Section */
      .plugin-status {
        margin-bottom: 24px;
        padding: 16px 20px;
        background: linear-gradient(135deg, #2a2a2a 0%, #1f1f1f 100%);
        border: 1px solid #333;
        border-radius: 16px;
      }
      
      .status-content {
        display: flex;
        align-items: center;
        gap: 12px;
      }
      
      .status-indicator {
        font-size: 16px;
        animation: pulse 2s infinite;
      }
      
      .status-time {
        margin-left: auto;
        font-size: 12px;
        color: #a0a0a0;
      }
      
      @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
      }
      
      /* Results Section */
      .results-container {
        background: linear-gradient(135deg, #2a2a2a 0%, #1f1f1f 100%);
        border: 1px solid #333;
        border-radius: 16px;
        overflow: hidden;
      }
      
      .results-header {
        padding: 20px;
        border-bottom: 1px solid #333;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
      
      .results-header h3 {
        margin: 0;
        color: #00d4aa;
        font-size: 18px;
        font-weight: 600;
      }
      
      .results-info {
        color: #a0a0a0;
        font-size: 14px;
      }
      
      .table-container {
        overflow-x: auto;
      }
      
      .results-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
      }
      
      .results-table th {
        background: linear-gradient(135deg, #3a3a3a 0%, #2f2f2f 100%);
        color: #e8e8e8;
        padding: 16px 12px;
        text-align: left;
        font-weight: 600;
        border-bottom: 2px solid #00d4aa;
        position: sticky;
        top: 0;
        z-index: 10;
      }
      
      .results-table td {
        padding: 12px;
        border-bottom: 1px solid #333;
        vertical-align: middle;
      }
      
      .results-table tr:hover {
        background: rgba(0, 212, 170, 0.05);
      }
      
      .col-severity { width: 80px; }
      .col-type { width: 120px; }
      .col-value { width: 250px; }
      .col-file { width: 200px; }
      .col-source { width: 200px; }
      .col-time { width: 120px; }
      .col-actions { width: 100px; }
      
      .empty-state {
        text-align: center;
        padding: 60px 20px;
        color: #666;
      }
      
      .empty-icon {
        font-size: 48px;
        margin-bottom: 16px;
        opacity: 0.5;
      }
      
      .empty-title {
        font-size: 18px;
        font-weight: 600;
        margin-bottom: 8px;
        color: #888;
      }
      
      .empty-description {
        font-size: 14px;
        color: #666;
      }
      
      .severity-badge {
        display: inline-flex;
        align-items: center;
        padding: 4px 8px;
        border-radius: 8px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }
      
      .severity-high { background: rgba(255, 107, 107, 0.2); color: #ff6b6b; }
      .severity-medium { background: rgba(255, 206, 84, 0.2); color: #ffce54; }
      .severity-low { background: rgba(150, 206, 180, 0.2); color: #96ceb4; }
      
      .match-type {
        display: inline-flex;
        align-items: center;
        padding: 6px 12px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        gap: 4px;
      }
      
      .url-cell {
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 12px;
      }
      
      .match-value {
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        background: rgba(0, 212, 170, 0.1);
        padding: 6px 10px;
        border-radius: 8px;
        font-size: 12px;
        word-break: break-all;
        border: 1px solid rgba(0, 212, 170, 0.2);
        max-width: 250px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      
      .file-url {
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      
      .source-url {
        max-width: 150px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      
      .timestamp {
        font-size: 11px;
        color: #888;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
      }
      
      .action-btn {
        padding: 4px 8px;
        background: rgba(0, 212, 170, 0.1);
        border: 1px solid rgba(0, 212, 170, 0.3);
        border-radius: 6px;
        color: #00d4aa;
        font-size: 11px;
        cursor: pointer;
        transition: all 0.2s ease;
      }
      
      .action-btn:hover {
        background: rgba(0, 212, 170, 0.2);
        border-color: #00d4aa;
      }
      
      .message {
        position: fixed;
        top: 24px;
        right: 24px;
        padding: 16px 24px;
        border-radius: 12px;
        color: white;
        font-weight: 600;
        z-index: 1000;
        animation: slideIn 0.3s ease;
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
        border-left: 4px solid currentColor;
      }
      
      .message.info { background: linear-gradient(135deg, #3182ce 0%, #2c5aa0 100%); }
      .message.success { background: linear-gradient(135deg, #38a169 0%, #2f855a 100%); }
      .message.warning { background: linear-gradient(135deg, #d69e2e 0%, #b7791f 100%); }
      .message.error { background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%); }
      
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      
      /* Match Type Colors */
      .type-api { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%); color: white; }
      .type-secret { background: linear-gradient(135deg, #4ecdc4 0%, #44a08d 100%); color: white; }
      .type-token { background: linear-gradient(135deg, #45b7d1 0%, #3498db 100%); color: white; }
      .type-password { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); color: white; }
      .type-key { background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); color: white; }
      .type-endpoint { background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%); color: white; }
      .type-email { background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color: white; }
      .type-ip { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; }
      .type-url { background: linear-gradient(135deg, #1abc9c 0%, #16a085 100%); color: white; }
      .type-file { background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%); color: white; }
      .type-other { background: linear-gradient(135deg, #34495e 0%, #2c3e50 100%); color: white; }
      
      /* Responsive Design */
      @media (max-width: 768px) {
        .js-hunter-plugin { padding: 16px; }
        .controls-row { flex-direction: column; align-items: stretch; }
        .search-group { min-width: auto; }
        .stats-grid { grid-template-columns: 1fr; }
        .results-table { font-size: 12px; }
        .results-table th, .results-table td { padding: 8px; }
      }
    `;
    document.head.appendChild(style);
  }

  private setupEventListeners(): void {
    // Export buttons
    const exportJsonBtn = this.container.querySelector('#export-json-btn') as HTMLButtonElement;
    const exportCsvBtn = this.container.querySelector('#export-csv-btn') as HTMLButtonElement;
    const clearBtn = this.container.querySelector('#clear-btn') as HTMLButtonElement;

    exportJsonBtn.addEventListener('click', () => this.exportResults('json'));
    exportCsvBtn.addEventListener('click', () => this.exportResults('csv'));
    clearBtn.addEventListener('click', () => this.clearResults());

    // Filter select
    this.filterSelect.addEventListener('change', () => this.filterResults());

    // Search input
    this.searchInput = this.container.querySelector('#search-input') as HTMLInputElement;
    this.searchInput.addEventListener('input', () => this.filterResults());

    // Severity filter
    this.severityFilter = this.container.querySelector('#severity-filter') as HTMLSelectElement;
    this.severityFilter.addEventListener('change', () => this.filterResults());

    // Stats container
    this.statsContainer = this.container.querySelector('#stats-container') as HTMLElement;

    // Table row clicks
    this.resultsBody.addEventListener('click', (event) => {
      const row = (event.target as HTMLElement).closest('tr');
      if (row && !row.classList.contains('no-results')) {
        const resultId = row.getAttribute('data-result-id');
        const result = this.results.find(r => r.id === resultId);
        if (result && this.onResultClickCallback) {
          this.onResultClickCallback(result);
        }
      }
    });
  }

  public addResult(result: ScanResult): void {
    this.results.push(result);
    this.updateResultsTable();
    this.updateStats(result);
    this.updateStatus();
  }

  public setResults(results: ScanResult[]): void {
    this.results = results;
    this.updateResultsTable();
    this.updateStatus();
  }

  private updateResultsTable(): void {
    const filteredResults = this.getFilteredResults();
    
    if (filteredResults.length === 0) {
      this.resultsBody.innerHTML = `
        <tr class="no-results">
          <td colspan="7">
            <div class="empty-state">
              <div class="empty-icon">🔍</div>
              <div class="empty-title">No findings yet</div>
              <div class="empty-description">Start browsing to detect JavaScript files and security findings</div>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    this.resultsBody.innerHTML = filteredResults.map(result => {
      const severity = this.getSeverity(result.matchType);
      const severityClass = `severity-${severity}`;
      const fileName = this.extractFileName(result.fileUrl);
      
      return `
        <tr data-result-id="${result.id}">
          <td><span class="severity-badge ${severityClass}">${severity.toUpperCase()}</span></td>
          <td>
            <span class="match-type" style="background-color: ${getMatchTypeColor(result.matchType)}">
              ${this.getTypeIcon(result.matchType)} ${result.matchType}
            </span>
          </td>
          <td class="match-value" title="${this.escapeHtml(result.matchValue)}">${this.escapeHtml(this.truncateValue(result.matchValue))}</td>
          <td class="file-url" title="${this.escapeHtml(fileName)}">${this.escapeHtml(fileName)}</td>
          <td class="source-url" title="${this.escapeHtml(result.sourceUrl)}">${this.escapeHtml(this.truncateUrl(result.sourceUrl))}</td>
          <td class="timestamp">${new Date(result.timestamp).toLocaleString()}</td>
          <td><button class="action-btn" onclick="navigator.clipboard.writeText('${this.escapeHtml(result.matchValue)}')" title="Copy to clipboard">📋</button></td>
        </tr>
      `;
    }).join('');
  }

  private getFilteredResults(): ScanResult[] {
    const typeFilter = this.filterSelect.value;
    const severityFilter = this.severityFilter.value;
    const searchTerm = this.searchInput.value.toLowerCase();
    
    return this.results.filter(result => {
      const typeMatch = typeFilter === 'all' || result.matchType === typeFilter;
      const severityMatch = severityFilter === 'all' || this.getSeverity(result.matchType) === severityFilter;
      const searchMatch = !searchTerm || 
        result.matchValue.toLowerCase().includes(searchTerm) ||
        result.fileUrl.toLowerCase().includes(searchTerm) ||
        result.sourceUrl.toLowerCase().includes(searchTerm) ||
        result.matchType.toLowerCase().includes(searchTerm);
      
      return typeMatch && severityMatch && searchMatch;
    });
  }

  private getSeverity(type: string): string {
    const severityMap: { [key: string]: string } = {
      'API_KEY': 'high',
      'SECRET': 'high',
      'TOKEN': 'high',
      'PASSWORD': 'high',
      'PRIVATE_KEY': 'high',
      'ENDPOINT': 'medium',
      'EMAIL': 'low',
      'IP': 'low',
      'URL': 'low'
    };
    
    return severityMap[type] || 'medium';
  }

  private extractFileName(url: string): string {
    try {
      const urlObj = new URL(url);
      const pathname = urlObj.pathname;
      const fileName = pathname.split('/').pop() || 'index';
      return fileName.length > 20 ? fileName.substring(0, 17) + '...' : fileName;
    } catch {
      return url.length > 20 ? url.substring(0, 17) + '...' : url;
    }
  }

  private truncateValue(value: string): string {
    return value.length > 40 ? value.substring(0, 37) + '...' : value;
  }

  private getTypeIcon(type: string): string {
    const iconMap: { [key: string]: string } = {
      'API_KEY': '🔑',
      'SECRET': '🔐',
      'TOKEN': '🎫',
      'PASSWORD': '🔒',
      'PRIVATE_KEY': '🗝️',
      'ENDPOINT': '🌐',
      'EMAIL': '📧',
      'IP': '🖥️',
      'URL': '🔗'
    };
    
    return iconMap[type] || '📋';
  }

  private truncateUrl(url: string, maxLength: number = 40): string {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
  }

  private escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  private updateStatus(): void {
    const totalResults = this.results.length;
    const secretsCount = this.results.filter(r => r.matchType === 'secret').length;
    const endpointsCount = this.results.filter(r => r.matchType === 'endpoint').length;
    const emailsCount = this.results.filter(r => r.matchType === 'email').length;
    const ipsCount = this.results.filter(r => r.matchType === 'ip').length;

    this.statusElement.innerHTML = `
      Found ${totalResults} total matches: 
      <span style="color: #ff4444">${secretsCount} secrets</span>, 
      <span style="color: #ffaa00">${endpointsCount} endpoints</span>, 
      <span style="color: #4488ff">${emailsCount} emails</span>, 
      <span style="color: #aa44ff">${ipsCount} IPs</span>
    `;
    
    this.updateStatsDisplay();
  }

  private updateStats(result: ScanResult): void {
    this.stats.totalResults++;
    
    switch (result.matchType) {
      case 'API_KEY':
      case 'SECRET':
      case 'TOKEN':
      case 'PASSWORD':
      case 'PRIVATE_KEY':
        this.stats.secretsCount++;
        break;
      case 'ENDPOINT':
        this.stats.endpointsCount++;
        break;
      case 'EMAIL':
        this.stats.emailsCount++;
        break;
      case 'IP':
        this.stats.ipsCount++;
        break;
    }
    
    this.stats.lastScanTime = new Date();
  }

  private updateStatsDisplay(): void {
    const totalCountEl = this.container.querySelector('#total-count');
    const secretsCountEl = this.container.querySelector('#secrets-count');
    const endpointsCountEl = this.container.querySelector('#endpoints-count');
    const emailsCountEl = this.container.querySelector('#emails-count');
    const ipsCountEl = this.container.querySelector('#ips-count');
    const filesCountEl = this.container.querySelector('#files-count');
    const lastScanTimeEl = this.container.querySelector('#last-scan-time');
    
    if (totalCountEl) totalCountEl.textContent = this.stats.totalResults.toString();
    if (secretsCountEl) secretsCountEl.textContent = this.stats.secretsCount.toString();
    if (endpointsCountEl) endpointsCountEl.textContent = this.stats.endpointsCount.toString();
    if (emailsCountEl) emailsCountEl.textContent = this.stats.emailsCount.toString();
    if (ipsCountEl) ipsCountEl.textContent = this.stats.ipsCount.toString();
    if (filesCountEl) filesCountEl.textContent = this.stats.filesScanned.toString();
    if (lastScanTimeEl && this.stats.lastScanTime) {
      lastScanTimeEl.textContent = `Last scan: ${this.stats.lastScanTime.toLocaleTimeString()}`;
    }
  }

  private filterResults(): void {
    this.updateResultsTable();
    
    // Update results count display
    const filteredResults = this.getFilteredResults();
    const resultsCountEl = this.container.querySelector('#results-count');
    if (resultsCountEl) {
      resultsCountEl.textContent = `${filteredResults.length} result${filteredResults.length !== 1 ? 's' : ''}`;
    }
  }

  private exportResults(format: 'json' | 'csv'): void {
    if (this.onExportCallback) {
      const data = this.onExportCallback(format);
      this.downloadFile(data, `js-hunter-results.${format}`, format === 'json' ? 'application/json' : 'text/csv');
    }
  }

  private downloadFile(content: string, filename: string, mimeType: string): void {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  private clearResults(): void {
    if (confirm('Are you sure you want to clear all results?')) {
      this.results = [];
      this.stats = {
        totalResults: 0,
        secretsCount: 0,
        endpointsCount: 0,
        emailsCount: 0,
        ipsCount: 0,
        filesScanned: 0
      };
      this.updateResultsTable();
      this.updateStatus();
      this.updateStatsDisplay();
      
      // Update results count display
      const resultsCountEl = this.container.querySelector('#results-count');
      if (resultsCountEl) {
        resultsCountEl.textContent = '0 results';
      }
      
      if (this.onClearCallback) {
        this.onClearCallback();
      }
    }
  }

  public onExport(callback: (format: 'json' | 'csv') => string): void {
    this.onExportCallback = callback;
  }

  public onClear(callback: () => void): void {
    this.onClearCallback = callback;
  }

  public onResultClick(callback: (result: ScanResult) => void): void {
    this.onResultClickCallback = callback;
  }

  public showMessage(message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info'): void {
    const colors = {
      info: '#2196F3',
      success: '#4CAF50',
      warning: '#ff9800',
      error: '#f44336'
    };

    const messageDiv = document.createElement('div');
    messageDiv.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${colors[type]};
      color: white;
      padding: 12px 20px;
      border-radius: 4px;
      z-index: 10000;
      font-size: 14px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    `;
    messageDiv.textContent = message;
    
    document.body.appendChild(messageDiv);
    
    setTimeout(() => {
      if (messageDiv.parentNode) {
        messageDiv.parentNode.removeChild(messageDiv);
      }
    }, 3000);
  }
}