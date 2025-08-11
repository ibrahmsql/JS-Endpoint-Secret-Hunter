import { Caido, CaidoResponse } from './types';
import { JSScanner, ScanResult } from './scanner';
import { PluginUI } from './ui';

/**
 * JS Endpoint & Secret Hunter Plugin for Caido
 * 
 * This plugin passively monitors HTTP responses to detect JavaScript files
 * and scan them for sensitive information including:
 * - API endpoints
 * - Secret keys and tokens
 * - Email addresses
 * - Internal IP addresses
 * 
 * The plugin operates only on in-scope targets and provides a complete
 * UI for viewing, filtering, and exporting results.
 */

class JSEndpointSecretHunter {
  private caido: Caido;
  private scanner: JSScanner;
  private ui!: PluginUI;
  private isEnabled: boolean = true;
  private processedRequests = new Set<string>();

  constructor(caido: Caido) {
    this.caido = caido;
    this.scanner = new JSScanner();
    this.setupScanner();
  }

  /**
   * Initialize the plugin
   */
  async initialize(): Promise<void> {
    try {
      // Create the plugin tab in Caido UI
      await this.createPluginTab();
      
      // Setup HTTP response monitoring
      this.setupResponseMonitoring();
      
      // Setup scope checking
      this.setupScopeMonitoring();
      
      console.log('JS Endpoint & Secret Hunter plugin initialized successfully');
    } catch (error) {
      console.error('Failed to initialize JS Endpoint & Secret Hunter plugin:', error);
    }
  }

  /**
   * Create the plugin tab in Caido UI
   */
  private async createPluginTab(): Promise<void> {
    const tabContainer = document.createElement('div');
    tabContainer.id = 'js-hunter-tab';
    
    // Initialize UI
    this.ui = new PluginUI(tabContainer);
    
    // Setup UI callbacks
    this.ui.onExport((format) => {
      const data = format === 'json' ? this.scanner.exportToJSON() : this.scanner.exportToCSV();
      this.ui.showMessage(`Exported ${this.scanner.getResults().length} results as ${format.toUpperCase()}`, 'success');
      return data;
    });
    
    this.ui.onClear(() => {
      this.scanner.clear();
      this.processedRequests.clear();
      this.ui.showMessage('All results cleared', 'info');
    });
    
    this.ui.onResultClick((result) => {
      this.openRequestInCaido(result);
      this.ui.showMessage('Opening request in Caido...', 'info');
    });
    
    // Add tab to Caido
    this.caido.ui.addTab({
      id: 'js-hunter',
      title: '🔍 JS Hunter',
      content: tabContainer
    });
    
    this.ui.showMessage('JS Endpoint & Secret Hunter initialized', 'success');
  }

  /**
   * Setup the scanner with result callbacks
   */
  private setupScanner(): void {
    this.scanner.onResult((result: ScanResult) => {
      if (this.ui) {
        this.ui.addResult(result);
        this.ui.showMessage(`Found ${result.matchType}: ${result.matchValue.substring(0, 30)}...`, 'success');
      }
    });
  }

  /**
   * Setup HTTP response monitoring
   */
  private setupResponseMonitoring(): void {
    // Monitor HTTP responses
    this.caido.proxy.onResponse(async (response: CaidoResponse) => {
      if (!this.isEnabled) {
        return;
      }

      try {
        const request = response.request;
        const requestId = request.id;
        
        // Skip if already processed
        if (this.processedRequests.has(requestId)) {
          return;
        }
        
        // Check if the request is in scope
        if (!await this.isInScope(request.url)) {
          return;
        }
        
        this.processedRequests.add(requestId);
        
        // Show processing status
        if (this.ui) {
          this.ui.showMessage(`Scanning: ${request.url}`, 'info');
        }
        
        // Get response body
        const responseBody = await response.getBody();
        if (!responseBody) {
          return;
        }
        
        const bodyText = new TextDecoder('utf-8').decode(responseBody);
        const contentType = response.getHeader('content-type') || '';
        
        // Only process HTML and JavaScript responses
        if (contentType.includes('text/html') || 
            contentType.includes('application/javascript') ||
            contentType.includes('text/javascript') ||
            request.url.endsWith('.js')) {
          
          await this.scanner.processResponse(bodyText, request.url, requestId);
        }
        
      } catch (error) {
        console.error('Error processing response:', error);
        if (this.ui) {
          this.ui.showMessage('Error processing response', 'error');
        }
      }
    });
  }

  /**
   * Setup scope monitoring
   */
  private setupScopeMonitoring(): void {
    // Listen for scope changes
    this.caido.scope.onChange(() => {
      // Clear results when scope changes to ensure we only have in-scope results
      this.scanner.clear();
      this.processedRequests.clear();
      if (this.ui) {
        this.ui.setResults([]);
        this.ui.showMessage('Scope changed - results cleared', 'info');
      }
    });
  }

  /**
   * Check if a URL is in scope
   */
  private async isInScope(url: string): Promise<boolean> {
    try {
      return await this.caido.scope.isInScope(url);
    } catch (error) {
      console.error('Error checking scope:', error);
      return false;
    }
  }

  /**
   * Open a request in Caido's main interface
   */
  private openRequestInCaido(result: ScanResult): void {
    try {
      // Try to open the request in Caido's request viewer
      this.caido.ui.openRequest(result.sourceRequestId);
      
      if (this.ui) {
        this.ui.showMessage(`Opened request ${result.sourceRequestId}`, 'success');
      }
    } catch (error) {
      console.error('Error opening request in Caido:', error);
      
      if (this.ui) {
        this.ui.showMessage('Could not open request in Caido', 'error');
      }
      
      // Fallback: copy URL to clipboard
      this.copyToClipboard(result.sourceUrl);
    }
  }

  /**
   * Copy text to clipboard
   */
  private copyToClipboard(text: string): void {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => {
        if (this.ui) {
          this.ui.showMessage('URL copied to clipboard', 'info');
        }
      }).catch(error => {
        console.error('Failed to copy to clipboard:', error);
      });
    }
  }

  /**
   * Enable/disable the plugin
   */
  public setEnabled(enabled: boolean): void {
    this.isEnabled = enabled;
    if (this.ui) {
      this.ui.showMessage(
        enabled ? 'Plugin enabled' : 'Plugin disabled', 
        enabled ? 'success' : 'warning'
      );
    }
  }

  /**
   * Get plugin statistics
   */
  public getStats(): { totalResults: number; byType: Record<string, number>; processedRequests: number } {
    const results = this.scanner.getResults();
    const byType: Record<string, number> = {};
    
    for (const result of results) {
      byType[result.matchType] = (byType[result.matchType] || 0) + 1;
    }
    
    return {
      totalResults: results.length,
      byType,
      processedRequests: this.processedRequests.size
    };
  }

  /**
   * Get the UI instance for external access
   */
  public getUI(): PluginUI {
    return this.ui;
  }

  /**
   * Get the scanner instance for external access
   */
  public getScanner(): JSScanner {
    return this.scanner;
  }
}

// Plugin entry point
export default function initialize(caido: Caido): void {
  const plugin = new JSEndpointSecretHunter(caido);
  plugin.initialize().catch(error => {
    console.error('Failed to initialize JS Endpoint & Secret Hunter plugin:', error);
  });
  
  // Make plugin available globally for debugging
  (window as any).jsHunterPlugin = plugin;
}

// Export types for external use
export { ScanResult, JSScanner, PluginUI };