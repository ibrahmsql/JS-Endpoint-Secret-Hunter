import { DETECTION_PATTERNS, shouldExclude, PatternConfig } from './patterns';

export interface ScanResult {
  id: string;
  fileUrl: string;
  matchType: string;
  matchValue: string;
  sourceRequestId: string;
  sourceUrl: string;
  patternName: string;
  timestamp: number;
}

export interface JSFile {
  url: string;
  content: string;
  sourceRequestId: string;
  sourceUrl: string;
}

export class JSScanner {
  private scannedFiles = new Set<string>();
  private results: ScanResult[] = [];
  private resultCallbacks: ((result: ScanResult) => void)[] = [];

  /**
   * Add a callback to be called when new results are found
   */
  onResult(callback: (result: ScanResult) => void): void {
    this.resultCallbacks.push(callback);
  }

  /**
   * Extract JavaScript file URLs from HTML content
   */
  extractJSFiles(htmlContent: string, baseUrl: string): string[] {
    const jsFiles: string[] = [];
    const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
    
    let match;
    while ((match = scriptRegex.exec(htmlContent)) !== null) {
      const src = match[1];
      if (src.endsWith('.js') || src.includes('.js?')) {
        const absoluteUrl = this.resolveUrl(src, baseUrl);
        if (absoluteUrl) {
          jsFiles.push(absoluteUrl);
        }
      }
    }

    // Also look for inline script content
    const inlineScriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    while ((match = inlineScriptRegex.exec(htmlContent)) !== null) {
      const scriptContent = match[1].trim();
      if (scriptContent.length > 100) { // Only process substantial inline scripts
        // Create a virtual URL for inline scripts
        const inlineUrl = `${baseUrl}#inline-script-${Date.now()}`;
        jsFiles.push(inlineUrl);
      }
    }

    return jsFiles;
  }

  /**
   * Resolve relative URLs to absolute URLs
   */
  private resolveUrl(url: string, baseUrl: string): string | null {
    try {
      if (url.startsWith('http://') || url.startsWith('https://')) {
        return url;
      }
      
      const base = new URL(baseUrl);
      if (url.startsWith('//')) {
        return `${base.protocol}${url}`;
      }
      
      if (url.startsWith('/')) {
        return `${base.protocol}//${base.host}${url}`;
      }
      
      // Relative URL
      const basePath = base.pathname.endsWith('/') ? base.pathname : base.pathname.substring(0, base.pathname.lastIndexOf('/') + 1);
      return `${base.protocol}//${base.host}${basePath}${url}`;
    } catch (error) {
      console.error('Error resolving URL:', error);
      return null;
    }
  }

  /**
   * Download JavaScript file content
   */
  async downloadJSFile(url: string): Promise<string | null> {
    try {
      // Handle inline scripts
      if (url.includes('#inline-script-')) {
        // This would need to be handled by extracting from the original HTML
        // For now, return null as inline scripts are handled separately
        return null;
      }

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
      });

      if (!response.ok) {
        console.warn(`Failed to download JS file: ${url} (${response.status})`);
        return null;
      }

      const content = await response.text();
      return content;
    } catch (error) {
      console.error(`Error downloading JS file ${url}:`, error);
      return null;
    }
  }

  /**
   * Scan JavaScript content for patterns
   */
  scanJSContent(content: string, fileUrl: string, sourceRequestId: string, sourceUrl: string): ScanResult[] {
    const results: ScanResult[] = [];
    
    for (const pattern of DETECTION_PATTERNS) {
      const matches = content.match(pattern.regex);
      if (matches) {
        for (const match of matches) {
          const cleanMatch = match.replace(/["']/g, '').trim();
          
          // Skip if match should be excluded
          if (shouldExclude(cleanMatch)) {
            continue;
          }

          // Skip very short matches for certain types
          if ((pattern.type === 'endpoint' && cleanMatch.length < 5) ||
              (pattern.type === 'secret' && cleanMatch.length < 8)) {
            continue;
          }

          const result: ScanResult = {
            id: `${fileUrl}-${pattern.name}-${cleanMatch}`.replace(/[^a-zA-Z0-9\-_]/g, '-'),
            fileUrl,
            matchType: pattern.type,
            matchValue: cleanMatch,
            sourceRequestId,
            sourceUrl,
            patternName: pattern.name,
            timestamp: Date.now()
          };

          results.push(result);
        }
      }
    }

    return results;
  }

  /**
   * Process a JavaScript file
   */
  async processJSFile(jsFile: JSFile): Promise<void> {
    // Skip if already scanned
    if (this.scannedFiles.has(jsFile.url)) {
      return;
    }

    this.scannedFiles.add(jsFile.url);

    try {
      let content = jsFile.content;
      
      // If content is empty, try to download it
      if (!content && !jsFile.url.includes('#inline-script-')) {
        const downloadedContent = await this.downloadJSFile(jsFile.url);
        if (!downloadedContent) {
          return;
        }
        content = downloadedContent;
      }

      if (!content) {
        return;
      }

      // Scan the content
      const scanResults = this.scanJSContent(content, jsFile.url, jsFile.sourceRequestId, jsFile.sourceUrl);
      
      // Add results and notify callbacks
      for (const result of scanResults) {
        this.results.push(result);
        this.resultCallbacks.forEach(callback => callback(result));
      }

    } catch (error) {
      console.error(`Error processing JS file ${jsFile.url}:`, error);
    }
  }

  /**
   * Process HTTP response to extract and scan JavaScript files
   */
  async processResponse(responseBody: string, responseUrl: string, requestId: string): Promise<void> {
    try {
      const contentType = 'text/html'; // This would come from response headers in real implementation
      
      if (responseUrl.endsWith('.js') || contentType.includes('javascript')) {
        // Direct JavaScript file
        const jsFile: JSFile = {
          url: responseUrl,
          content: responseBody,
          sourceRequestId: requestId,
          sourceUrl: responseUrl
        };
        await this.processJSFile(jsFile);
      } else if (contentType.includes('html')) {
        // HTML page - extract JavaScript files
        const jsUrls = this.extractJSFiles(responseBody, responseUrl);
        
        for (const jsUrl of jsUrls) {
          const jsFile: JSFile = {
            url: jsUrl,
            content: jsUrl.includes('#inline-script-') ? this.extractInlineScript(responseBody, jsUrl) : '',
            sourceRequestId: requestId,
            sourceUrl: responseUrl
          };
          await this.processJSFile(jsFile);
        }
      }
    } catch (error) {
      console.error('Error processing response:', error);
    }
  }

  /**
   * Extract inline script content from HTML
   */
  private extractInlineScript(htmlContent: string, inlineUrl: string): string {
    const timestamp = inlineUrl.split('#inline-script-')[1];
    const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    
    let match;
    let scriptIndex = 0;
    while ((match = scriptRegex.exec(htmlContent)) !== null) {
      const scriptContent = match[1].trim();
      if (scriptContent.length > 100) {
        if (scriptIndex.toString() === timestamp.substring(timestamp.length - 1)) {
          return scriptContent;
        }
        scriptIndex++;
      }
    }
    
    return '';
  }

  /**
   * Get all scan results
   */
  getResults(): ScanResult[] {
    return [...this.results];
  }

  /**
   * Clear all results and reset scanner
   */
  clear(): void {
    this.results = [];
    this.scannedFiles.clear();
  }

  /**
   * Get results filtered by type
   */
  getResultsByType(type: string): ScanResult[] {
    return this.results.filter(result => result.matchType === type);
  }

  /**
   * Export results to JSON
   */
  exportToJSON(): string {
    return JSON.stringify(this.results, null, 2);
  }

  /**
   * Export results to CSV
   */
  exportToCSV(): string {
    if (this.results.length === 0) {
      return 'No results to export';
    }

    const headers = ['File URL', 'Match Type', 'Match Value', 'Source Request ID', 'Source URL', 'Pattern Name', 'Timestamp'];
    const csvRows = [headers.join(',')];

    for (const result of this.results) {
      const row = [
        `"${result.fileUrl}"`,
        `"${result.matchType}"`,
        `"${result.matchValue}"`,
        `"${result.sourceRequestId}"`,
        `"${result.sourceUrl}"`,
        `"${result.patternName}"`,
        `"${new Date(result.timestamp).toISOString()}"`
      ];
      csvRows.push(row.join(','));
    }

    return csvRows.join('\n');
  }
}