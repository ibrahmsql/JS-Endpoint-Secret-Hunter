import { DETECTION_PATTERNS, shouldExclude, PatternConfig } from "../patterns";

// Caido SDK types
interface CaidoRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
}

interface CaidoResponse {
  request: CaidoRequest;
  status: number;
  headers: Record<string, string>;
  getBody(): Promise<ArrayBuffer | null>;
  getHeader(name: string): string | undefined;
}

interface CaidoProxy {
  onResponse(callback: (response: CaidoResponse) => void | Promise<void>): void;
}

interface CaidoScope {
  isInScope(url: string): Promise<boolean>;
}

interface CaidoCommands {
  register(id: string, command: { name: string; run: (...args: any[]) => any }): void;
}

interface CaidoConsole {
  log(...args: any[]): void;
  error(...args: any[]): void;
}

interface CaidoHttp {
  request(options: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: ArrayBuffer;
  }): Promise<{ status: number; body: ArrayBuffer; headers: Record<string, string> }>;
}

interface Caido {
  proxy: CaidoProxy;
  scope: CaidoScope;
  commands: CaidoCommands;
  console: CaidoConsole;
  http: CaidoHttp;
}

export interface ScanResult {
  id: string;
  fileUrl: string;
  matchType: string;
  matchValue: string;
  sourceRequestId: string;
  sourceUrl: string;
  patternName: string;
  timestamp: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface JSFile {
  url: string;
  content: string;
  sourceRequestId: string;
  sourceUrl: string;
}

class JSEndpointSecretHunter {
  private caido: Caido;
  private scannedFiles = new Set<string>();
  private results: ScanResult[] = [];
  private isEnabled: boolean = true;
  private processedRequests = new Set<string>();
  private cache = new Map<string, string>();

  constructor(caido: Caido) {
    this.caido = caido;
    this.setupResponseMonitoring();
    this.registerCommands();
  }

  private setupResponseMonitoring(): void {
    this.caido.proxy.onResponse(async (response: CaidoResponse) => {
      if (!this.isEnabled) return;

      try {
        const requestId = response.request.id;
        const url = response.request.url;

        // Avoid duplicate processing
        if (this.processedRequests.has(requestId)) return;
        this.processedRequests.add(requestId);

        // Check if URL is in scope
        const inScope = await this.caido.scope.isInScope(url);
        if (!inScope) return;

        const body = await response.getBody();
        if (!body) return;

        const contentType = response.getHeader('content-type') || '';
        const bodyText = new TextDecoder().decode(body);

        // Process JavaScript files directly
        if (contentType.includes('javascript') || url.endsWith('.js')) {
          await this.processJSFile({
            url,
            content: bodyText,
            sourceRequestId: requestId,
            sourceUrl: url
          });
        }
        // Extract JS files from HTML
        else if (contentType.includes('html')) {
          const jsFiles = this.extractJSFiles(bodyText, url);
          for (const jsUrl of jsFiles) {
            if (!this.scannedFiles.has(jsUrl)) {
              const jsContent = await this.downloadJSFile(jsUrl);
              if (jsContent) {
                await this.processJSFile({
                  url: jsUrl,
                  content: jsContent,
                  sourceRequestId: requestId,
                  sourceUrl: url
                });
              }
            }
          }
        }
      } catch (error) {
        this.caido.console.error('Error processing response:', error);
      }
    });
  }

  private registerCommands(): void {
    this.caido.commands.register('js-hunter.get-results', {
      name: 'Get Scan Results',
      run: () => {
        return {
          results: this.results,
          stats: this.getStats()
        };
      }
    });

    this.caido.commands.register('js-hunter.clear-results', {
      name: 'Clear Scan Results',
      run: () => {
        this.clearResults();
        return { success: true };
      }
    });

    this.caido.commands.register('js-hunter.export-results', {
      name: 'Export Results',
      run: (format: 'json' | 'csv') => {
        return this.exportResults(format);
      }
    });

    this.caido.commands.register('js-hunter.toggle-enabled', {
      name: 'Toggle Scanner',
      run: () => {
        this.isEnabled = !this.isEnabled;
        return { enabled: this.isEnabled };
      }
    });
  }

  private extractJSFiles(htmlContent: string, baseUrl: string): string[] {
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

    // Also extract inline scripts
    const inlineScriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    let inlineMatch;
    let inlineIndex = 0;
    while ((inlineMatch = inlineScriptRegex.exec(htmlContent)) !== null) {
      const scriptContent = inlineMatch[1].trim();
      if (scriptContent.length > 100) { // Only process substantial inline scripts
        const inlineUrl = `${baseUrl}#inline-script-${inlineIndex++}`;
        jsFiles.push(inlineUrl);
        this.cache.set(inlineUrl, scriptContent);
      }
    }

    return jsFiles;
  }

  private resolveUrl(url: string, baseUrl: string): string | null {
    try {
      if (url.startsWith('http://') || url.startsWith('https://')) {
        return url;
      }
      if (url.startsWith('//')) {
        return new URL(baseUrl).protocol + url;
      }
      return new URL(url, baseUrl).href;
    } catch {
      return null;
    }
  }

  private async downloadJSFile(url: string): Promise<string | null> {
    try {
      // Check cache first
      if (this.cache.has(url)) {
        return this.cache.get(url)!;
      }

      // For inline scripts, return cached content
      if (url.includes('#inline-script-')) {
        return this.cache.get(url) || null;
      }

      // Use Caido's HTTP client to download
      const response = await this.caido.http.request({
        method: 'GET',
        url: url,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; Caido JS Hunter)'
        }
      });

      if (response.status === 200) {
        const content = new TextDecoder().decode(response.body);
        this.cache.set(url, content);
        return content;
      }
    } catch (error) {
      this.caido.console.error(`Failed to download JS file ${url}:`, error);
    }
    return null;
  }

  private async processJSFile(jsFile: JSFile): Promise<void> {
    if (this.scannedFiles.has(jsFile.url)) return;
    this.scannedFiles.add(jsFile.url);

    const results = this.scanJSContent(
      jsFile.content,
      jsFile.url,
      jsFile.sourceRequestId,
      jsFile.sourceUrl
    );

    for (const result of results) {
      this.results.push(result);
      this.caido.console.log(
        `[JS Hunter] ${this.getTypeIcon(result.matchType)} Found ${result.patternName}: ${result.matchValue}`
      );
    }
  }

  private scanJSContent(
    content: string,
    fileUrl: string,
    sourceRequestId: string,
    sourceUrl: string
  ): ScanResult[] {
    const results: ScanResult[] = [];

    for (const pattern of DETECTION_PATTERNS) {
      const matches = content.match(pattern.regex);
      if (matches) {
        for (const match of matches) {
          const cleanMatch = match.replace(/["']/g, '').trim();
          
          // Skip if should be excluded
          if (shouldExclude(cleanMatch)) continue;
          
          // Skip duplicates
          if (results.some(r => r.matchValue === cleanMatch && r.matchType === pattern.type)) {
            continue;
          }

          // Apply minimum length requirements
          if (pattern.type === 'secret' && cleanMatch.length < 8) continue;
          if (pattern.type === 'endpoint' && cleanMatch.length < 5) continue;

          const result: ScanResult = {
            id: this.generateId(),
            fileUrl,
            matchType: pattern.type,
            matchValue: cleanMatch,
            sourceRequestId,
            sourceUrl,
            patternName: pattern.name,
            timestamp: Date.now(),
            severity: this.getSeverity(pattern.type, pattern.name)
          };

          results.push(result);
        }
      }
    }

    return results;
  }

  private getSeverity(type: string, patternName: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    if (type === 'secret') {
      if (patternName.includes('AWS') || patternName.includes('Private Key') || patternName.includes('Database')) {
        return 'critical';
      }
      if (patternName.includes('API Key') || patternName.includes('JWT') || patternName.includes('Token')) {
        return 'high';
      }
      return 'medium';
    }
    if (type === 'endpoint') return 'medium';
    if (type === 'email') return 'low';
    if (type === 'ip') return 'info';
    return 'info';
  }

  private getTypeIcon(type: string): string {
    switch (type) {
      case 'secret': return '🔑';
      case 'endpoint': return '🌐';
      case 'email': return '📧';
      case 'ip': return '🖥️';
      default: return '🔍';
    }
  }

  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private getStats() {
    const stats = {
      totalResults: this.results.length,
      byType: {} as Record<string, number>,
      bySeverity: {} as Record<string, number>,
      filesScanned: this.scannedFiles.size,
      lastScanTime: this.results.length > 0 ? new Date(Math.max(...this.results.map(r => r.timestamp))) : null
    };

    for (const result of this.results) {
      stats.byType[result.matchType] = (stats.byType[result.matchType] || 0) + 1;
      stats.bySeverity[result.severity] = (stats.bySeverity[result.severity] || 0) + 1;
    }

    return stats;
  }

  private clearResults(): void {
    this.results = [];
    this.scannedFiles.clear();
    this.processedRequests.clear();
    this.cache.clear();
  }

  private exportResults(format: 'json' | 'csv'): string {
    if (format === 'json') {
      return JSON.stringify({
        metadata: {
          exportTime: new Date().toISOString(),
          totalResults: this.results.length,
          plugin: 'JS Endpoint & Secret Hunter v2.0.0'
        },
        results: this.results
      }, null, 2);
    } else {
      const headers = ['ID', 'Type', 'Severity', 'Pattern', 'Value', 'File URL', 'Source URL', 'Timestamp'];
      const rows = this.results.map(r => [
        r.id,
        r.matchType,
        r.severity,
        r.patternName,
        r.matchValue,
        r.fileUrl,
        r.sourceUrl,
        new Date(r.timestamp).toISOString()
      ]);
      
      return [headers, ...rows]
        .map(row => row.map(cell => `"${cell.toString().replace(/"/g, '""')}"`).join(','))
        .join('\n');
    }
  }
}

export default function initialize(caido: Caido): void {
  new JSEndpointSecretHunter(caido);
  caido.console.log('🔍 JS Endpoint & Secret Hunter v2.0.0 initialized successfully');
}