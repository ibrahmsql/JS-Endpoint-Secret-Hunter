/**
 * Regex patterns for detecting various types of sensitive information in JavaScript files
 */

export interface PatternConfig {
  name: string;
  regex: RegExp;
  type: 'endpoint' | 'secret' | 'email' | 'ip';
  description: string;
}

// Patterns to exclude (false positives)
export const EXCLUSION_PATTERNS = [
  /demo/i,
  /test/i,
  /sample/i,
  /todo/i,
  /example/i,
  /placeholder/i,
  /localhost/i,
  /127\.0\.0\.1/,
  /0\.0\.0\.0/,
  /\bfoo\b/i,
  /\bbar\b/i,
  /\bbaz\b/i,
  /\bdummy\b/i,
  /\bmock\b/i,
  /\bfake\b/i
];

export const DETECTION_PATTERNS: PatternConfig[] = [
  // API Endpoints
  {
    name: 'HTTP/HTTPS URLs',
    regex: /https?:\/\/[^\s"'<>\[\]{}|\\^`]+/gi,
    type: 'endpoint',
    description: 'Absolute HTTP/HTTPS URLs'
  },
  {
    name: 'Relative API Paths',
    regex: /\/[a-zA-Z0-9_\-\/\.]+(?:\?[^\s"'<>\[\]{}|\\^`]*)?(?=#|$|[\s"'<>\[\]{}|\\^`])/g,
    type: 'endpoint',
    description: 'Relative API paths starting with /'
  },
  {
    name: 'API Endpoints with Parameters',
    regex: /["']\/?api\/[a-zA-Z0-9_\-\/\.:?&=]+["']/gi,
    type: 'endpoint',
    description: 'API endpoints containing /api/'
  },

  // AWS Keys and Tokens
  {
    name: 'AWS Access Key',
    regex: /AKIA[0-9A-Z]{16}/g,
    type: 'secret',
    description: 'AWS Access Key ID'
  },
  {
    name: 'AWS Secret Key',
    regex: /[A-Za-z0-9\/+=]{40}/g,
    type: 'secret',
    description: 'Potential AWS Secret Access Key (40 chars)'
  },

  // Google API Keys
  {
    name: 'Google API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    type: 'secret',
    description: 'Google API Key'
  },

  // Slack Tokens
  {
    name: 'Slack Token',
    regex: /xox[baprs]-[0-9A-Za-z]{10,48}/g,
    type: 'secret',
    description: 'Slack API Token'
  },

  // Stripe Keys
  {
    name: 'Stripe Live Key',
    regex: /sk_live_[0-9a-zA-Z]{24}/g,
    type: 'secret',
    description: 'Stripe Live Secret Key'
  },
  {
    name: 'Stripe Publishable Key',
    regex: /pk_live_[0-9a-zA-Z]{24}/g,
    type: 'secret',
    description: 'Stripe Live Publishable Key'
  },

  // GitHub Tokens
  {
    name: 'GitHub Personal Access Token',
    regex: /ghp_[0-9A-Za-z]{36}/g,
    type: 'secret',
    description: 'GitHub Personal Access Token'
  },
  {
    name: 'GitHub OAuth Token',
    regex: /gho_[0-9A-Za-z]{36}/g,
    type: 'secret',
    description: 'GitHub OAuth Token'
  },

  // JWT Tokens
  {
    name: 'JWT Token',
    regex: /eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{5,}/g,
    type: 'secret',
    description: 'JSON Web Token (JWT)'
  },

  // Generic API Keys
  {
    name: 'Generic API Key',
    regex: /["']?[a-zA-Z0-9_\-]*[aA][pP][iI][_\-]?[kK][eE][yY]["']?\s*[:=]\s*["']?[a-zA-Z0-9_\-]{16,}["']?/g,
    type: 'secret',
    description: 'Generic API key patterns'
  },

  // Database Connection Strings
  {
    name: 'Database Connection String',
    regex: /(mongodb|mysql|postgresql|redis):\/\/[^\s"'<>\[\]{}|\\^`]+/gi,
    type: 'secret',
    description: 'Database connection strings'
  },

  // Email Addresses
  {
    name: 'Email Address',
    regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    type: 'email',
    description: 'Email addresses'
  },

  // Internal IPv4 Addresses
  {
    name: 'Private IPv4 (10.x.x.x)',
    regex: /\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b/g,
    type: 'ip',
    description: 'Private IPv4 addresses (10.x.x.x)'
  },
  {
    name: 'Private IPv4 (192.168.x.x)',
    regex: /\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b/g,
    type: 'ip',
    description: 'Private IPv4 addresses (192.168.x.x)'
  },
  {
    name: 'Private IPv4 (172.16-31.x.x)',
    regex: /\b172\.(?:1[6-9]|2\d|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}\b/g,
    type: 'ip',
    description: 'Private IPv4 addresses (172.16-31.x.x)'
  },
  {
    name: 'Loopback IPv4',
    regex: /\b127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b/g,
    type: 'ip',
    description: 'Loopback IPv4 addresses'
  },

  // Internal IPv6 Addresses
  {
    name: 'Private IPv6',
    regex: /\bfc00:[0-9a-fA-F:]+\b/g,
    type: 'ip',
    description: 'Private IPv6 addresses (fc00::/7)'
  },
  {
    name: 'Link-local IPv6',
    regex: /\bfe80:[0-9a-fA-F:]+\b/g,
    type: 'ip',
    description: 'Link-local IPv6 addresses'
  },

  // Additional Secret Patterns
  {
    name: 'Generic Secret/Password',
    regex: /["']?(?:secret|password|passwd|pwd|token|key)["']?\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
    type: 'secret',
    description: 'Generic secret/password patterns'
  },
  {
    name: 'Base64 Encoded Data',
    regex: /["'][A-Za-z0-9+\/]{40,}={0,2}["']/g,
    type: 'secret',
    description: 'Potential Base64 encoded secrets'
  }
];

/**
 * Check if a match should be excluded based on exclusion patterns
 */
export function shouldExclude(match: string): boolean {
  return EXCLUSION_PATTERNS.some(pattern => pattern.test(match));
}

/**
 * Get color for match type
 */
export function getMatchTypeColor(type: string): string {
  const colors: { [key: string]: string } = {
    'API_KEY': '#ff6b6b',
    'SECRET': '#4ecdc4',
    'TOKEN': '#45b7d1',
    'PASSWORD': '#f39c12',
    'PRIVATE_KEY': '#9b59b6',
    'ENDPOINT': '#2ecc71',
    'EMAIL': '#3498db',
    'IP': '#e74c3c',
    'URL': '#1abc9c',
    'FILE': '#95a5a6',
    // Legacy support
    'endpoint': '#2ecc71',
    'secret': '#e74c3c',
    'email': '#3498db',
    'ip': '#f39c12'
  };
  return colors[type] || '#34495e';
}