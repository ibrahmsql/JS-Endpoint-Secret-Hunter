# 🔍 JS Endpoint Secret Hunter

**Caido Plugin for JavaScript Security Analysis**

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/ibrahmsql/js-endpoint-secret-hunter)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Caido](https://img.shields.io/badge/caido-%3E%3D0.20.0-orange.svg)](https://caido.io)

## 📋 Features

### 🎯 Scanning Capabilities
- **🔗 Endpoint Discovery**: Finds API endpoints in JavaScript files
- **🔐 Secret Detection**: Detects API keys, tokens and sensitive information
- **📧 Email Addresses**: Extracts email addresses from JavaScript
- **🌐 IP Addresses**: Finds hardcoded IP addresses
- **⚡ Passive Scanning**: Automatically analyzes HTTP traffic

### 🎨 Modern Interface
- **📊 Real-time Results**: Instant scan results
- **🔍 Filtering**: Type, severity and search-based filtering
- **📤 Export Feature**: Export in JSON, CSV and TXT formats
- **🎯 Severity Levels**: Critical, High, Medium, Low, Info
- **📱 Responsive Design**: Modern and user-friendly interface

## 🚀 Installation

### Requirements
- **Caido**: v0.20.0 or higher
- **Node.js**: v16.0.0 or higher (for development)

### Manual Installation

1. **Download plugin files**:
   ```bash
   git clone https://github.com/ibrahmsql/js-endpoint-secret-hunter.git
   cd js-endpoint-secret-hunter
   ```

2. **Install to Caido**:
   - Open Caido
   - Settings > Plugins > Install Plugin
   - Select `manifest.json` file

### Development Setup

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Production build
npm run build

# Create plugin package
npm run package
```

## 📖 Usage

### 🔧 Basic Usage

1. **Activate Plugin**: Enable the plugin in Caido
2. **Automatic Scanning**: Plugin automatically monitors HTTP traffic
3. **View Results**: Examine results from the frontend interface

### 🎛️ Commands

#### Backend Commands
- `get-results`: Get all scan results
- `clear-results`: Clear results
- `get-stats`: Display statistics
- `export-results`: Export results

### 🔍 Detection Types

| Type | Description | Severity |
|------|-------------|----------|
| **🔗 API Endpoint** | REST API endpoints | Medium |
| **🔐 API Key** | API keys and tokens | Critical |
| **🗝️ JWT Token** | JSON Web Tokens | High |
| **🔑 Private Key** | Private keys | Critical |
| **📧 Email** | Email addresses | Low |
| **🌐 IP Address** | IP addresses | Info |
| **🔗 URL** | External URLs | Medium |

## 🎨 Interface Features

### 📊 Main Panel
- **Real-time result counter**
- **Severity-based color coding**
- **Quick filtering buttons**
- **Search box**

### 🔍 Filtering
```javascript
// Type-based filtering
filterByType('endpoint')
filterByType('secret')

// Severity-based filtering
filterBySeverity('critical')
filterBySeverity('high')

// Text-based search
searchResults('api.example.com')
```

### 📤 Export Options
- **JSON**: For programmatic use
- **CSV**: For Excel/Spreadsheet analysis
- **TXT**: Simple text format

## ⚙️ Configuration

### 🎯 Regex Patterns

The plugin uses the following regex patterns:

```javascript
// API Endpoints
/(?:\/api\/|\bapi\.|api_)[\w\/-]+/gi

// Secrets
/(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"]([^'"\s]{10,})['"]?/gi

// JWT Tokens
/eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g

// Email Addresses
/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g

// IP Addresses
/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g
```

## 🛡️ Security

### 🔒 Secure Usage
- Plugin only performs **passive scanning**
- **No data is sent externally**
- All operations are performed **locally**
- **Sensitive information is not logged**

### ⚠️ Warnings
- This tool should only be used for **legal penetration testing**
- **Do not test without permission**
- Follow **responsible disclosure** principles


### 🧪 Testing

```bash
# Lint check
npm run lint

# Run tests
npm test

# Test plugin package
npm run package
```

### 🤝 Contributing

1. **Fork** the repository
2. **Create feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Test** your changes (`npm test`)
5. **Push** to branch (`git push origin feature/amazing-feature`)
6. **Open Pull Request**



## 📄 License

This project is licensed under the [MIT License](LICENSE).

## 🙏 Acknowledgments

- **Caido Team** - For the amazing platform
- **Security Community** - For feedback and contributions
- **Open Source Contributors** - For continuous development

## 📞 Contact

- **GitHub**: [ibrahmsql](https://github.com/ibrahmsql)
- **Email**: ibrahimsql@proton.me
- **Issues**: [GitHub Issues](https://github.com/ibrahmsql/js-endpoint-secret-hunter/issues)

---
*This plugin developed for the Caido platform.*
