# Installation & Quick Start Guide

## JS Endpoint & Secret Hunter - Caido Plugin

### 📋 Prerequisites

- **Caido**: Version 0.20.0 or higher
- **Operating System**: Windows, macOS, or Linux
- **Permissions**: Authorized testing scope defined in Caido

### 🚀 Quick Installation

#### Method 1: Using Pre-built Package

1. **Download the plugin package**:
   - Use the provided `.tar.gz` file: `js-endpoint-secret-hunter-YYYYMMDD-HHMMSS.tar.gz`

2. **Install in Caido**:
   ```
   1. Open Caido
   2. Navigate to Settings → Plugins
   3. Click "Install Plugin"
   4. Select the .tar.gz package file
   5. Click "Install"
   6. Enable the plugin in the plugins list
   ```

3. **Verify Installation**:
   - Look for the "🔍 JS Hunter" tab in Caido's interface
   - You should see the plugin's main interface with a warning about ethical use

#### Method 2: Build from Source

1. **Clone/Download Source**:
   ```bash
   # Navigate to the plugin directory
   cd /path/to/js-endpoint-secret-hunter
   ```

2. **Install Built Package**:
   - Use the generated `.tar.gz` file from step 1
   - Follow Method 1 steps 2-3

### 🎯 First Use

#### 1. Configure Your Scope
```
1. In Caido, go to Settings → Scope
2. Add your authorized target domains
3. Ensure only authorized targets are included
```

#### 2. Start Scanning
```
1. Navigate to the "🔍 JS Hunter" tab
2. Browse your target application normally
3. Watch as JavaScript files are automatically detected and scanned
4. Results will appear in real-time in the results table
```

#### 3. Review Results
- **🔑 Red entries**: Secrets, API keys, tokens (HIGH PRIORITY)
- **🌐 Orange entries**: API endpoints and URLs
- **📧 Blue entries**: Email addresses
- **🖥️ Purple entries**: Internal IP addresses

### 📊 Understanding Results

#### Result Table Columns
| Column | Description |
|--------|-------------|
| **Type** | Category of finding with color-coded icon |
| **File URL** | JavaScript file where the match was found |
| **Match Value** | The actual discovered sensitive data |
| **Pattern** | Detection pattern that triggered the match |
| **Source URL** | Original page that referenced the JS file |
| **Timestamp** | When the finding was discovered |

#### Interacting with Results
- **Click any row**: Opens the corresponding request in Caido
- **Filter dropdown**: Show only specific types of findings
- **Export buttons**: Save results as JSON or CSV
- **Clear button**: Reset all results (useful when changing scope)

### 🔧 Common Operations

#### Filtering Results
```
1. Use the "Filter by type" dropdown
2. Select: All Types, Secrets/Keys, Endpoints, Emails, or IP Addresses
3. Table updates automatically
```

#### Exporting Data
```
1. Click "Export JSON" for structured data
2. Click "Export CSV" for spreadsheet compatibility
3. Files download automatically to your default download folder
```

#### Clearing Results
```
1. Click "Clear Results" button
2. Confirm the action
3. All results are removed (useful when changing target scope)
```

### ⚠️ Important Security Notes

#### Ethical Use Requirements
- ✅ **Only use on authorized targets**
- ✅ **Respect scope boundaries**
- ✅ **Follow responsible disclosure**
- ❌ **Never use on unauthorized systems**
- ❌ **Don't ignore terms of engagement**

#### Best Practices
1. **Verify Findings**: Always manually verify discovered secrets
2. **Secure Storage**: Export and store results securely
3. **Regular Cleanup**: Clear results when changing targets
4. **Documentation**: Keep records of authorized testing scope

### 🐛 Troubleshooting

#### Plugin Not Loading
```
Problem: Plugin doesn't appear in Caido
Solution:
1. Check Caido version (must be ≥0.20.0)
2. Verify plugin is enabled in Settings → Plugins
3. Restart Caido if necessary
```

#### No Results Appearing
```
Problem: No findings despite browsing target
Solution:
1. Verify target is in Caido scope
2. Check that target loads JavaScript files
3. Look for errors in browser console (F12)
4. Ensure plugin is enabled
```

#### Performance Issues
```
Problem: Caido becomes slow during scanning
Solution:
1. Reduce scope to fewer domains
2. Clear results periodically
3. Close other resource-intensive applications
```

#### False Positives
```
Problem: Too many irrelevant results
Solution:
1. Results are pre-filtered for common false positives
2. Use the filter dropdown to focus on specific types
3. Manually verify all findings before reporting
```

### 📈 Additional Usage

#### Customizing Detection Patterns
```
To add custom patterns:
1. Edit src/patterns.ts
2. Add new PatternConfig entries
3. Rebuild the plugin
4. Reinstall in Caido
```

#### Integration with Other Tools
```
Exported data can be used with:
- Burp Suite (import CSV)
- Custom scripts (parse JSON)
- Reporting tools (CSV format)
- Spreadsheet applications (CSV format)
```

### 🔄 Updates and Maintenance

#### Updating the Plugin
```
1. Download new version
2. Uninstall old version in Caido
3. Install new version
4. Reconfigure scope if needed
```

#### Backup and Restore
```
To backup results:
1. Export to JSON before updating
2. Save exported files securely
3. Import/reference as needed
```

### 📞 Support

For issues or questions:
1. Check this guide first
2. Review the main README.md
3. Check browser console for errors
4. Report issues with:
   - Caido version
   - Plugin version
   - Error messages
   - Steps to reproduce

---

**Happy hunting! 🔍**

*Remember: This tool is for authorized security testing only. Always follow ethical guidelines and legal requirements.*