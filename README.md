# Cyber Sentinel

![Python](https://img.shields.io/badge/Python-3.8%2B-green.svg)  
![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)  

## 📌 Overview

Cyber Sentinel is a browser extension designed to enhance online security by analyzing web pages and files for potential threats. The extension integrates real-time URL verification, file scanning, and AI-powered threat detection to provide users with a comprehensive cybersecurity tool.

## Features

- **Real-Time URL Analysis**: Checks the authenticity of visited web pages using Google Safe Browsing API, heuristic methods, and SSL/TLS certificate validation.
- **File Upload Scanning**: Analyzes uploaded files for potential malware using hash comparison, entropy detection, MIME type verification, and deep content inspection.
- **AI-Powered Threat Detection**:
  - **SecureBERT** for phishing detection and suspicious content analysis.
  - **Machine Learning Heuristic Analysis** for identifying malicious patterns in URLs and file metadata.
- **Cryptographic Hashing**: Uses **MD5** and **SHA-256** hash functions to compare files against known malicious databases.
- **SSL/TLS Certificate Inspection**: Validates the authenticity and expiration of certificates to detect fraudulent websites.
- **Domain Age Analysis**: Determines the legitimacy of a domain by checking its registration date and age.
- **Dark/Light Mode Toggle**: Provides a customizable UI theme for better user experience.

---

## Components

### 1. Manifest File (`manifest.json`)

- Defines metadata such as the extension name, version, permissions, and required APIs.
- Grants permissions to read active tabs, execute scripts, store data, and monitor web navigation.
- Specifies `popup.html` as the default interface.

### 2. Popup Interface

#### `popup.html`

- Provides a graphical interface for users to check the security status of the current webpage and analyze uploaded files.
- Displays results and warnings based on the backend analysis.

#### `popup.css`

- Defines styles for both dark and light modes.
- Enhances UI elements like buttons, input fields, and result displays.

#### `popup.js`

- Retrieves the active tab's URL and sends it to the backend for analysis.
- Handles UI interactions such as theme toggling and loading states.
- Manages file uploads and displays analysis results in real time.

### 3. Backend API (`app.py`)

- Developed using **Flask**, this API serves as the core analysis engine.
- **URL Analysis**:
  - Uses **Google Safe Browsing API** to check for known malicious sites.
  - Performs heuristic analysis on domain age, SSL certificate, and phishing indicators.
  - Analyzes redirect chains to detect excessive redirections or cloaking techniques.
- **File Analysis**:
  - Checks file hashes against a database of known malicious hashes.
  - Uses **python-magic** to verify MIME type consistency.
  - Calculates **Shannon entropy** to detect obfuscated or encrypted malware.
  - Performs **content-based anomaly detection** by analyzing file structure and metadata.
- **AI-Based Threat Detection**:
  - Implements **SecureBERT** for detecting phishing attempts based on webpage content.
  - Uses **Machine Learning Classifiers** (e.g., Decision Trees, SVM) for URL safety prediction.
  - Applies **Natural Language Processing (NLP)** techniques to extract potential threats from webpage content.
  - Identifies **hidden iframes, obfuscated JavaScript, and malicious redirects**.
- **SSL/TLS Security Verification**:
  - Checks for expired, self-signed, or improperly configured SSL certificates.
  - Analyzes HTTPS implementation and detects mixed content vulnerabilities.
- **Advanced Heuristic Analysis**:
  - Flags domains associated with known phishing patterns.
  - Identifies suspicious URL structures (e.g., long subdomains, homograph attacks, and Punycode-based deception).

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/RiturajSingh2004/CyberSentinel.git
   cd CyberSentinel
   ```

2. Load the extension:

   - Open Chrome and navigate to `chrome://extensions/`.
   - Enable **Developer Mode** (top-right corner).
   - Click **Load unpacked** and select the project folder.

3. Run the backend API:

   ```bash
   pip install -r requirements.txt
   python app.py
   ```
---
## Usage

- Click on the Cyber Sentinel extension icon to open the popup.
- Click **Check Current Page** to analyze the active tab.
- Upload a file for advanced malware analysis.
- Review the results to identify potential threats.

## Future Enhancements

- Integration with **VirusTotal API** for file scanning.
- Real-time phishing detection using advanced deep learning models.
- Implementation of **blockchain-based domain reputation tracking**.
- User-defined URL blocklists and custom security rules.
- Enhanced detection for **JavaScript-based exploits and zero-day vulnerabilities**.
---

## 📜 License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
