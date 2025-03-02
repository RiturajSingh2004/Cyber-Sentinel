document.addEventListener('DOMContentLoaded', function() {
    // DOM elements
    const checkButton = document.getElementById('checkButton');
    const resultContainer = document.getElementById('result');
    const errorElement = document.getElementById('error');
    const spinner = checkButton.querySelector('.spinner');
    const fileUploadForm = document.getElementById('fileUploadForm');
    const fileInput = document.getElementById('fileInput');
    const fileResult = document.getElementById('fileResult');
    const fileSpinner = fileUploadForm.querySelector('.spinner');
    const urlInput = document.getElementById('urlInput');
    const themeToggle = document.getElementById('themeToggle');
    
    // Store the current URL
    let currentUrl = '';
    
    // Base API URL - adjust if needed
    const API_BASE_URL = 'http://localhost:5000';
    
    // Theme toggle functionality
    themeToggle.addEventListener('click', function() {
        const html = document.documentElement;
        const currentTheme = html.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        html.setAttribute('data-theme', newTheme);
        
        // Update theme icon
        if (newTheme === 'dark') {
            themeToggle.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" class="theme-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                </svg>
            `;
        } else {
            themeToggle.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" class="theme-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="5"></circle>
                    <line x1="12" y1="1" x2="12" y2="3"></line>
                    <line x1="12" y1="21" x2="12" y2="23"></line>
                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                    <line x1="1" y1="12" x2="3" y2="12"></line>
                    <line x1="21" y1="12" x2="23" y2="12"></line>
                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
                </svg>
            `;
        }
    });
    
    // Check the saved theme on load
    chrome.storage.local.get(['theme'], function(result) {
        if (result.theme) {
            document.documentElement.setAttribute('data-theme', result.theme);
            if (result.theme === 'dark') {
                themeToggle.innerHTML = `
                    <svg xmlns="http://www.w3.org/2000/svg" class="theme-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                    </svg>
                `;
            }
        }
    });
    
    // Save theme preference when changed
    themeToggle.addEventListener('click', function() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        chrome.storage.local.set({theme: currentTheme});
    });
    
    // Get current tab URL automatically
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        let currentTab = tabs[0];
        if (currentTab && currentTab.url) {
            currentUrl = currentTab.url;
            urlInput.value = currentUrl;
        } else {
            urlInput.value = 'Unable to retrieve current URL';
            errorElement.textContent = 'Could not detect current page URL';
            errorElement.classList.remove('hidden');
        }
    });
    
    // Handle application check
    checkButton.addEventListener('click', function() {
        // Reset previous state
        resultContainer.textContent = '';
        resultContainer.classList.add('hidden');
        resultContainer.classList.remove('success', 'error');
        errorElement.classList.add('hidden');
        
        // Validate input
        if (!currentUrl) {
            errorElement.textContent = 'No URL detected to check';
            errorElement.classList.remove('hidden');
            return;
        }
        
        // Show loading state
        checkButton.disabled = true;
        spinner.classList.remove('hidden');
        
        // Make API request
        fetch(`${API_BASE_URL}/check_app`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({url: currentUrl})
        })
        .then(response => {
            if (!response.ok) {
                // Handle HTTP errors
                return response.json().then(errorData => {
                    throw new Error(errorData.details || 'Server Error');
                });
            }
            return response.json();
        })
        .then(data => {
            // Clear any previous styles
            resultContainer.classList.remove('error', 'success');
            
            // Set result message and styling
            resultContainer.innerHTML = `<strong>${data.message}</strong>`;
            
            // Add detailed information
            if (data.details) {
                resultContainer.innerHTML += `<br><small>${data.details}</small>`;
            }
            
            // Add domain age info if available
            if (data.domain_info && data.domain_info.age_info) {
                const ageInfo = data.domain_info.age_info;
                resultContainer.innerHTML += `
                    <br><br><div class="domain-info">
                    <strong>Domain Information:</strong><br>
                    Domain: ${data.domain_info.domain}<br>
                    Creation Date: ${ageInfo.creation_date}<br>
                    Domain Age: ${ageInfo.age_days} days<br>
                    Registrar: ${ageInfo.registrar}
                    </div>`;
            }
            
            // Apply appropriate styling based on authenticity
            resultContainer.classList.add(data.is_fake ? 'error' : 'success');
            resultContainer.classList.remove('hidden');
        })
        .catch(error => {
            console.error('Verification Error:', error);
            errorElement.textContent = `Error: ${error.message || 'Unable to verify app authenticity'}`;
            errorElement.classList.remove('hidden');
        })
        .finally(() => {
            spinner.classList.add('hidden');
            checkButton.disabled = false;
        });
    });

    // Handle file upload and analysis
    fileUploadForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const file = fileInput.files[0];
        if (!file) {
            fileResult.innerHTML = '<div class="error">Please select a file to analyze</div>';
            fileResult.classList.remove('hidden');
            return;
        }
        
        // Create form data for file upload
        const formData = new FormData();
        formData.append('file', file);
        
        // Add URL automatically
        if (currentUrl) {
            formData.append('url', currentUrl);
        }
        
        // Show loading state
        fileSpinner.classList.remove('hidden');
        fileUploadForm.querySelector('button').disabled = true;
        
        // Make API request
        fetch(`${API_BASE_URL}/analyze`, {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(errorData => {
                    throw new Error(errorData.message || 'Server Error');
                });
            }
            return response.json();
        })
        .then(data => {
            // Display file analysis results
            let resultHTML = `
                <h3>${data.is_malicious ? '❌ Malicious File Detected' : '✅ File Appears Safe'}</h3>
                <div class="analysis-section">
                    <div class="analysis-item">
                        <span>Filename:</span>
                        <span>${data.filename}</span>
                    </div>
                    <div class="analysis-item">
                        <span>File Size:</span>
                        <span>${formatFileSize(data.file_size)}</span>
                    </div>
                    <div class="analysis-item">
                        <span>File Entropy:</span>
                        <span>${data.entropy.toFixed(2)}</span>
                    </div>
                    <div class="analysis-item">
                        <span>MD5 Hash:</span>
                    </div>
                    <div class="hash-value">${data.md5}</div>
                    <div class="analysis-item">
                        <span>SHA256 Hash:</span>
                    </div>
                    <div class="hash-value">${data.sha256}</div>
                </div>
            `;
            
            // Add alerts if any
            if (data.alerts && data.alerts.length > 0) {
                resultHTML += '<div class="alerts-section"><h4>Detected Issues:</h4>';
                data.alerts.forEach(alert => {
                    resultHTML += `
                        <div class="alert">
                            <div class="alert-title">${formatAlertType(alert.type)}</div>
                            <div class="alert-message">${alert.message}</div>
                        </div>
                    `;
                });
                resultHTML += '</div>';
            }
            
            fileResult.innerHTML = resultHTML;
            fileResult.classList.remove('hidden');
        })
        .catch(error => {
            console.error('File Analysis Error:', error);
            fileResult.innerHTML = `<div class="error">Error: ${error.message || 'Unable to analyze file'}</div>`;
            fileResult.classList.remove('hidden');
        })
        .finally(() => {
            fileSpinner.classList.add('hidden');
            fileUploadForm.querySelector('button').disabled = false;
        });
    });

    // Helper functions
    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' bytes';
        else if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
        else return (bytes / 1048576).toFixed(2) + ' MB';
    }

    function formatAlertType(type) {
        const alertTypes = {
            'extension': 'Suspicious File Extension',
            'mime': 'MIME Type Mismatch',
            'hash': 'Known Malicious Hash',
            'size': 'File Size Anomaly',
            'url': 'URL Safety Issue',
            'content': 'Suspicious Content',
            'entropy': 'High Entropy (Potential Obfuscation)'
        };
        
        return alertTypes[type] || 'Alert';
    }

    // Check if API server is running
    fetch(`${API_BASE_URL}/health`)
        .catch(error => {
            errorElement.textContent = 'Warning: API server appears to be offline. Please ensure the server is running at ' + API_BASE_URL;
            errorElement.classList.remove('hidden');
        });
});