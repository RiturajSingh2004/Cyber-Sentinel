from flask import Flask, request, jsonify
import os
import hashlib
import magic
import re
import numpy as np
from flask_cors import CORS
import time
import logging
from datetime import datetime
import urllib.parse
import json
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import ssl
import socket
import whois
import ipaddress
import requests
import base64
from bs4 import BeautifulSoup
import html5lib
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Google Safe Browsing API Configuration
SAFE_BROWSING_API_KEY = os.environ.get('YOUR_API_KEY', '')  # Set via environment variable
SAFE_BROWSING_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

class GoogleSafeBrowsing:
    def __init__(self, api_key):
        self.api_key = api_key
        self.api_url = SAFE_BROWSING_API_URL
        self.enabled = bool(api_key)
        if not self.enabled:
            logger.warning("Google Safe Browsing API key not provided. Safe Browsing checks disabled.")
    
    def check_url(self, url, include_browser_inspection=False):
        """
        Check if a URL is in Google's Safe Browsing lists with optional browser inspection
        Returns a dict with threat information or None if the URL is safe
        """
        result = {
            'is_malicious': False,
            'browser_inspection': None
        }
        
        # First, check with Google Safe Browsing API
        if not self.enabled:
            logger.warning("Safe Browsing check skipped: API key not configured")
        else:
            try:
                payload = {
                    'client': {
                        'clientId': 'malware-detector',
                        'clientVersion': '1.0.0'
                    },
                    'threatInfo': {
                        'threatTypes': [
                            'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'
                        ],
                        'platformTypes': ['ANY_PLATFORM'],
                        'threatEntryTypes': ['URL'],
                        'threatEntries': [{'url': url}]
                    }
                }
                
                params = {'key': self.api_key}
                response = requests.post(self.api_url, params=params, json=payload)
                
                if response.status_code == 200:
                    api_result = response.json()
                    if 'matches' in api_result:
                        # Enhanced threat details extraction
                        threats_summary = []
                        threat_details = []
                        
                        for match in api_result['matches']:
                            threat_type = match.get('threatType', 'Unknown')
                            platform_type = match.get('platformType', 'Unknown')
                            threat_entry_type = match.get('threatEntryType', 'Unknown')
                            
                            # Add to summary list
                            threats_summary.append(threat_type)
                            
                            # Create detailed entry
                            detail = {
                                'threatType': threat_type,
                                'platformType': platform_type,
                                'threatEntryType': threat_entry_type
                            }
                            
                            # Add cache duration if available
                            if 'cacheDuration' in match:
                                detail['cacheDuration'] = match['cacheDuration']
                                
                            # Add threat metadata if available
                            if 'threatEntryMetadata' in match:
                                metadata_entries = []
                                for entry in match['threatEntryMetadata'].get('entries', []):
                                    if 'key' in entry and 'value' in entry:
                                        try:
                                            # Decode base64 values
                                            key = base64.b64decode(entry['key']).decode('utf-8')
                                            value = base64.b64decode(entry['value']).decode('utf-8')
                                            metadata_entries.append({'key': key, 'value': value})
                                        except:
                                            metadata_entries.append(entry)
                                detail['metadata'] = metadata_entries
                            
                            threat_details.append(detail)
                        
                        result.update({
                            'is_malicious': True,
                            'threats': threats_summary,
                            'threat_details': threat_details,
                            'raw_response': api_result['matches']
                        })
                else:
                    logger.error(f"Safe Browsing API error: {response.status_code}, {response.text}")
                    
            except Exception as e:
                logger.error(f"Error in Safe Browsing check: {str(e)}")
        
        # If requested, perform browser inspection for suspicious code
        if include_browser_inspection:
            browser_inspection_result = self._perform_browser_inspection(url)
            result['browser_inspection'] = browser_inspection_result
            
            # If browser inspection found issues but Google API didn't, mark as malicious
            if browser_inspection_result.get('is_suspicious') and not result.get('is_malicious'):
                result['is_malicious'] = True
                result['threats'] = result.get('threats', []) + ['SUSPICIOUS_BROWSER_CONTENT']
        
        return result
    
    def _perform_browser_inspection(self, url):
        """
        Inspect URL content for browser-based threats like obfuscated JavaScript, 
        suspicious iframes, redirect chains, etc.
        """
        inspection_result = {
            'is_suspicious': False,
            'issues': []
        }
        
        try:
            # Fetch URL content with timeout and proper headers to mimic a browser
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0',
            }
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            # Check for redirect chains
            if len(response.history) > 3:
                inspection_result['is_suspicious'] = True
                inspection_result['issues'].append({
                    'type': 'excessive_redirects',
                    'message': f'Excessive redirect chain detected ({len(response.history)} redirects)',
                    'details': [r.url for r in response.history]
                })
            
            # If not HTML, skip content inspection
            content_type = response.headers.get('Content-Type', '')
            if not ('text/html' in content_type.lower() or 'application/xhtml+xml' in content_type.lower()):
                return inspection_result
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html5lib')
            
            # Check for obfuscated JavaScript
            js_issues = self._inspect_javascript(soup, response.text)
            if js_issues:
                inspection_result['is_suspicious'] = True
                inspection_result['issues'].extend(js_issues)
            
            # Check for suspicious iframes
            iframe_issues = self._inspect_iframes(soup)
            if iframe_issues:
                inspection_result['is_suspicious'] = True
                inspection_result['issues'].extend(iframe_issues)
            
            # Check for phishing indicators
            phishing_issues = self._inspect_phishing_indicators(soup, url)
            if phishing_issues:
                inspection_result['is_suspicious'] = True
                inspection_result['issues'].extend(phishing_issues)
            
            # Check for popup and redirect scripts
            popup_issues = self._inspect_popups_and_redirects(soup, response.text)
            if popup_issues:
                inspection_result['is_suspicious'] = True
                inspection_result['issues'].extend(popup_issues)
                
            # Add page metadata for reference
            inspection_result['metadata'] = {
                'title': soup.title.string if soup.title else None,
                'final_url': response.url,
                'content_length': len(response.text),
                'server': response.headers.get('Server'),
                'content_type': content_type
            }
            
        except Exception as e:
            logger.error(f"Error during browser inspection: {str(e)}")
            inspection_result['issues'].append({
                'type': 'inspection_error',
                'message': f'Error during page inspection: {str(e)}'
            })
        
        return inspection_result
    
    def _inspect_javascript(self, soup, html_content):
        """Inspect JavaScript content for suspicious patterns"""
        issues = []
        
        # Extract all script elements
        scripts = soup.find_all('script')
        
        # Look for inline scripts
        for script in scripts:
            script_content = script.string
            if not script_content:
                continue
                
            # Check for obfuscation techniques
            obfuscation_patterns = [
                (r'eval\s*\(.*\)', 'Dynamic code execution via eval()'),
                (r'document\.write\s*\(.*\)', 'Dynamic page modification via document.write()'),
                (r'escape\s*\(.*unescape\s*\(', 'String obfuscation via escape/unescape'),
                (r'String\.fromCharCode\(', 'String obfuscation via fromCharCode'),
                (r'\\x[0-9a-f]{2}', 'Hexadecimal escape sequences'),
                (r'\\u[0-9a-f]{4}', 'Unicode escape sequences'),
                (r'atob\s*\(', 'Base64 decoding'),
                (r'\[\s*["\']\w+["\'][\s,]*["\']\w+', 'Array-based string obfuscation'),
            ]
            
            for pattern, description in obfuscation_patterns:
                matches = re.findall(pattern, script_content)
                if matches:
                    issues.append({
                        'type': 'obfuscated_js',
                        'message': f'Potentially obfuscated JavaScript: {description}',
                        'count': len(matches),
                        'pattern': pattern
                    })
            
            # Check for sensitive operations
            sensitive_operations = [
                (r'location\s*=|location\.href\s*=|location\.replace\s*\(', 'Page redirect'),
                (r'window\.open\s*\(', 'Popup window creation'),
                (r'navigator\.userAgent', 'Browser fingerprinting'),
                (r'document\.cookie', 'Cookie access/manipulation'),
                (r'localStorage|sessionStorage', 'Client-side storage access'),
            ]
            
            for pattern, description in sensitive_operations:
                if re.search(pattern, script_content):
                    issues.append({
                        'type': 'sensitive_js_operation',
                        'message': f'Sensitive JavaScript operation: {description}'
                    })
        
        # Check for hidden script tags or iframes in encoded content
        encoded_content_patterns = [
            (r'\\x3cscript', 'Encoded script tag'),
            (r'\\x3ciframe', 'Encoded iframe tag'),
            (r'\\u003cscript', 'Unicode encoded script tag'),
            (r'\\u003ciframe', 'Unicode encoded iframe tag'),
        ]
        
        for pattern, description in encoded_content_patterns:
            if re.search(pattern, html_content):
                issues.append({
                    'type': 'encoded_script',
                    'message': f'Detected {description} in encoded form'
                })
        
        return issues
    
    def _inspect_iframes(self, soup):
        """Inspect iframes for suspicious attributes or sources"""
        issues = []
        
        iframes = soup.find_all('iframe')
        
        for iframe in iframes:
            # Check for hidden iframes
            if iframe.get('height') == '0' or iframe.get('width') == '0' or iframe.get('hidden'):
                issues.append({
                    'type': 'hidden_iframe',
                    'message': 'Hidden iframe detected',
                    'details': str(iframe)[:200]  # Truncate to avoid large outputs
                })
            
            # Check for suspicious sources
            src = iframe.get('src', '')
            if src and not src.startswith(('http://', 'https://', '/')):
                issues.append({
                    'type': 'suspicious_iframe_src',
                    'message': 'Iframe with suspicious source',
                    'src': src
                })
            
            # Check for data: URIs in iframes
            if src and src.startswith('data:'):
                issues.append({
                    'type': 'data_uri_iframe',
                    'message': 'Iframe using data: URI scheme (potential code hiding)',
                    'src_preview': src[:50] + '...' if len(src) > 50 else src
                })
        
        return issues
    
    def _inspect_phishing_indicators(self, soup, url):
        """Inspect for common phishing page indicators"""
        issues = []
        parsed_url = urllib.parse.urlparse(url)
        
        # Check for password fields in non-HTTPS sites
        if parsed_url.scheme != 'https' and soup.find('input', {'type': 'password'}):
            issues.append({
                'type': 'password_over_http',
                'message': 'Password field detected on non-HTTPS site'
            })
        
        # Check for login forms with suspicious actions
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            
            # Check for password fields in the form
            has_password = bool(form.find('input', {'type': 'password'}))
            
            if has_password:
                # Check if form action goes to a different domain
                if action and not action.startswith('/'):
                    try:
                        action_domain = urllib.parse.urlparse(action).netloc
                        current_domain = parsed_url.netloc
                        
                        if action_domain and action_domain != current_domain:
                            issues.append({
                                'type': 'cross_domain_credentials',
                                'message': 'Login form submits to different domain',
                                'current_domain': current_domain,
                                'target_domain': action_domain
                            })
                    except:
                        pass
        
        # Check for fake favicon (common in phishing sites)
        favicons = soup.find_all('link', rel=lambda r: r and 'icon' in r.lower())
        for favicon in favicons:
            href = favicon.get('href', '')
            if href and not href.startswith(('http://', 'https://', '/')):
                issues.append({
                    'type': 'suspicious_favicon',
                    'message': 'Suspicious favicon source',
                    'href': href
                })
        
        # Look for hidden fields with suspicious names
        hidden_fields = soup.find_all('input', {'type': 'hidden'})
        for field in hidden_fields:
            name = field.get('name', '').lower()
            value = field.get('value', '')
            sensitive_names = ['password', 'pass', 'token', 'auth', 'key', 'secret', 'credential']
            
            if any(sensitive in name for sensitive in sensitive_names) and value:
                issues.append({
                    'type': 'sensitive_hidden_field',
                    'message': f'Hidden field with sensitive name: {name}',
                    'field_info': {'name': name, 'value_preview': value[:20] + '...' if len(value) > 20 else value}
                })
        
        return issues
    
    def _inspect_popups_and_redirects(self, soup, html_content):
        """Inspect for popup and redirect techniques"""
        issues = []
        
        # Check for common popup and redirect patterns in scripts
        redirect_patterns = [
            r'window\.location\s*=',
            r'window\.location\.href\s*=',
            r'window\.location\.replace\s*\(',
            r'document\.location\s*=',
            r'document\.location\.href\s*=',
            r'document\.location\.replace\s*\(',
            r'setTimeout\s*\(\s*function\s*\(\s*\)\s*{\s*window\.location',
            r'setInterval\s*\(\s*function\s*\(\s*\)\s*{\s*window\.location',
        ]
        
        popup_patterns = [
            r'window\.open\s*\(',
            r'onclick\s*=\s*[\'"]window\.open\s*\(',
        ]
        
        # Find scripts and check them
        scripts = soup.find_all('script')
        for script in scripts:
            script_content = script.string
            if not script_content:
                continue
            
            # Check for redirects
            for pattern in redirect_patterns:
                if re.search(pattern, script_content):
                    issues.append({
                        'type': 'js_redirect',
                        'message': 'JavaScript redirect detected',
                        'pattern': pattern
                    })
            
            # Check for popups
            for pattern in popup_patterns:
                if re.search(pattern, script_content):
                    issues.append({
                        'type': 'js_popup',
                        'message': 'JavaScript popup detected',
                        'pattern': pattern
                    })
        
        # Check for meta refresh redirects
        meta_refresh = soup.find('meta', {'http-equiv': 'refresh'})
        if meta_refresh:
            content = meta_refresh.get('content', '')
            issues.append({
                'type': 'meta_redirect',
                'message': 'Meta refresh redirect detected',
                'content': content
            })
        
        # Check for automatic form submission
        for script in scripts:
            script_content = script.string
            if script_content and re.search(r'document\.forms\[\d+\]\.submit\(\)', script_content):
                issues.append({
                    'type': 'auto_form_submit',
                    'message': 'Automatic form submission detected'
                })
        
        return issues

class SecureBERT:
    def __init__(self):
        try:
            # Load SecureBERT model and tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained("jackaduma/SecureBERT")
            self.model = AutoModelForSequenceClassification.from_pretrained("jackaduma/SecureBERT")
            
            # Set model to evaluation mode
            self.model.eval()
            
            # Check if CUDA is available
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model.to(self.device)
            
            logger.info(f"SecureBERT model loaded successfully on {self.device}")
            self.model_loaded = True
        except Exception as e:
            logger.error(f"Error loading SecureBERT model: {str(e)}")
            # Fallback to keyword-based detection if model loading fails
            self.model_loaded = False
            self.suspicious_keywords = [
                'invoice', 'payment', 'password', 'payroll', 'bank', 'account',
                'urgent', 'verify', 'login', 'security', 'update', 'free',
                'win', 'prize', 'crypto', 'wallet', 'tax', 'refund'
            ]
            logger.warning("Using fallback keyword-based detection instead")
    
    def predict(self, text):
        if not self.model_loaded:
            # Fallback to keyword matching
            return self._keyword_predict(text)
        
        try:
            # Truncate text if it's too long for the model
            max_length = self.tokenizer.model_max_length
            if len(text) > max_length:
                text = text[:max_length]
            
            # Tokenize and prepare input
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, padding=True)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Get prediction
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = torch.nn.functional.softmax(logits, dim=1)
                malicious_prob = probs[0][1].item()  # Assuming binary classification
            
            return malicious_prob
        except Exception as e:
            logger.error(f"Error during SecureBERT prediction: {str(e)}")
            # Fallback to keyword matching if prediction fails
            return self._keyword_predict(text)
    
    def _keyword_predict(self, text):
        """Fallback method using keyword matching"""
        text = text.lower()
        score = 0
        
        # Simple keyword matching
        for keyword in self.suspicious_keywords:
            if keyword in text:
                score += 0.2  # Increase suspicion score
        
        return min(score, 1.0)  # Cap at 1.0

app = Flask(__name__)
CORS(app)

# Initialize SecureBERT
secure_bert = SecureBERT()

# Initialize Google Safe Browsing
safe_browsing = GoogleSafeBrowsing(SAFE_BROWSING_API_KEY)

# Load malicious file hashes from a database
def load_malicious_hashes():
    try:
        with open('malicious_hashes.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Create real-world initialized data
        real_hashes = {
            "md5": [
                "44d88612fea8a8f36de82e1278abb02f",  # Conficker worm
                "841dd3db32923f22d065243a29252728",  # Zeus trojan variant
                "5e28284f9b5f9097640d58a73d38ad4c",  # WannaCry ransomware
                "84c82835a5d21bbcf75a61706d8ab549",  # Emotet malware
                "0a209ac0de4ac033f31d6ba9191a8f7a",  # CryptoLocker ransomware
                "b7f2e42d5a09c5a269d67c658b3f4087",  # BlackEnergy malware
                "c365ddaa345cfcaff3d629505572a484",  # Gameover Zeus
                "2f24a2c5553c6a47980f55e9a6f67e34"   # Locky ransomware
            ],
            "sha256": [
                "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",  # EMOTET
                "fe90c2c733cb6b9cc0882287c9c0149dbfbc3db367ffa0b0142eface72e41547",  # Trickbot
                "5510365d45bbb02c781fba2d1232583a15583bd86c12c9846ccebcaca6a25c11",  # Ryuk
                "a93ee7ea13238bd038bcbec635f39619db566145498fe6e0ea60e6e76d614bd3",  # Petya/NotPetya
                "7a828afd2abf153d840938090d498072b7e507c7021e4cdd8c6baf727cafc545",  # DarkSide ransomware
                "10533176ffb5f7db366c824f9cd0639bbede02d4340f893e9261a5446dc2be35",  # REvil/Sodinokibi
                "d8a9879a99ac7b12e63e6bcae7f965fbf1b63d892a8649ab1d6b08ce711f7127",  # Conti ransomware
                "4a468603fdcb7a2eb5770705898cf9ef37dade8594a471654ee5d5d9c4138df3",  # LockBit
                "495b61d28e66fbc43fea2d7a358e9a141597b4108c5b84124c275bc50b7d384b"   # BlackCat
            ]
        }
        # Save the real-world initialized data
        with open('malicious_hashes.json', 'w') as f:
            json.dump(real_hashes, f)
        return real_hashes

MALICIOUS_HASHES = load_malicious_hashes()

# Helper functions for file analysis
def analyze_file_extension(filename):
    """Check for suspicious file extensions"""
    filename = filename.lower()
    
    # Check for double extensions
    extensions = filename.split('.')
    if len(extensions) > 2:
        dangerous_second_exts = ['exe', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'wsf', 'msi']
        if extensions[-1] in dangerous_second_exts:
            return True, f"Double extension detected: {filename}"
    
    # Known dangerous extensions
    dangerous_extensions = ['exe', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'wsf', 'msi']
    extension = extensions[-1]
    if extension in dangerous_extensions:
        return True, f"Potentially dangerous file extension: .{extension}"
    
    return False, None

def calculate_file_hash(file_data):
    """Calculate MD5 and SHA-256 hashes of a file"""
    md5_hash = hashlib.md5(file_data).hexdigest()
    sha256_hash = hashlib.sha256(file_data).hexdigest()
    return md5_hash, sha256_hash

def check_hash_database(md5_hash, sha256_hash):
    """Check if file hash matches known malicious hashes"""
    if md5_hash in MALICIOUS_HASHES["md5"] or sha256_hash in MALICIOUS_HASHES["sha256"]:
        return True, "File hash matches known malicious file"
    return False, None

def detect_mime_type_mismatch(file_data, claimed_extension):
    """Detect if the actual file type doesn't match its extension"""
    try:
        # Use python-magic to determine actual file type
        mime = magic.Magic(mime=True)
        actual_mime = mime.from_buffer(file_data)
        
        # Common MIME type mappings
        extension_mime_map = {
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls': 'application/vnd.ms-excel',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'txt': 'text/plain',
            'html': 'text/html',
            'htm': 'text/html',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'mp3': 'audio/mpeg',
            'mp4': 'video/mp4',
            'exe': 'application/x-msdownload',
            'zip': 'application/zip',
            'rar': 'application/x-rar-compressed'
        }
        
        # Check if claimed extension matches actual MIME type
        claimed_extension = claimed_extension.lower().lstrip('.')
        expected_mime = extension_mime_map.get(claimed_extension)
        
        if expected_mime and expected_mime != actual_mime:
            return True, f"MIME type mismatch: File claims to be {claimed_extension} but is actually {actual_mime}"
        
        # Specifically check for executable content
        if 'executable' in actual_mime.lower() and claimed_extension not in ['exe', 'msi', 'bat']:
            return True, f"Executable content detected in non-executable file format"
            
        return False, None
    except Exception as e:
        logger.error(f"Error detecting MIME type: {str(e)}")
        return False, None

def analyze_file_entropy(file_data):
    """Calculate Shannon entropy of file data to detect encryption/obfuscation"""
    if len(file_data) == 0:
        return 0
    
    byte_counts = {}
    for byte in file_data:
        if isinstance(byte, str):
            byte = ord(byte)
        if byte in byte_counts:
            byte_counts[byte] += 1
        else:
            byte_counts[byte] = 1
    
    entropy = 0
    for count in byte_counts.values():
        probability = count / len(file_data)
        entropy -= probability * np.log2(probability)
    
    # High entropy (> 7.0) often indicates encryption or compression
    return entropy

def check_file_size_anomaly(file_size, claimed_extension):
    """Check if file size is unusual for its claimed type"""
    # Size limits in bytes for different file types
    size_limits = {
        'pdf': 10 * 1024 * 1024,  # 10 MB for PDFs
        'doc': 5 * 1024 * 1024,   # 5 MB for DOC
        'docx': 5 * 1024 * 1024,  # 5 MB for DOCX
        'txt': 1 * 1024 * 1024,   # 1 MB for text files
        'html': 2 * 1024 * 1024,  # 2 MB for HTML
        'htm': 2 * 1024 * 1024,   # 2 MB for HTM
    }
    
    claimed_extension = claimed_extension.lower().lstrip('.')
    
    # Check for anomalously large files
    if claimed_extension in size_limits and file_size > size_limits[claimed_extension]:
        return True, f"File size ({file_size/1024/1024:.2f} MB) is larger than expected for {claimed_extension} file"
    
    # Check for suspiciously small files
    if file_size < 100 and claimed_extension not in ['txt', 'html', 'htm']:
        return True, f"File is suspiciously small ({file_size} bytes)"
    
    return False, None

def is_ip_address(domain):
    """Check if the domain is an IP address"""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def verify_ssl_certificate(domain):
    """
    Enhanced SSL certificate verification with detailed checks
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                
                # Extract certificate details
                return {
                    'is_valid': True,
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'expiration': datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                }
    except ssl.SSLCertVerificationError as e:
        logger.warning(f"SSL Certificate Verification Error: {e}")
        return {'is_valid': False, 'error': str(e)}
    except socket.timeout:
        logger.warning(f"SSL connection timeout for {domain}")
        return {'is_valid': False, 'error': 'Connection Timeout'}
    except Exception as e:
        logger.error(f"Unexpected SSL verification error: {e}")
        return {'is_valid': False, 'error': 'Verification Failed'}

def check_domain_age(domain):
    """
    Comprehensive domain age check with detailed error handling
    """
    try:
        domain_info = whois.whois(domain)
        
        # Extract creation date with multiple fallback strategies
        creation_date = None
        if hasattr(domain_info, 'creation_date'):
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            elif isinstance(domain_info.creation_date, datetime):
                creation_date = domain_info.creation_date
        
        # Check for alternative date fields
        if not creation_date:
            date_fields = ['created', 'creation', 'registered', 'reg_date']
            for field in date_fields:
                if hasattr(domain_info, field):
                    date_value = getattr(domain_info, field)
                    if isinstance(date_value, (datetime, list)):
                        creation_date = date_value[0] if isinstance(date_value, list) else date_value
                        break
        
        if creation_date:
            age = (datetime.now() - creation_date).days
            return {
                'age_days': age,
                'creation_date': creation_date.strftime('%Y-%m-%d'),
                'registrar': domain_info.registrar or 'Unknown'
            }
        
        return None
    except Exception as e:
        logger.error(f"Unexpected error in domain age check: {e}")
        return None

def analyze_url_safety(url):
    """Analyze URL for suspicious characteristics and check Google Safe Browsing"""
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.split(':')[0]
        
        # First, check Google Safe Browsing
        safe_browsing_result = safe_browsing.check_url(url)
        if safe_browsing_result and safe_browsing_result.get('is_malicious', False):
            threat_types = ", ".join(safe_browsing_result.get('threats', ['Unknown threat']))
            return True, f"Google Safe Browsing alert: {threat_types}"
        
        # Continue with other checks
        # Skip analysis for IP addresses
        if is_ip_address(domain):
            return True, "Direct IP address URLs are suspicious"

        # Check for HTTPS
        if parsed_url.scheme != 'https':
            return True, "Non-HTTPS URL detected"
        
        # Check for suspicious domains
        suspicious_domains = ['freefile', 'download-now', 'free-download', 'crack', 'keygen', 'warez']
        for domain_part in suspicious_domains:
            if domain_part in parsed_url.netloc.lower():
                return True, f"Suspicious domain detected: {parsed_url.netloc}"
        
        # Risk assessment
        risks = []
        is_suspicious = False
        
        # Domain age check
        domain_age_info = check_domain_age(domain)
        if domain_age_info:
            if domain_age_info['age_days'] < 180:
                risks.append(f"Recently registered domain (Age: {domain_age_info['age_days']} days)")
                is_suspicious = True
        
        # SSL verification
        ssl_result = verify_ssl_certificate(domain)
        if not ssl_result['is_valid']:
            risks.append(f"Invalid SSL Certificate: {ssl_result.get('error', 'Unknown Error')}")
            is_suspicious = True
        
        # Suspicious keywords in URL
        suspicious_keywords = ['clone', 'fake', 'mirror', 'replica', 'test', 'mock']
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            risks.append("Suspicious URL keywords detected")
            is_suspicious = True
        
        if is_suspicious:
            return True, f"URL safety concerns: {', '.join(risks)}"
        
        return False, None
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return True, f"Error analyzing URL: {str(e)}"

def text_based_threat_detection(text):
    """Use SecureBERT to detect threats in text content"""
    threat_score = secure_bert.predict(text)
    if threat_score > 0.7:
        return True, f"Text content appears suspicious (score: {threat_score:.2f})"
    return False, None

def analyze_url(url):
    """
    Comprehensive URL analysis with multiple risk checks and enhanced Safe Browsing details
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.split(':')[0]
        
        # Check Google Safe Browsing first
        safe_browsing_result = safe_browsing.check_url(url)
        
        # Enhanced Safe Browsing reporting
        safe_browsing_info = {
            'checked': safe_browsing.enabled,
            'result': 'Clean' if safe_browsing.enabled else 'Check skipped (API not configured)'
        }
        
        if safe_browsing_result and safe_browsing_result.get('is_malicious', False):
            threat_types = ", ".join(safe_browsing_result.get('threats', ['Unknown threat']))
            
            # Add detailed Safe Browsing information
            safe_browsing_info.update({
                'is_malicious': True,
                'threats': safe_browsing_result.get('threats', []),
                'details': safe_browsing_result.get('threat_details', [])
            })
            
            # Create threat descriptions
            threat_descriptions = []
            for threat in safe_browsing_result.get('threat_details', []):
                description = f"Type: {threat.get('threatType', 'Unknown')}"
                if 'platformType' in threat:
                    description += f", Platform: {threat.get('platformType')}"
                if 'metadata' in threat:
                    meta_info = "; ".join([f"{item.get('key')}: {item.get('value')}" for item in threat.get('metadata', [])])
                    if meta_info:
                        description += f", Metadata: [{meta_info}]"
                threat_descriptions.append(description)
            
            return {
                'is_fake': True,
                'message': 'Google Safe Browsing Alert',
                'details': f"This URL has been flagged as malicious: {threat_types}",
                'safe_browsing': safe_browsing_info,
                'threat_descriptions': threat_descriptions
            }
        
        # Continue with other checks as before
        # Skip analysis for IP addresses
        if is_ip_address(domain):
            return {
                'is_fake': True,
                'message': 'IP Address Detection',
                'details': 'Direct IP address URLs are suspicious',
                'safe_browsing': safe_browsing_info
            }

        # Risk assessment dictionary
        risks = []
        is_fake = False

        # Domain age check
        domain_age_info = check_domain_age(domain)
        if domain_age_info:
            if domain_age_info['age_days'] < 180:
                risks.append(f"Recently registered domain (Age: {domain_age_info['age_days']} days)")
                is_fake = True
            
        # SSL verification
        ssl_result = verify_ssl_certificate(domain)
        if not ssl_result['is_valid']:
            risks.append(f"Invalid SSL Certificate: {ssl_result.get('error', 'Unknown Error')}")
            is_fake = True

        # Suspicious keywords
        suspicious_keywords = ['clone', 'fake', 'mirror', 'replica', 'test', 'mock']
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            risks.append("Suspicious URL keywords detected")
            is_fake = True

        # Prepare result
        return {
            'is_fake': is_fake,
            'message': "App Authenticity" if not is_fake else "Potential Fake App Detected",
            'details': f"Risks identified: {', '.join(risks)}" if risks else "No immediate risks found",
            'domain_info': {
                'domain': domain,
                'age_info': domain_age_info
            },
            'safe_browsing': safe_browsing_info
        }
    
    except Exception as e:
        logger.error(f"Unexpected error in URL analysis: {e}")
        return {
            'is_fake': True, 
            'message': 'Analysis Error', 
            'details': f'Unexpected error during URL verification: {e}',
            'safe_browsing': {'checked': False, 'result': 'Analysis failed'}
        }

@app.route('/analyze', methods=['POST'])
def analyze_file():
    try:
        # Check if the post has the file part
        if 'file' not in request.files:
            return jsonify({
                'status': 'error',
                'message': 'No file part in the request'
            }), 400
        
        file = request.files['file']
        filename = file.filename
        url = request.form.get('url', '')
        
        # If user didn't select a file
        if filename == '':
            return jsonify({
                'status': 'error', 
                'message': 'No file selected'
            }), 400
        
        # Read the file data
        file_data = file.read()
        file_size = len(file_data)
        
        # Start building our response
        response = {
            'status': 'success',
            'filename': filename,
            'file_size': file_size,
            'alerts': [],
            'is_malicious': False,
            'analysis_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
        
        # Calculate file hashes
        md5_hash, sha256_hash = calculate_file_hash(file_data)
        response['md5'] = md5_hash
        response['sha256'] = sha256_hash
        
        # 1. File Extension Analysis
        extension = filename.split('.')[-1] if '.' in filename else ''
        is_suspicious, message = analyze_file_extension(filename)
        if is_suspicious:
            response['alerts'].append({'type': 'extension', 'message': message})
            response['is_malicious'] = True
        
        # 2. MIME Type Mismatch Detection
        is_suspicious, message = detect_mime_type_mismatch(file_data, extension)
        if is_suspicious:
            response['alerts'].append({'type': 'mime', 'message': message})
            response['is_malicious'] = True
        
        # 3. Hash Database Check
        is_suspicious, message = check_hash_database(md5_hash, sha256_hash)
        if is_suspicious:
            response['alerts'].append({'type': 'hash', 'message': message})
            response['is_malicious'] = True
        
        # 4. File Size Anomaly Detection
        is_suspicious, message = check_file_size_anomaly(file_size, extension)
        if is_suspicious:
            response['alerts'].append({'type': 'size', 'message': message})
        
        # 5. URL Safety Analysis (if URL provided)
        if url:
            response['url'] = url
            
            # Enhanced Safe Browsing check
            safe_browsing_result = safe_browsing.check_url(url)
            
            if safe_browsing_result and safe_browsing_result.get('is_malicious', False):
                # Detailed Safe Browsing report
                threat_types = ", ".join(safe_browsing_result.get('threats', ['Unknown threat']))
                response['safe_browsing'] = {
                    'is_malicious': True,
                    'threats': safe_browsing_result.get('threats', []),
                    'details': safe_browsing_result.get('threat_details', [])
                }
                
                response['alerts'].append({
                    'type': 'safe_browsing', 
                    'message': f"Google Safe Browsing alert: {threat_types}",
                    'details': safe_browsing_result.get('threat_details', [])
                })
                response['is_malicious'] = True
            else:
                # Continue with other URL checks
                is_suspicious, message = analyze_url_safety(url)
                if is_suspicious:
                    response['alerts'].append({'type': 'url', 'message': message})
                    response['is_malicious'] = True
        
        # 6. Text Content Analysis (for text-based files)
        text_extensions = ['txt', 'html', 'htm', 'xml', 'json', 'csv']
        if extension.lower() in text_extensions:
            try:
                text_content = file_data.decode('utf-8')
                is_suspicious, message = text_based_threat_detection(text_content)
                if is_suspicious:
                    response['alerts'].append({'type': 'content', 'message': message})
                    response['is_malicious'] = True
            except UnicodeDecodeError:
                # Not a valid text file
                response['alerts'].append({
                    'type': 'content', 
                    'message': f"File with .{extension} extension contains binary data"
                })
                response['is_malicious'] = True
        
        # 7. File Entropy Analysis
        entropy = analyze_file_entropy(file_data)
        response['entropy'] = entropy
        if entropy > 7.5:  # High entropy threshold
            response['alerts'].append({
                'type': 'entropy',
                'message': f"File has high entropy ({entropy:.2f}), possibly encrypted or obfuscated"
            })
        
        # Log the analysis results
        logger.info(f"Analyzed file: {filename}, Result: {'Malicious' if response['is_malicious'] else 'Clean'}")
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f"Server error: {str(e)}"
        }), 500

@app.route('/check_app', methods=['POST'])
def check_app():
    """
    Flask route for app URL verification
    """
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                'is_fake': True, 
                'message': 'Invalid URL', 
                'details': 'No URL provided for verification'
            }), 400

        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'is_fake': True, 
                'message': 'Invalid URL', 
                'details': 'No URL provided for verification'
            }), 400

        # Validate URL format
        try:
            parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL format")
        except Exception:
            return jsonify({
                'is_fake': True, 
                'message': 'Invalid URL', 
                'details': 'Provided URL is not well-formed'
            }), 400

        # Log the URL being checked
        logger.info(f"Checking URL: {url}")
        
        # Analyze URL using the comprehensive function
        result = analyze_url(url)
        
        # Log the result
        logger.info(f"URL check result for {url}: {'Suspicious' if result['is_fake'] else 'Authentic'}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Server error in check_app route: {e}")
        return jsonify({
            'is_fake': True, 
            'message': 'Server Error', 
            'details': f'Unexpected error during URL verification: {str(e)}'
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': time.time()})

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
