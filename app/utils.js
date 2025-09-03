// DPoP Lab Utilities
// Helper functions for cryptographic operations and storage


// ============================================================================
// IndexedDB Storage Utilities
// ============================================================================

class StorageManager {
    constructor() {
        this.dbName = 'DPoPLabDB';
        this.version = 1;
        this.stores = {
            keys: 'keys',
            meta: 'meta'
        };
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Create stores
                if (!db.objectStoreNames.contains(this.stores.keys)) {
                    db.createObjectStore(this.stores.keys, { keyPath: 'id' });
                }
                if (!db.objectStoreNames.contains(this.stores.meta)) {
                    db.createObjectStore(this.stores.meta, { keyPath: 'id' });
                }
            };
        });
    }

    async get(storeName, id) {
        const db = await this.init();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readonly');
            const store = transaction.objectStore(storeName);
            const request = store.get(id);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async put(storeName, data) {
        const db = await this.init();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.put(data);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async delete(storeName, id) {
        const db = await this.init();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.delete(id);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async clear(storeName) {
        const db = await this.init();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.clear();
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async wipe() {
        const db = await this.init();
        await Promise.all([
            this.clear(this.stores.keys),
            this.clear(this.stores.meta)
        ]);
    }
}

// ============================================================================
// Cryptographic Utilities
// ============================================================================

class CryptoUtils {
    static async generateKeyPair() {
        return await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            false, // extractable
            ['sign', 'verify']
        );
    }

    static async exportPublicKey(publicKey) {
        const exported = await crypto.subtle.exportKey('jwk', publicKey);
        return {
            kty: exported.kty,
            crv: exported.crv,
            x: exported.x,
            y: exported.y
        };
    }

    static async sign(data, privateKey) {
        const encoder = new TextEncoder();
        const message = encoder.encode(data);
        const signature = await crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            privateKey,
            message
        );
        return this.arrayBufferToBase64Url(signature);
    }

    static async verify(signature, data, publicKey) {
        const encoder = new TextEncoder();
        const message = encoder.encode(data);
        const signatureBuffer = this.base64UrlToArrayBuffer(signature);
        
        return await crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            publicKey,
            signatureBuffer,
            message
        );
    }

    static arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    static base64UrlToArrayBuffer(base64Url) {
        const base64 = base64Url
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const padding = '='.repeat((4 - base64.length % 4) % 4);
        const binary = atob(base64 + padding);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    static generateNonce() {
        const array = new Uint8Array(18);
        crypto.getRandomValues(array);
        return this.arrayBufferToBase64Url(array);
    }

    static generateJti() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return this.arrayBufferToBase64Url(array);
    }
}

// ============================================================================
// JWT Utilities
// ============================================================================

class JWTUtils {
    static createJWT(header, payload, privateKey) {
        return new Promise(async (resolve, reject) => {
            try {
                const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
                const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
                
                const data = `${encodedHeader}.${encodedPayload}`;
                const signature = await CryptoUtils.sign(data, privateKey);
                
                resolve(`${data}.${signature}`);
            } catch (error) {
                reject(error);
            }
        });
    }

    static base64UrlEncode(str) {
        return btoa(str)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    static base64UrlDecode(str) {
        const base64 = str
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const padding = '='.repeat((4 - base64.length % 4) % 4);
        return atob(base64 + padding);
    }
}

// ============================================================================
// DPoP Utilities
// ============================================================================

class DPoPUtils {
    static async createDPoPProof(url, method, nonce, privateKey, publicJwk) {
        const now = Math.floor(Date.now() / 1000);
        const jti = CryptoUtils.generateJti();
        
        const header = {
            typ: 'dpop+jwt',
            alg: 'ES256',
            jwk: publicJwk
        };
        
        const payload = {
            htm: method,
            htu: url,
            iat: now,
            jti: jti
        };
        
        if (nonce) {
            payload.nonce = nonce;
        }
        
        return await JWTUtils.createJWT(header, payload, privateKey);
    }

    static async createBIKJWS(nonce, privateKey, publicJwk) {
        const now = Math.floor(Date.now() / 1000);
        
        const header = {
            typ: 'bik-reg+jws',
            alg: 'ES256',
            jwk: publicJwk
        };
        
        const payload = {
            nonce: nonce,
            iat: now
        };
        
        return await JWTUtils.createJWT(header, payload, privateKey);
    }
}

// ============================================================================
// WebAuthn Utilities
// ============================================================================

class WebAuthnUtils {
    static isSupported() {
        return window.PublicKeyCredential && 
            typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function';
    }

    static async createCredentials(options) {
        try {
            // Convert base64 challenge to ArrayBuffer
            if (options.challenge) {
                options.challenge = this.base64UrlToArrayBuffer(options.challenge);
            }
            
            // Convert user.id from base64 to ArrayBuffer
            if (options.user && options.user.id) {
                options.user.id = this.base64UrlToArrayBuffer(options.user.id);
            }
            
            const credential = await navigator.credentials.create({
                publicKey: options
            });
            return credential;
        } catch (error) {
            throw new Error(`WebAuthn creation failed: ${error.message}`);
        }
    }

    static async getCredentials(options) {
        try {
            // Convert base64 challenge to ArrayBuffer
            if (options.challenge) {
                options.challenge = this.base64UrlToArrayBuffer(options.challenge);
            }
            
            // Convert credential IDs from base64 to ArrayBuffer
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(cred => ({
                    ...cred,
                    id: this.base64UrlToArrayBuffer(cred.id)
                }));
            }
            
            const assertion = await navigator.credentials.get({
                publicKey: options
            });
            return assertion;
        } catch (error) {
            throw new Error(`WebAuthn authentication failed: ${error.message}`);
        }
    }

    static credentialToJSON(credential) {
        if (credential instanceof ArrayBuffer) {
            return this.arrayBufferToBase64Url(credential);
        } else if (credential instanceof Array) {
            return credential.map(c => this.credentialToJSON(c));
        } else if (credential instanceof Object) {
            const obj = {};
            for (let key in credential) {
                obj[key] = this.credentialToJSON(credential[key]);
            }
            return obj;
        } else {
            return credential;
        }
    }

    static arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    static base64UrlToArrayBuffer(base64Url) {
        const base64 = base64Url
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const padding = '='.repeat((4 - base64.length % 4) % 4);
        const binary = atob(base64 + padding);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
}



// ============================================================================
// QR Code Utilities
// ============================================================================

class QRCodeUtils {
    static async generateQRCode(text, elementId, size = 200, errorCorrection = 'M', displayText = null) {
        if (!text || !text.trim()) {
            throw new Error('Text input is required');
        }

        const element = document.getElementById(elementId);
        if (!element) {
            throw new Error(`Element with id '${elementId}' not found`);
        }

        // Check if QRCode library is available
        if (typeof QRCode === 'undefined') {
            throw new Error('QRCode library not loaded. Please ensure qrcode.min.js is loaded before utils.js');
        }

        // Fix proxy path in link URL if needed
        let linkUrl = text;
        const pathname = window.location.pathname;
        if (pathname.includes('/proxy/')) {
            const proxyMatch = pathname.match(/^(\/proxy\/\d+\/)/);
            if (proxyMatch) {
                const proxyPrefix = proxyMatch[1];
                // Remove the proxy prefix from the server's link_url and add it back
                const cleanUrl = linkUrl.replace(/^https?:\/\/[^\/]+/, '');
                linkUrl = `${window.location.origin}${proxyPrefix}${cleanUrl}`;
                console.log('[QRCodeUtils] Fixed proxy path in link URL:', { original: text, fixed: linkUrl });
            }
        } else if (pathname.includes('/lab/')) {
            const labMatch = pathname.match(/^(\/lab\/)/);
            if (labMatch) {
                const labPrefix = labMatch[1];
                const cleanUrl = linkUrl.replace(/^https?:\/\/[^\/]+/, '');
                linkUrl = `${window.location.origin}${labPrefix}${cleanUrl}`;
                console.log('[QRCodeUtils] Fixed lab path in link URL:', { original: text, fixed: linkUrl });
            }
        }

        try {
            // Clear previous content
            element.innerHTML = '';
            
            // Debug: log available QRCode methods
            console.log('QRCode object:', QRCode);
            console.log('QRCode methods:', Object.getOwnPropertyNames(QRCode));
            
            // Try different QR code library APIs
            if (typeof QRCode.toCanvas === 'function') {
                // Standard qrcode.js API
                await new Promise((resolve, reject) => {
                    QRCode.toCanvas(element, linkUrl.trim(), {
                        width: size,
                        margin: 2,
                        errorCorrectionLevel: errorCorrection,
                        color: {
                            dark: '#000000',
                            light: '#FFFFFF'
                        }
                    }, (error) => {
                        if (error) {
                            reject(error);
                            return;
                        }
                        resolve(true);
                    });
                });
                
                // Display the link text underneath the QR code
                const linkTextElement = document.getElementById('qrLinkText');
                if (linkTextElement) {
                    const textToDisplay = displayText || linkUrl.trim();
                    linkTextElement.innerHTML = `<strong>Link URL:</strong><br><code style="background: #f5f5f5; padding: 5px; border-radius: 3px;">${textToDisplay}</code>`;
                }
            } else if (typeof QRCode.toDataURL === 'function') {
                // Alternative API - generate data URL and create img element
                const dataUrl = await new Promise((resolve, reject) => {
                    QRCode.toDataURL(linkUrl.trim(), {
                        width: size,
                        margin: 2,
                        errorCorrectionLevel: errorCorrection,
                        color: {
                            dark: '#000000',
                            light: '#FFFFFF'
                        }
                    }, (error, url) => {
                        if (error) {
                            reject(error);
                            return;
                        }
                        resolve(url);
                    });
                });
                
                const img = document.createElement('img');
                img.src = dataUrl;
                img.alt = 'QR Code';
                element.appendChild(img);
                
                // Display the link text underneath the QR code
                const linkTextElement = document.getElementById('qrLinkText');
                if (linkTextElement) {
                    const textToDisplay = displayText || linkUrl.trim();
                    linkTextElement.innerHTML = `<strong>Link URL:</strong><br><code style="background: #f5f5f5; padding: 5px; border-radius: 3px;">${textToDisplay}</code>`;
                }
            } else if (typeof QRCode === 'function') {
                // Constructor-based API (like your working example)
                try {
                    // Use the exact same approach as your working function
                    new QRCode(element, linkUrl.trim());
                    
                    // Display the link text underneath the QR code
                    const linkTextElement = document.getElementById('qrLinkText');
                    if (linkTextElement) {
                        const textToDisplay = displayText || linkUrl.trim();
                        linkTextElement.innerHTML = `<strong>Link URL:</strong><br><code style="background: #f5f5f5; padding: 5px; border-radius: 3px;">${textToDisplay}</code>`;
                    }
                    
                    return true;
                } catch (qrError) {
                    console.error('QR code creation failed:', qrError);
                    // Fallback to text representation
                    element.innerHTML = `
                        <div style="border: 2px solid #000; padding: 10px; display: inline-block; font-family: monospace; font-size: 12px; line-height: 14px; background: white;">
                            <div style="font-weight: bold; margin-bottom: 5px;">QR Code (Text Fallback)</div>
                            <div style="word-break: break-all; max-width: 200px;">${linkUrl}</div>
                            <div style="font-size: 10px; color: #666; margin-top: 5px;">Library: ${Object.getOwnPropertyNames(QRCode).join(', ')}</div>
                        </div>
                    `;
                    
                    // Also display link text for fallback
                    const linkTextElement = document.getElementById('qrLinkText');
                    if (linkTextElement) {
                        const textToDisplay = displayText || linkUrl.trim();
                        linkTextElement.innerHTML = `<strong>Link URL:</strong><br><code style="background: #f5f5f5; padding: 5px; border-radius: 3px;">${textToDisplay}</code>`;
                    }
                    
                    return true;
                }
            } else {
                throw new Error(`Unsupported QR code library. Available methods: ${Object.getOwnPropertyNames(QRCode).join(', ')}`);
            }
            
            return true;
        } catch (error) {
            throw new Error(`QR code generation failed: ${error.message}`);
        }
    }
}

// ============================================================================
// API Utilities
// ============================================================================

class APIUtils {
    static async request(url, options = {}) {
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        };
        
        // Properly merge headers to avoid overwriting
        const finalOptions = { ...defaultOptions, ...options };
        if (options.headers) {
            finalOptions.headers = { ...defaultOptions.headers, ...options.headers };
        }
        
        try {
            const response = await fetch(url, finalOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            } else {
                return await response.text();
            }
        } catch (error) {
            throw new Error(`API request failed: ${error.message}`);
        }
    }

    static async get(url, headers = {}) {
        // Use proxy-aware URL generation
        const proxyUrl = this.getProxyAwareUrl(url);
        return this.request(proxyUrl, { method: 'GET', headers });
    }

    static async post(url, data = null, headers = {}) {
        const options = { method: 'POST', headers };
        
        if (data) {
            if (typeof data === 'string') {
                options.body = data;
                options.headers['Content-Type'] = 'text/plain';
            } else {
                options.body = JSON.stringify(data);
            }
        }
        
        // Use proxy-aware URL generation
        const proxyUrl = this.getProxyAwareUrl(url);
        return this.request(proxyUrl, options);
    }
    
    static getProxyAwareUrl(url) {
        // Get proxy prefix from current URL
        const pathname = window.location.pathname;
        let proxyPrefix = '';
        
        // Check for common proxy patterns
        if (pathname.includes('/proxy/')) {
            const proxyMatch = pathname.match(/^(\/proxy\/\d+\/)/);
            if (proxyMatch) {
                proxyPrefix = proxyMatch[1];
            }
        } else if (pathname.includes('/lab/')) {
            const labMatch = pathname.match(/^(\/lab\/)/);
            if (labMatch) {
                proxyPrefix = labMatch[1];
            }
        }
        
        // If we have a proxy prefix, include it in the URL
        if (proxyPrefix) {
            const cleanUrl = url.startsWith('/') ? url.slice(1) : url;
            return `${window.location.origin}${proxyPrefix}${cleanUrl}`;
        }
        
        // No proxy prefix, return original URL
        return url.startsWith('http') ? url : `${window.location.origin}${url.startsWith('/') ? url : '/' + url}`;
    }
}

// ============================================================================
// URL Utilities
// ============================================================================

class URLUtils {
    static getProxyPrefix() {
        // Detect if we're running behind a reverse proxy with path prefix
        // Common patterns: /proxy/8000/, /proxy/port/, /lab/, etc.
        const pathname = window.location.pathname;
        
        // Check for common proxy patterns
        if (pathname.includes('/proxy/')) {
            // Extract the proxy prefix (e.g., /proxy/8000/)
            const proxyMatch = pathname.match(/^(\/proxy\/\d+\/)/);
            if (proxyMatch) {
                return proxyMatch[1];
            }
        }
        
        // Check for other common lab prefixes
        if (pathname.includes('/lab/')) {
            const labMatch = pathname.match(/^(\/lab\/)/);
            if (labMatch) {
                return labMatch[1];
            }
        }
        
        return '';
    }
    
    static getBaseURL() {
        // Get the current page's origin (protocol + hostname + port)
        return window.location.origin;
    }
    
    static getAPIURL(endpoint) {
        // Remove leading slash if present to avoid double slashes
        const cleanEndpoint = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
        const proxyPrefix = this.getProxyPrefix();
        
        // If we have a proxy prefix, include it in the URL
        if (proxyPrefix) {
            return `${this.getBaseURL()}${proxyPrefix}${cleanEndpoint}`;
        }
        
        return `${this.getBaseURL()}/${cleanEndpoint}`;
    }
    
    static getStaticURL(path) {
        // For static files (JS, CSS, etc.), also include proxy prefix if present
        const cleanPath = path.startsWith('/') ? path.slice(1) : path;
        const proxyPrefix = this.getProxyPrefix();
        
        if (proxyPrefix) {
            return `${proxyPrefix}${cleanPath}`;
        }
        
        return `/${cleanPath}`;
    }
}

// ============================================================================
// Internet Service Integration (Convenience Feature)
// ============================================================================

class InternetServiceUtils {
    // Base URL for the internet service endpoints
    static BASE_URL = 'https://dpop.fun';
    
    // Debug: Log when class is defined
    static {
        console.log('[DEBUG] InternetServiceUtils class defined with BASE_URL:', this.BASE_URL);
    }
    
    /**
     * Register a link ID with the internet service for cross-device linking simulation
     * @param {string} linkId - The link ID to register
     * @returns {Promise<Object>} Response from the internet service
     */
    static async registerLink(linkId) {
        try {
            const response = await fetch(`${this.BASE_URL}/reg-link/${linkId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                return await response.json();
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        } catch (error) {
            throw new Error(`Internet service registration failed: ${error.message}`);
        }
    }
    
    /**
     * Check if a link ID exists in the internet service
     * @param {string} linkId - The link ID to check
     * @returns {Promise<Object>} Response from the internet service
     */
    static async verifyLink(linkId) {
        try {
            const response = await fetch(`${this.BASE_URL}/link-verify/${linkId}`);
            
            if (response.ok) {
                return await response.json();
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        } catch (error) {
            throw new Error(`Internet service verification failed: ${error.message}`);
        }
    }
}

// ============================================================================
// Polling Utilities
// ============================================================================

class PollingUtils {
    /**
     * Generic polling utility that checks a status endpoint until a condition is met
     * @param {string} statusEndpoint - API endpoint to check (e.g., '/link/status/{id}')
     * @param {Function} checkCondition - Function that returns true when polling should stop
     * @param {Object} options - Polling options
     * @param {number} options.maxAttempts - Maximum number of attempts (default: 60)
     * @param {number} options.interval - Polling interval in milliseconds (default: 5000)
     * @param {Function} options.onAttempt - Callback for each attempt
     * @param {Function} options.onSuccess - Callback when condition is met
     * @param {Function} options.onTimeout - Callback when max attempts reached
     * @param {Function} options.onError - Callback for errors
     * @returns {Promise} Resolves when condition is met or rejects on timeout/error
     */
    static async pollForStatus(statusEndpoint, checkCondition, options = {}) {
        const {
            maxAttempts = 60,
            interval = 5000,
            onAttempt = () => {},
            onSuccess = () => {},
            onTimeout = () => {},
            onError = () => {}
        } = options;
        
        let attempts = 0;
        
        const poll = async () => {
            try {
                attempts++;
                onAttempt(attempts, maxAttempts);
                
                const response = await APIUtils.get(statusEndpoint);
                
                if (checkCondition(response)) {
                    onSuccess(response);
                    return response;
                }
                
                if (attempts >= maxAttempts) {
                    onTimeout();
                    throw new Error(`Polling timed out after ${maxAttempts} attempts`);
                }
                
                // Continue polling
                setTimeout(poll, interval);
                
            } catch (error) {
                onError(error, attempts, maxAttempts);
                
                if (attempts >= maxAttempts) {
                    throw error;
                } else {
                    // Retry after interval
                    setTimeout(poll, interval);
                }
            }
        };
        
        // Start polling
        return poll();
    }
}

// ============================================================================
// Constants
// ============================================================================

const STORAGE_KEYS = {
    BIK_CURRENT: 'bik_current',
    DPoP_CURRENT: 'dpop_current',
    CSRF: 'csrf',
    REG_NONCE: 'reg_nonce',
    BIND_TOKEN: 'bind_token',
    DPoP_NONCE: 'dpop_nonce'
};

// ============================================================================
// Export utilities for use in the lab
// ============================================================================

// Export utilities as ES6 module
export {
    StorageManager,
    CryptoUtils,
    JWTUtils,
    DPoPUtils,
    WebAuthnUtils,
    QRCodeUtils,
    URLUtils,
    APIUtils,
    PollingUtils,
    InternetServiceUtils,
    STORAGE_KEYS
};

// Debug: Log what's being exported
console.log('[DEBUG] utils.js exports - InternetServiceUtils:', typeof InternetServiceUtils);
console.log('[DEBUG] utils.js exports - InternetServiceUtils.BASE_URL:', InternetServiceUtils?.BASE_URL);

