/**
 * DPoP Lab - Student Implementation File
 * 
 * This file contains the main application logic for the DPoP lab.
 * Students should implement the TODO sections to complete the lab.
 */

// Import utilities from utils.js
import {
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
} from './utils.js';

class DPoPLab {
    constructor() {
        this.state = {
            hasSession: false,
            hasBIK: false,
            hasDPoP: false,
            hasPasskey: false,
            isLinked: false
        };
        
        this.currentLinkId = null;
        
        this.initializeEventListeners();
        this.log('[INFO] DPoP Lab initialized. Ready to implement security controls!');
    }

    initializeEventListeners() {
        // Step 1: Session & BIK
        document.getElementById('initBtn').addEventListener('click', () => this.initializeSession());
        document.getElementById('bikBtn').addEventListener('click', () => this.registerBIK());

        // Step 2: DPoP Binding
        document.getElementById('dpopBtn').addEventListener('click', () => this.bindDPoP());

        // Step 3: Testing
        document.getElementById('testBtn').addEventListener('click', () => this.testAPI());

        // Step 4: WebAuthn Passkey
        document.getElementById('regBtn').addEventListener('click', () => this.registerPasskey());
        document.getElementById('authBtn').addEventListener('click', () => this.authenticatePasskey());

        // Step 5: Cross-Device Linking
        document.getElementById('linkBtn').addEventListener('click', () => this.startLinking());
        document.getElementById('completeLinkBtn').addEventListener('click', () => this.completeLinkManually());
    }

    // ============================================================================
    // STEP 1a: Session Initialization
    // ============================================================================

    async initializeSession() {
        this.setLoading('initBtn', 'Initializing...');
        
        try {
            this.log('[INFO] Starting session initialization...');
            
            // TODO: Step 1.1 - Call /session/init endpoint to get CSRF token and reg_nonce from the server
            // Hint: Use APIUtils.post('/session/init', { browser_uuid: 'lab-browser-' + crypto.randomUUID() })
            
            // TODO: Step 1.2 - Store CSRF token and reg_nonce in IndexedDB
            // Hint: Use StorageManager to store the response data with STORAGE_KEYS.CSRF and STORAGE_KEYS.REG_NONCE
            
            // TODO: Step 1.3 - Update state and UI to show that session is initialized
            // Hint: Set this.state.hasSession = true and call this.updateState()
            
            this.setSuccess('initBtn', 'Session initialized!');
            this.log('[SUCCESS] Session initialized successfully');
            
        } catch (error) {
            this.setError('initBtn', 'Initialization failed');
            this.log('[ERROR] Session initialization failed:', error);
        }
    }


    // ============================================================================
    // STEP 1b: Browser Identity Key (BIK) Registration
    // ============================================================================
   
    async registerBIK() {
        this.setLoading('bikBtn', 'Registering BIK...');
        
        try {
            this.log('[INFO] Starting BIK registration...');
            
            // TODO: Step 1.4 - Generate ECDSA key pair with P-256 curve using Web Crypto API for BIK signing and verification
            // Hint: Use crypto.subtle.generateKey() with ECDSA P-256 algorithm for signing and verification
            // Note: This creates the actual cryptographic key material in the browser
            
            // TODO: Step 1.5 - Store BIK keys in IndexedDB
            // Hint: Export public key as JWK using crypto.subtle.exportKey('jwk', publicKey)
            // Store both private key reference and public JWK with STORAGE_KEYS.BIK_CURRENT
            
            // TODO: Step 1.6 - Get stored nonce from IndexedDB
            // Hint: Retrieve the reg_nonce that was stored during session initialization using StorageManager
            
            // TODO: Step 1.7 - Create BIK JWS with nonce and public key. There are 3 parts to a JWS: header, payload, and signature
            // Hint: Create JWT with header (typ: 'bik-reg+jws', alg: 'ES256', jwk: publicJwk)
            // and payload (nonce, iat: timestamp), then use JWTUtils.createJWT(header, payload, privateKey) to sign
            
            // TODO: Step 1.8 - Send to /browser/register endpoint
            // Hint: Use APIUtils.post('/browser/register', jws, { 'X-CSRF-Token': csrfToken })
            
            // TODO: Step 1.9 - Update state and UI
            // Hint: Set this.state.hasBIK = true and call this.updateState()
            
            this.setSuccess('bikBtn', 'BIK registered!');
            this.log('[SUCCESS] BIK registered successfully');
            
        } catch (error) {
            this.setError('bikBtn', 'BIK registration failed');
            this.log('[ERROR] BIK registration failed:', error);
        }
    }

    // ============================================================================
    // STEP 2: DPoP Binding
    // ============================================================================

    async bindDPoP() {
        this.setLoading('dpopBtn', 'Binding DPoP...');
        
        try {
            this.log('[INFO] Starting DPoP binding...');
            
            // TODO: Step 2.1 - Generate DPoP ECDSA key pair with P-256 curve using Web Crypto API for DPoP signing and verification
            // Hint: Use crypto.subtle.generateKey() with ECDSA P-256 algorithm for signing and verification
            // Note: This creates the actual cryptographic key material in the browser
            
            // TODO: Step 2.2 - Store DPoP keys
            // Hint: Export public key as JWK using crypto.subtle.exportKey('jwk', publicKey)
            // Store both private key reference and public JWK with STORAGE_KEYS.DPoP_CURRENT
            
            // TODO: Step 2.3 - Create DPoP JWT with required claims
            // Hint: Create JWT with header (typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk)
            // and payload (htm: 'POST', htu: URLUtils.getAPIURL('dpop/bind'), iat: timestamp, jti: uniqueId)
            // Use JWTUtils.createJWT(header, payload, privateKey) to sign
            
            // TODO: Step 2.4 - Send to /dpop/bind endpoint
            // Hint: Use APIUtils.post('/dpop/bind', dpopJwt, { 'X-CSRF-Token': csrfToken })
            
            // TODO: Step 2.5 - Store binding token and nonce
            // Hint: Store the response.bind token and any DPoP-Nonce header from response.headers
            
            // TODO: Step 2.6 - Update state and UI
            // Hint: Set this.state.hasDPoP = true and call this.updateState()
            
            this.setSuccess('dpopBtn', 'DPoP bound!');
            this.log('[SUCCESS] DPoP bound successfully');
            
        } catch (error) {
            this.setError('dpopBtn', 'DPoP binding failed');
            this.log('[ERROR] DPoP binding failed:', error);
        }
    }

    // ============================================================================
    // STEP 3: Testing
    // ============================================================================

    async testAPI() {
        this.setLoading('testBtn', 'Testing...');
        
        try {
            this.log('[INFO] Starting API test with DPoP...');
            
            // TODO: Step 3.1 - Get stored DPoP key and binding token
            // Hint: Retrieve DPoP keys and binding token from IndexedDB using StorageManager
            
            // TODO: Step 3.2 - Create DPoP proof for API request
            // Hint: Create JWT with header (typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk)
            // and payload (htm: 'POST', htu: URLUtils.getDPoPURI('api/test'), iat: timestamp, jti: uniqueId)
            // Note: Use URLUtils.getDPoPURI() to get full URL without proxy prefix (e.g., https://lab-server.com/api/test)
            // Use JWTUtils.createJWT(header, payload, privateKey) to sign
            
            // TODO: Step 3.3 - Send request to /api/test endpoint
            // Hint: Use APIUtils.post with DPoP and DPoP-Bind headers
            
            this.setSuccess('testBtn', 'Test passed!');
            this.log('[SUCCESS] API test with DPoP successful');
            
        } catch (error) {
            this.setError('testBtn', 'Test failed');
            this.log('[ERROR] API test failed:', error);
        }
    }

    // ============================================================================
    // STEP 4a: WebAuthn Passkey Creation
    // ============================================================================

    async registerPasskey() {
        this.setLoading('regBtn', 'Registering passkey...');
        
        try {
            this.log('[INFO] Starting passkey registration...');
            
            // TODO: Step 4.1 - Check WebAuthn support
            // Hint: Use WebAuthnUtils.isSupported()
            
            // TODO: Step 4.2 - Get registration options from server
            // Hint: Use APIUtils.post('/webauthn/registration/options')
            
            // TODO: Step 4.3 - Create credentials with navigator.credentials.create()
            // Hint: Convert base64 challenge to ArrayBuffer using CryptoUtils.base64UrlToArrayBuffer()
            // Convert user.id to ArrayBuffer, then call navigator.credentials.create({ publicKey: options })
            // This will trigger the actual user challenge (biometrics/PIN) to create the passkey
            
            // TODO: Step 4.4 - Send attestation to server
            // Hint: Convert credential to JSON using WebAuthnUtils.credentialToJSON() and send to /webauthn/registration/verify
            
            // TODO: Step 4.5 - Update state and UI
            // Hint: Set this.state.hasPasskey = true and call this.updateState()
            
            this.setSuccess('regBtn', 'Passkey registered!');
            this.log('[SUCCESS] Passkey registered successfully');
            
        } catch (error) {
            this.setError('regBtn', 'Passkey registration failed');
            this.log('[ERROR] Passkey registration failed:', error);
        }
    }

    // ============================================================================
    // STEP 4b: WebAuthn Passkey Authentication
    // ============================================================================

    async authenticatePasskey() {
        this.setLoading('authBtn', 'Authenticating...');
        
        try {
            this.log('[INFO] Starting passkey authentication...');
            
            // TODO: Step 4.6 - Get authentication options from server
            // Hint: Use APIUtils.post('/webauthn/authentication/options')
            
            // TODO: Step 4.7 - Get credentials with navigator.credentials.get()
            // Hint: Convert base64 challenge to ArrayBuffer using CryptoUtils.base64UrlToArrayBuffer()
            // Convert credential IDs to ArrayBuffers, then call navigator.credentials.get({ publicKey: options })
            // This will trigger the actual user challenge (biometrics/PIN) to verify the passkey
            
            // TODO: Step 4.8 - Send assertion to server
            // Hint: Convert assertion to JSON using WebAuthnUtils.credentialToJSON() and send to /webauthn/authentication/verify
            
            this.setSuccess('authBtn', 'Authenticated!');
            this.log('[SUCCESS] Passkey authentication successful');
            
        } catch (error) {
            this.setError('authBtn', 'Authentication failed');
            this.log('[ERROR] Passkey authentication failed:', error);
        }
    }

    // ============================================================================
    // STEP 5: Cross-Device Linking
    // ============================================================================

    async startLinking() {
        this.setLoading('linkBtn', 'Starting linking...');
        
        try {
            this.log('[INFO] Starting cross-device linking...');
            
            // TODO: Step 5.1 - Call /link/start endpoint
            // Hint: Use APIUtils.post('/link/start')
            
            // TODO: Step 5.2 - Link initiated, waiting for mobile device to register
            // No action needed here - mobile device scans QR and directly calls dpop.fun/reg-link/{link_id}
            // This allows mobile devices to register with the internet service for cross-device verification
            
            // TODO: Step 5.3 - Generate QR code with internet service registration endpoint
            // Hint: Use QRCodeUtils.generateQRCode(internetLinkUrl, 'qrCode', 200, 'M', response.link_url)
            // This creates a QR code with the registration endpoint (dpop.fun/reg-link/{link_id}) but displays the local URL as text
            
            // TODO: Step 5.4 - Show QR container and manual completion button
            // Hint: Display QR code, show completeLinkBtn, and call this.pollForLinkCompletion(response.link_id)
            // The QR code points to dpop.fun/reg-link/{link_id} for direct registration
            
            // TODO: Step 5.5 - Start polling for link completion (both local and internet services)
            // Hint: Store link_id and start polling for completion
            
        } catch (error) {
            this.setError('linkBtn', 'Linking failed');
            this.log('[ERROR] Cross-device linking failed:', error);
        }
    }

    // ============================================================================
    // Utility Methods For Linking (No changes needed)
    // ============================================================================

    async pollForLinkCompletion(linkId) {
        // TODO: Step 5.6 - Implement polling for link completion using PollingUtils
        // Hint: Use PollingUtils.pollForCustomStatus() with a custom function that checks both services:
        // 1. Local: APIUtils.get('/link/status/{linkId}') until status is 'linked'
        // 2. Internet: InternetServiceUtils.verifyLink(linkId) until found is true
        // Use maxAttempts: 60, interval: 5000, and handle success/timeout/error callbacks
        // This allows mobile devices to complete the link via either service
    }

    async completeLinkManually() {
        // TODO: Step 5.7 - Implement manual link completion for testing
        // Hint: Call /link/complete/{linkId} with device information (device_type, user_agent, timestamp)
        // Update state, UI, and hide QR code and manual completion button
    }

    // ============================================================================
    // Utility Methods For UI (No changes needed)
    // ============================================================================

    updateState() {
        // Enable/disable buttons based on state
        document.getElementById('bikBtn').disabled = !this.state.hasSession;
        document.getElementById('dpopBtn').disabled = !this.state.hasBIK;
        document.getElementById('testBtn').disabled = !this.state.hasDPoP;
        document.getElementById('regBtn').disabled = !this.state.hasDPoP;
        document.getElementById('authBtn').disabled = !this.state.hasDPoP;
        document.getElementById('linkBtn').disabled = !this.state.hasDPoP;
        
        // Update status messages
        this.updateStatus('bikStatus', this.state.hasSession ? 'Ready to register BIK' : 'Complete session initialization first');
        this.updateStatus('dpopStatus', this.state.hasBIK ? 'Ready to bind DPoP' : 'Complete BIK registration first');
        this.updateStatus('testStatus', this.state.hasDPoP ? 'Ready to test API' : 'Complete DPoP binding first');
        this.updateStatus('passkeyStatus', this.state.hasDPoP ? 'Ready to register passkey' : 'Complete DPoP binding first');
        this.updateStatus('linkStatus', this.state.hasDPoP ? 'Ready to start linking' : 'Complete DPoP binding first');
    }

    setLoading(buttonId, text) {
        const button = document.getElementById(buttonId);
        button.textContent = text;
        button.disabled = true;
        button.className = 'loading';
    }

    setSuccess(buttonId, text) {
        const button = document.getElementById(buttonId);
        button.textContent = text;
        button.disabled = false;
        button.className = 'success';
    }

    setError(buttonId, text) {
        const button = document.getElementById(buttonId);
        button.textContent = text;
        button.disabled = false;
        button.className = 'error';
    }

    updateStatus(elementId, message) {
        const element = document.getElementById(elementId);
        element.textContent = message;
        element.className = 'status info';
    }

    log(message, data = null) {
        const logContainer = document.getElementById('logContainer');
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.textContent = `[${timestamp}] ${message}`;
        if (data) {
            logEntry.textContent += ` ${JSON.stringify(data)}`;
        }
        logContainer.appendChild(logEntry);
        logContainer.scrollTop = logContainer.scrollHeight;
        
        if (data) {
            console.log(message, data);
        } else {
            console.log(message);
        }
    }

}

// Initialize the lab when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new DPoPLab();
});
