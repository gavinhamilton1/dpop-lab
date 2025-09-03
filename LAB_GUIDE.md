# DPoP Lab Implementation Guide

This guide provides step-by-step instructions for implementing each component of the DPoP security system.

## Overview

You will implement a complete browser identity and security system with:
- Browser Identity Key (BIK) registration
- DPoP (Demonstration of Proof-of-Possession) binding
- API testing with DPoP
- WebAuthn passkey support
- Cross-device linking with internet service integration

## Prerequisites

- Lab application running on your local server (URL will be shown when you start the server)
- Modern browser with WebAuthn support
- Basic JavaScript knowledge
- Understanding of cryptographic concepts

## Architecture

The lab uses ES6 modules with the following structure:
- `app.js` - Main application logic (student implementation)
- `utils.js` - Utility classes and helper functions
- `app-complete.js` - Complete solution for reference
- `app-todo.js` - Template with TODO comments

## Step-by-Step Implementation

### Step 1a: Session Initialization

**Objective**: Initialize a session with the server to obtain CSRF token and registration nonce.

**Implementation in `app.js`**:

The `initializeSession()` method contains TODO comments. Here's the complete implementation:

```javascript
async initializeSession() {
    this.setLoading('initBtn', 'Initializing...');
    
    try {
        this.log('[INFO] Starting session initialization...');
        
        // Step 1.1 - Call /session/init endpoint to get CSRF token and reg_nonce from the server
        this.log('[INFO] Calling /session/init endpoint...');
        const response = await APIUtils.post('/session/init', {
            browser_uuid: 'lab-browser-' + crypto.randomUUID() 
        });
        this.log('[INFO] Server response received', { 
            csrf_length: response.csrf?.length || 0,
            nonce_length: response.reg_nonce?.length || 0,
            state: response.state 
        });
        
        // Step 1.2 - Store CSRF token and reg_nonce in IndexedDB
        this.log('[INFO] Storing session data in IndexedDB...');
        const storage = new StorageManager();
        await storage.put('meta', { id: STORAGE_KEYS.CSRF, value: response.csrf });
        await storage.put('meta', { id: STORAGE_KEYS.REG_NONCE, value: response.reg_nonce });
        this.log('[INFO] Session data stored successfully');
        
        // Step 1.3 - Update state and UI to show that session is initialized
        this.state.hasSession = true;
        this.updateState();
        this.setSuccess('initBtn', 'Session initialized!');
        this.log('[SUCCESS] Session initialized successfully', response);
        
    } catch (error) {
        this.setError('initBtn', 'Initialization failed');
        this.log('[ERROR] Session initialization failed:', error);
    }
}
```

### Step 1b: Browser Identity Key (BIK) Registration

**Objective**: Generate a non-exportable cryptographic key pair to establish browser identity.

**Implementation in `app.js`**:

The `registerBIK()` method contains TODO comments. Here's the complete implementation:

```javascript
async registerBIK() {
    this.setLoading('bikBtn', 'Registering BIK...');
    
    try {
        this.log('[INFO] Starting BIK registration...');
        
        // Step 1.4 - Generate ECDSA key pair with P-256 curve using Web Crypto API for BIK signing and verification
        this.log('[INFO] Generating EC key pair using Web Crypto API...');
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            false, // non-extractable - highly important as we should never expose key material
            ['sign', 'verify']
        );
        this.log('[INFO] Key pair generated successfully');
        
        // Step 1.5 - Store BIK keys in IndexedDB
        this.log('[INFO] Storing BIK keys in IndexedDB...');
        const storage = new StorageManager();
        // Export public key as JWK (JSON Web Key) for storage and transmission
        const exported = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
        const publicJwk = {
            kty: exported.kty,
            crv: exported.crv,
            x: exported.x,
            y: exported.y
        };
        await storage.put('keys', {
            id: STORAGE_KEYS.BIK_CURRENT,
            privateKey: keyPair.privateKey, // this is not the private key material but a reference to the key
            publicJwk: publicJwk
        });
        this.log('[INFO] BIK keys stored successfully');
        
        // Step 1.6 - Get stored nonce
        this.log('[INFO] Retrieving registration nonce from storage...');
        const nonceRecord = await storage.get('meta', STORAGE_KEYS.REG_NONCE);
        const nonce = nonceRecord.value;
        this.log('[INFO] Nonce retrieved', { nonce_length: nonce?.length || 0 });
        
        // Step 1.7 - Create BIK JWS with nonce and public key. There are 3 parts to a JWS: header, payload, and signature
        this.log('[INFO] Creating BIK JWS with nonce and public key...');
        
        const now = Math.floor(Date.now() / 1000);
        
        // BIK header with type, algorithm, and public key
        const header = {
            typ: 'bik-reg+jws',
            alg: 'ES256',
            jwk: publicJwk
        };
        
        // BIK payload with nonce and timestamp
        const payload = {
            nonce: nonce, // Registration nonce from server
            iat: now // Issued at timestamp
        };
        
        // Create the JWS by encoding header, payload, and signing
        const jws = await JWTUtils.createJWT(header, payload, keyPair.privateKey);
        this.log('[INFO] BIK JWS created successfully');
        
        // Step 1.8 - Send to /browser/register endpoint
        this.log('[INFO] Sending BIK registration to server...');
        const csrfRecord = await storage.get('meta', STORAGE_KEYS.CSRF);
        const response = await APIUtils.post('/browser/register', jws, {
            'X-CSRF-Token': csrfRecord.value // HTTP header
        });
        this.log('[INFO] Server verified BIK registration', { bik_jkt: response.bik_jkt });
        
        // Step 1.9 - Update state and UI
        this.state.hasBIK = true;
        this.updateState();
        this.setSuccess('bikBtn', 'BIK registered!');
        this.log('[SUCCESS] BIK registered successfully', response);
        
    } catch (error) {
        this.setError('bikBtn', 'BIK registration failed');
        this.log('[ERROR] BIK registration failed:', error);
    }
}
```

**Key Concepts**:
- **Web Crypto API**: Direct usage of `crypto.subtle.generateKey()` for key generation
- **JWK Format**: Exporting public keys as JSON Web Keys for storage and transmission
- **JWT Creation**: Manual JWT creation showing header, payload, and signature structure
- **Nonce Usage**: Registration nonce prevents replay attacks during BIK registration

### Step 2: DPoP Binding

**Objective**: Bind a DPoP key pair to the session for future API authentication.

**Implementation in `app.js`**:

The `bindDPoP()` method contains TODO comments. Here's the complete implementation:

```javascript
async bindDPoP() {
    this.setLoading('dpopBtn', 'Binding DPoP...');
    
    try {
        this.log('[INFO] Starting DPoP binding...');
        
        // Step 2.1 - Generate DPoP ECDSA key pair with P-256 curve using Web Crypto API for DPoP signing and verification
        this.log('[INFO] Generating DPoP key pair...');
        const dpopKeyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            false, // non-extractable - highly important as we should never expose key material
            ['sign', 'verify']
        );
        this.log('[INFO] DPoP key pair generated successfully');
        
        // Step 2.2 - Store DPoP keys
        this.log('[INFO] Storing DPoP keys in IndexedDB...');
        const storage = new StorageManager();
        // Export public key as JWK (JSON Web Key) for storage and transmission
        const exported = await crypto.subtle.exportKey('jwk', dpopKeyPair.publicKey);
        const publicJwk = {
            kty: exported.kty,
            crv: exported.crv,
            x: exported.x,
            y: exported.y
        };
        await storage.put('keys', {
            id: STORAGE_KEYS.DPoP_CURRENT,
            privateKey: dpopKeyPair.privateKey, // this is not the private key material but a reference to the key
            publicJwk: publicJwk
        });
        this.log('[INFO] DPoP keys stored successfully');
        
        // Step 2.3 - Create DPoP JWT with required claims
        this.log('[INFO] Creating DPoP proof JWT...');
        
        const now = Math.floor(Date.now() / 1000);
        const jti = CryptoUtils.generateJti(); // Generate unique JWT ID
        
        // DPoP header with type, algorithm, and public key
        const header = {
            typ: 'dpop+jwt',
            alg: 'ES256',
            jwk: publicJwk
        };
        
        // DPoP payload with HTTP method, URL, timestamp, and JWT ID
        const payload = {
            htm: 'POST', // HTTP method
            htu: URLUtils.getAPIURL('dpop/bind'), // HTTP target URI
            iat: now, // Issued at timestamp
            jti: jti // JWT ID (unique identifier)
        };
        
        // Create the JWT by encoding header, payload, and signing
        const dpopJwt = await JWTUtils.createJWT(header, payload, dpopKeyPair.privateKey);
        this.log('[INFO] DPoP proof JWT created successfully');
        
        // Step 2.4 - Send to /dpop/bind endpoint
        this.log('[INFO] Sending DPoP binding request to server...');
        const csrfRecord = await storage.get('meta', STORAGE_KEYS.CSRF);
        const response = await APIUtils.post('/dpop/bind', dpopJwt, {
            'X-CSRF-Token': csrfRecord.value // HTTP header
        });
        this.log('[INFO] Server verified DPoP binding', { 
            bind_token_length: response.bind?.length || 0,
            has_nonce: !!(response.headers && response.headers['DPoP-Nonce'])
        });
        
        // Step 2.5 - Store binding token and nonce
        this.log('[INFO] Storing DPoP binding data...');
        await storage.put('meta', { id: STORAGE_KEYS.BIND_TOKEN, value: response.bind });
        if (response.headers && response.headers['DPoP-Nonce']) {
            await storage.put('meta', { id: STORAGE_KEYS.DPoP_NONCE, value: response.headers['DPoP-Nonce'] });
            this.log('[INFO] DPoP nonce stored for future requests');
        }
        this.log('[INFO] DPoP binding data stored successfully');
        
        // Step 2.6 - Update state and UI
        this.state.hasDPoP = true;
        this.updateState();
        this.setSuccess('dpopBtn', 'DPoP bound!');
        this.log('[SUCCESS] DPoP bound successfully', response);
        
    } catch (error) {
        this.setError('dpopBtn', 'DPoP binding failed');
        this.log('[ERROR] DPoP binding failed:', error);
    }
}
```

**Key Concepts**:
- **DPoP Claims**: `htm` (HTTP method), `htu` (HTTP target URI), `iat` (issued at), `jti` (JWT ID)
- **Binding Token**: Server returns a binding token that links the DPoP key to the session
- **DPoP Nonce**: Optional nonce for replay protection in subsequent requests

### Step 3: API Testing with DPoP

**Objective**: Test the DPoP binding by making an authenticated API request.

**Implementation in `app.js`**:

The `testAPI()` method contains TODO comments. Here's the complete implementation:

```javascript
async testAPI() {
    this.setLoading('testBtn', 'Testing...');
    
    try {
        this.log('[INFO] Starting API test with DPoP...');
        
        // Step 3.1 - Get stored DPoP key and binding token
        this.log('[INFO] Retrieving DPoP keys and binding token from storage...');
        const storage = new StorageManager();
        const dpopRecord = await storage.get('keys', STORAGE_KEYS.DPoP_CURRENT);
        const bindRecord = await storage.get('meta', STORAGE_KEYS.BIND_TOKEN);
        const nonceRecord = await storage.get('meta', STORAGE_KEYS.DPoP_NONCE);
        
        if (!dpopRecord || !bindRecord) {
            throw new Error('DPoP keys or binding token not found');
        }
        this.log('[INFO] DPoP credentials retrieved successfully');
        
        // Step 3.2 - Create DPoP proof for API request
        this.log('[INFO] Creating DPoP proof for API request...');
        
        // Create DPoP proof JWT manually to show students the process
        const now = Math.floor(Date.now() / 1000);
        const jti = CryptoUtils.generateJti(); // Generate unique JWT ID
        
        // DPoP header with type, algorithm, and public key
        const header = {
            typ: 'dpop+jwt',
            alg: 'ES256',
            jwk: dpopRecord.publicJwk
        };
        
        // DPoP payload with HTTP method, URL, timestamp, JWT ID, and nonce (if available)
        const payload = {
            htm: 'POST', // HTTP method
            htu: URLUtils.getDPoPURI('api/test'), // HTTP target URI (server-side path, not client-side URL)
            iat: now, // Issued at timestamp
            jti: jti // JWT ID (unique identifier)
        };
        
        // Add nonce if available (for subsequent requests after initial binding)
        if (nonceRecord?.value) {
            payload.nonce = nonceRecord.value;
            this.log('[INFO] Added DPoP nonce to proof', { nonce_length: nonceRecord.value.length });
        }
        
        // Create the JWT by encoding header, payload, and signing
        const dpopProof = await JWTUtils.createJWT(header, payload, dpopRecord.privateKey);
        this.log('[INFO] DPoP proof created successfully');
        
        // Step 3.3 - Send request to /api/test endpoint
        this.log('[INFO] Sending API request with DPoP proof...');
        const response = await APIUtils.post('/api/test', {
            message: 'Hello from DPoP Lab!',
            timestamp: Date.now()
        }, {
            'DPoP': dpopProof, // HTTP header
            'DPoP-Bind': bindRecord.value // HTTP header
        });
        this.log('[INFO] Server verified DPoP proof and processed request', { 
            status: response.status || 'success',
            message: response.message 
        });
        
        this.setSuccess('testBtn', 'Test passed!');
        this.log('[SUCCESS] API test with DPoP successful', response);
        
    } catch (error) {
        this.setError('testBtn', 'Test failed');
        this.log('[ERROR] API test failed:', error);
    }
}
```

**Key Concepts**:
- **DPoP Header**: Contains the DPoP proof JWT
- **DPoP-Bind Header**: Contains the binding token from step 2
- **URLUtils.getDPoPURI()**: Returns full URL without proxy prefix for DPoP `htu` claims
- **Nonce Usage**: Optional nonce for replay protection in subsequent requests

### Step 4a: WebAuthn Passkey Registration

**Objective**: Register a WebAuthn passkey for biometric authentication.

**Implementation in `app.js`**:

The `registerPasskey()` method contains TODO comments. Here's the complete implementation:

```javascript
async registerPasskey() {
    this.setLoading('regBtn', 'Registering passkey...');
    
    try {
        this.log('[INFO] Starting passkey registration...');
        
        // Step 4.1 - Check WebAuthn support
        this.log('[INFO] Checking WebAuthn support...');
        if (!WebAuthnUtils.isSupported()) {
            throw new Error('WebAuthn not supported in this browser');
        }
        this.log('[INFO] WebAuthn is supported');
        
        // Step 4.2 - Get registration options from server
        this.log('[INFO] Requesting registration options from server...');
        const options = await APIUtils.post('/webauthn/registration/options');
        this.log('[INFO] Registration options received', { 
            challenge_length: options.challenge?.length || 0, // Cryptographic challenge from server (base64)
            rp_id: options.rpId, // Relying Party ID (domain name)
            user_verification: options.authenticatorSelection?.userVerification // Biometric/PIN requirement level
        });
        
        // Step 4.3 - Create credentials with navigator.credentials.create()
        this.log('[INFO] Creating WebAuthn credentials...');
                    
        // Convert base64 challenge to ArrayBuffer (required by WebAuthn API)
        const webauthnOptions = { ...options };
        if (webauthnOptions.challenge) {
            webauthnOptions.challenge = CryptoUtils.base64UrlToArrayBuffer(webauthnOptions.challenge);
            this.log('[INFO] Converted challenge to ArrayBuffer', { 
                original_length: options.challenge.length,
                buffer_size: webauthnOptions.challenge.byteLength 
            });
        }
        
        // Convert user.id from base64 to ArrayBuffer (required by WebAuthn API)
        if (webauthnOptions.user && webauthnOptions.user.id) {
            webauthnOptions.user.id = CryptoUtils.base64UrlToArrayBuffer(webauthnOptions.user.id);
            this.log('[INFO] Converted user ID to ArrayBuffer', { 
                original_length: options.user.id.length,
                buffer_size: webauthnOptions.user.id.byteLength 
            });
        }
        
        // Create the WebAuthn credential using the browser's native API
        this.log('[INFO] Calling navigator.credentials.create()...');
        const credential = await navigator.credentials.create({
            publicKey: webauthnOptions
        });
        
        this.log('[INFO] WebAuthn credentials created successfully', {
            credential_type: credential.type,
            credential_id_length: credential.id.byteLength
        });
        
        // Step 4.4 - Send attestation to server
        this.log('[INFO] Sending attestation to server for verification...');
        const attestation = WebAuthnUtils.credentialToJSON(credential);
        const response = await APIUtils.post('/webauthn/registration/verify', attestation);
        this.log('[INFO] Server verified attestation', { credential_id: response.credential_id });
        
        // Step 4.5 - Update state and UI
        this.state.hasPasskey = true;
        this.updateState();
        this.setSuccess('regBtn', 'Passkey registered!');
        this.log('[SUCCESS] Passkey registered successfully', response);
        
    } catch (error) {
        this.setError('regBtn', 'Passkey registration failed');
        this.log('[ERROR] Passkey registration failed:', error);
    }
}
```

**Key Concepts**:
- **ArrayBuffer Conversion**: WebAuthn API requires ArrayBuffer format for binary data
- **navigator.credentials.create()**: Triggers actual biometric/PIN challenge to user
- **Attestation**: Server verifies the credential creation and stores metadata

### Step 4b: WebAuthn Passkey Authentication

**Objective**: Authenticate using the registered WebAuthn passkey.

**Implementation in `app.js`**:

The `authenticatePasskey()` method contains TODO comments. Here's the complete implementation:

```javascript
async authenticatePasskey() {
    this.setLoading('authBtn', 'Authenticating...');
    
    try {
        this.log('[INFO] Starting passkey authentication...');
        
        // Step 4.6 - Get authentication options from server
        this.log('[INFO] Requesting authentication options from server...');
        const options = await APIUtils.post('/webauthn/authentication/options');
        this.log('[INFO] Authentication options received', { 
            challenge_length: options.challenge?.length || 0, // Cryptographic challenge from server (base64)
            rp_id: options.rpId, // Relying Party ID (domain name)
            allow_credentials_count: options.allowCredentials?.length || 0 // Number of allowed credential IDs
        });
        
        // Debug: Log the raw options to see what the server is actually sending
        this.log('[DEBUG] Raw authentication options from server:', options);
        
        // Step 4.7 - Get credentials with navigator.credentials.get()
        this.log('[INFO] Getting WebAuthn assertion...');
                    
        // Convert base64 challenge to ArrayBuffer (required by WebAuthn API)
        const webauthnOptions = { ...options };
                    
        if (webauthnOptions.challenge) {
            webauthnOptions.challenge = CryptoUtils.base64UrlToArrayBuffer(webauthnOptions.challenge);
            this.log('[INFO] Converted challenge to ArrayBuffer', { 
                original_length: options.challenge.length,
                buffer_size: webauthnOptions.challenge.byteLength 
            });
        }
        
        // Convert credential IDs from base64 to ArrayBuffer (required by WebAuthn API)
        if (webauthnOptions.allowCredentials) {
            // Log the raw credential data from server to show students the structure
            this.log('[INFO] Raw credentials from server:', webauthnOptions.allowCredentials);
            
            // Log each credential's properties for debug and demonstration purposes
            //Credentials are a server record of the passkey, they are not the passkey itself. credential -> challenge -> passkey -> signed message -> server -> verified!
            webauthnOptions.allowCredentials.forEach((cred, index) => {
                this.log(`[INFO] Credential ${index + 1} properties:`, {
                    type: cred.type, // Always 'public-key' for WebAuthn - identifies this as a WebAuthn credential (not a password or other auth method)
                    id: cred.id, // Base64 credential ID - unique identifier for this specific passkey, used to find the right credential during authentication
                    id_length: cred.id?.length || 0, // Base64 credential ID length - used to verify that the credential ID is the same as the one sent to the server
                    transports: cred.transports, // Array of transport methods - tells browser how to communicate with the authenticator: 'internal'=built-in sensor, 'usb'=USB security key, 'nfc'=near-field, 'ble'=Bluetooth
                    alg: cred.alg, // Algorithm identifier - cryptographic algorithm used: -7=ES256 (ECDSA with SHA-256), -257=RS256 (RSA with SHA-256), -37=PS256 (RSA-PSS with SHA-256)
                    userHandle: cred.userHandle, // Optional user identifier (base64) - links credential to specific user account, useful when multiple users share same device
                    signCount: cred.signCount, // Optional signature counter for replay protection - increases with each use, server checks it's higher than last seen value to prevent replay attacks
                    backupEligible: cred.backupEligible, // Whether credential can be backed up - true if passkey can be synced to other devices (iCloud Keychain, Google Password Manager, etc.)
                    backupState: cred.backupState, // Current backup status: 'not-backed-up'=only on this device, 'backed-up'=synced to cloud, 'backup-eligible'=can be backed up but hasn't been yet
                    clientExtensionResults: cred.clientExtensionResults // Any extension results - additional data from WebAuthn extensions, usually empty {} but can contain app-specific metadata
                });
            });
            
            webauthnOptions.allowCredentials = webauthnOptions.allowCredentials.map(cred => ({
                ...cred, // copy all existing credential properties (type, transports, alg, userHandle, etc.)
                id: CryptoUtils.base64UrlToArrayBuffer(cred.id) // Override the ID with converted ArrayBuffer
            }));
            this.log('[INFO] Converted credential IDs to ArrayBuffers', { 
                count: webauthnOptions.allowCredentials.length 
            });
        }
        
        // Get the WebAuthn assertion using the browser's native API - this will trigger the biometric challenge to the user
        this.log('[INFO] Calling navigator.credentials.get()...');
        this.log('[DEBUG] WebAuthn options being passed:', webauthnOptions);
        
        let assertion;
        try {
            assertion = await navigator.credentials.get({
                publicKey: webauthnOptions
            });
            
            this.log('[DEBUG] Raw assertion object received:', assertion);
            
            // Validate the assertion was created successfully
            if (!assertion) {
                throw new Error('No assertion received from WebAuthn API');
            }
            
            if (!assertion.id || !assertion.response?.signature) {
                throw new Error('Invalid assertion structure - missing required fields');
            }
            
            this.log('[INFO] WebAuthn assertion received successfully', {
                assertion_type: assertion.type, // Always 'public-key' - identifies this as a WebAuthn assertion
                credential_id_length: assertion.id.byteLength, // Length of credential ID in bytes
                has_signature: !!assertion.response?.signature, // Whether signature was created (in response object)
                has_authenticator_data: !!assertion.response?.authenticatorData, // Whether authenticator data is present (in response object)
                has_client_data: !!assertion.response?.clientDataJSON // Whether client data is present (in response object)
            });
            
        } catch (error) {
            this.log('[DEBUG] WebAuthn API error details:', {
                name: error.name,
                message: error.message,
                stack: error.stack
            });
            
            if (error.name === 'NotAllowedError') {
                throw new Error('User cancelled the biometric authentication or denied permission');
            } else if (error.name === 'SecurityError') {
                throw new Error('Security error during WebAuthn authentication - possible tampering detected');
            } else if (error.name === 'InvalidStateError') {
                throw new Error('WebAuthn operation failed - credential may be invalid or expired');
            } else {
                throw new Error(`WebAuthn authentication failed: ${error.message}`);
            }
        }
        
        // Step 4.8 - Send assertion to server
        this.log('[INFO] Sending assertion to server for verification...');
        const assertionData = WebAuthnUtils.credentialToJSON(assertion);
        const response = await APIUtils.post('/webauthn/authentication/verify', assertionData);
        this.log('[INFO] Server verified assertion', { user_id: response.user_id });
        
        this.setSuccess('authBtn', 'Authenticated!');
        this.log('[SUCCESS] Passkey authentication successful', response);
        
    } catch (error) {
        this.setError('authBtn', 'Authentication failed');
        this.log('[ERROR] Passkey authentication failed:', error);
    }
}
```

**Key Concepts**:
- **Credential Properties**: Detailed logging of all credential metadata from server
- **ArrayBuffer Conversion**: Converting base64 credential IDs to ArrayBuffer format
- **navigator.credentials.get()**: Triggers actual biometric/PIN challenge to user
- **Assertion Validation**: Checking that assertion contains required fields
- **Error Handling**: Specific handling for different WebAuthn error types

### Step 5: Cross-Device Linking with Internet Service Integration

**Objective**: Enable secure communication between devices for VDI and step-up authentication, with internet service integration for cross-device verification.

**Implementation in `app.js`**:

The `startLinking()` method contains TODO comments. Here's the complete implementation:

```javascript
async startLinking() {
    this.setLoading('linkBtn', 'Starting linking...');
    
    try {
        this.log('[INFO] Starting cross-device linking...');
        
        // Step 5.1 - Call /link/start endpoint
        this.log('[INFO] Requesting link initiation from server...');
        const response = await APIUtils.post('/link/start');
        this.log('[INFO] Link initiated', { 
            link_id: response.link_id,
            link_url_length: response.link_url?.length || 0,
            link_url: response.link_url
        });
        
        // Step 5.2 - Link initiated, waiting for mobile device to register
        // Mobile device scans QR and directly calls dpop.fun/reg-link/{link_id}
        
        // Step 5.3 - Generate QR code with internet service registration endpoint
        this.log('[INFO] Generating QR code for mobile device...');
        this.log('[DEBUG] InternetServiceUtils loaded:', typeof InternetServiceUtils);
        this.log('[DEBUG] InternetServiceUtils.BASE_URL:', InternetServiceUtils?.BASE_URL);
        this.log('[DEBUG] response.link_id:', response.link_id);
        
        // Force the correct BASE_URL if it's wrong
        const baseUrl = InternetServiceUtils?.BASE_URL || 'https://dpop.fun';
        this.log('[DEBUG] Using baseUrl:', baseUrl);
        
        const internetLinkUrl = `${baseUrl}/reg-link/${response.link_id}`;
        this.log('[DEBUG] Constructed internetLinkUrl:', internetLinkUrl);
        this.log('[DEBUG] Display text (response.link_url):', response.link_url);
        await QRCodeUtils.generateQRCode(internetLinkUrl, 'qrCode', 200, 'M', response.link_url);
        this.log('[INFO] QR code generated successfully with registration URL:', internetLinkUrl);
        this.log('[INFO] Display text shows local URL:', response.link_url);
        
        // Step 5.4 - Show QR container and manual completion button
        document.getElementById('qrContainer').style.display = 'block';
        document.getElementById('completeLinkBtn').style.display = 'inline-block';
        document.getElementById('completeLinkBtn').disabled = false;
        this.log('[INFO] QR code displayed for mobile scanning');
        
        // Step 5.5 - Start polling for link completion (both local and internet services)
        this.log('[INFO] Starting to poll for link completion...');
        this.currentLinkId = response.link_id; // Store for manual completion
        this.pollForLinkCompletion(response.link_id);
        
    } catch (error) {
        this.setError('linkBtn', 'Linking failed');
        this.log('[ERROR] Cross-device linking failed:', error);
    }
}
```

The `pollForLinkCompletion()` method contains TODO comments. Here's the complete implementation:

```javascript
async pollForLinkCompletion(linkId) {
    // Use the generic polling utility to check both local and internet services
    try {
        await PollingUtils.pollForCustomStatus(
            // Check both local and internet services
            async () => {
                // Check local service first
                try {
                    const localData = await APIUtils.get(`/link/status/${linkId}`);
                    if (localData.status === 'linked') {
                        this.log('[INFO] Link completed via local service!');
                        return { success: true, source: 'local', data: localData };
                    }
                } catch (localError) {
                    this.log('[WARN] Local service check failed:', localError);
                }
                
                // Check internet service
                try {
                    const internetData = await InternetServiceUtils.verifyLink(linkId);
                    if (internetData.found) {
                        this.log('[INFO] Link completed via internet service!');
                        return { success: true, source: 'internet', data: internetData };
                    }
                } catch (internetError) {
                    this.log('[WARN] Internet service check failed:', internetError);
                }
                
                // Neither service shows completion
                return { success: false };
            },
            (result) => result.success, // Check if either service shows completion
            {
                maxAttempts: 60, // 5 minutes max
                interval: 5000, // Check every 5 seconds
                onAttempt: (attempt, maxAttempts) => {
                    this.log(`[INFO] Checking link status (attempt ${attempt}/${maxAttempts})...`);
                },
                onSuccess: (result) => {
                    this.log(`[INFO] Link completed by mobile device via ${result.source} service!`);
                    this.state.isLinked = true;
                    this.updateState();
                    this.setSuccess('linkBtn', 'Device linked!');
                    this.log('[SUCCESS] Cross-device linking established', result.data);
                    
                    // Hide QR code and manual completion button
                    document.getElementById('qrContainer').style.display = 'none';
                    document.getElementById('completeLinkBtn').style.display = 'none';
                    this.log('[INFO] QR code and manual completion button hidden after successful linking');
                },
                onTimeout: () => {
                    this.log('[WARN] Link polling timed out after 5 minutes');
                    this.setError('linkBtn', 'Linking timed out');
                    document.getElementById('qrContainer').style.display = 'none';
                    document.getElementById('completeLinkBtn').style.display = 'none';
                },
                onError: (error, attempt, maxAttempts) => {
                    this.log('[ERROR] Link status check failed:', error);
                    if (attempt >= maxAttempts) {
                        this.setError('linkBtn', 'Linking failed');
                        document.getElementById('qrContainer').style.display = 'none';
                        document.getElementById('completeLinkBtn').style.display = 'none';
                    }
                }
            }
        );
    } catch (error) {
        // Polling utility handles most errors, but catch any unexpected ones
        this.log('[ERROR] Unexpected error during link polling:', error);
    }
}
```

The `completeLinkManually()` method contains TODO comments. Here's the complete implementation:

```javascript
async completeLinkManually() {
    if (!this.currentLinkId) {
        this.log('[ERROR] No active link to complete');
        return;
    }

    this.setLoading('completeLinkBtn', 'Completing...');
    
    try {
        this.log('[INFO] Manually completing link...');
        
        // Step 5.6 - Simulate mobile device completing the link
        const response = await APIUtils.post(`/link/complete/${this.currentLinkId}`, {
            device_type: 'mobile',
            user_agent: navigator.userAgent,
            timestamp: Date.now()
        });
        
        this.log('[INFO] Manual link completion successful', response);
        
        // The polling function will detect the completion and update the UI
        // But we can also update immediately for better UX
        this.state.isLinked = true;
        this.updateState();
        this.setSuccess('linkBtn', 'Device linked!');
        this.setSuccess('completeLinkBtn', 'Completed!');
        
        // Hide QR code and manual completion button
        document.getElementById('qrContainer').style.display = 'none';
        document.getElementById('completeLinkBtn').style.display = 'none';
        
        this.log('[SUCCESS] Manual link completion successful');
        
    } catch (error) {
        this.setError('completeLinkBtn', 'Completion failed');
        this.log('[ERROR] Manual link completion failed:', error);
    }
}
```

**Key Concepts**:
- **QR Code Generation**: Creates QR code pointing to internet service registration endpoint
- **Dual-Service Polling**: Checks both local and internet services for completion
- **PollingUtils**: Generic polling utility with configurable callbacks
- **Manual Completion**: Testing feature for development and demonstration

### Internet Service Integration

The lab now includes integration with an external internet service (`https://dpop.fun`) for enhanced cross-device linking:

**How it works**:
1. **Desktop**: Generates QR code pointing to `dpop.fun/reg-link/{link_id}`
2. **Mobile**: Scans QR code and directly registers with the internet service
3. **Desktop**: Polls both local service and internet service for completion
4. **Verification**: Link is established when either service reports completion

**Benefits**:
- **Cross-Domain**: Works across different networks and domains
- **Real-World**: Simulates actual production cross-device scenarios
- **Redundant**: Dual-service checking improves reliability
- **Scalable**: Internet service can handle multiple lab instances

## Available Utilities

The lab provides several utility classes in `utils.js`:

- **StorageManager**: IndexedDB operations for storing keys and metadata
- **CryptoUtils**: Web Crypto API operations for key generation and signing
- **JWTUtils**: JWT creation and verification
- **DPoPUtils**: DPoP proof creation and verification
- **WebAuthnUtils**: WebAuthn credential creation and authentication
- **QRCodeUtils**: QR code generation for device linking
- **APIUtils**: HTTP request utilities with CSRF support
- **URLUtils**: URL construction with proxy path handling
- **PollingUtils**: Generic polling utilities for status checking
- **InternetServiceUtils**: Integration with external internet service (dpop.fun)

## Testing Your Implementation

1. **Session Initialization**: Should create session and store CSRF token
2. **BIK Registration**: Should generate keys and register with server
3. **DPoP Binding**: Should create binding and store tokens
4. **API Testing**: Should make authenticated requests with DPoP proofs
5. **WebAuthn Registration**: Should create passkey and verify with server
6. **WebAuthn Authentication**: Should authenticate using passkey
7. **Cross-Device Linking**: Should generate QR code and establish connection via internet service
