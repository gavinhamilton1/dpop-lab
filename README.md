# DPoP Hands-On Lab: Browser Identity & Security

## Learning Objectives

By the end of this 30-minute lab, participants will understand and implement:

1. **Session Initialization** - Establishing secure session with CSRF protection and registration nonces
2. **Browser Identity Key (BIK) Registration** - Creating non-exportable cryptographic keys using Web Crypto API
3. **DPoP (Demonstration of Proof-of-Possession) Binding** - Cryptographically binding browser identity to session tokens
4. **API Testing with DPoP** - Making authenticated API requests with cryptographic proofs
5. **WebAuthn/Passkey Integration** - Passwordless authentication with device biometrics
6. **Cross-Device Linking with Internet Service Integration** - Secure device-to-device communication across domains

## Prerequisites

- Basic JavaScript knowledge (ES6 modules, async/await)
- Understanding of web security concepts (CSRF, authentication, JWT)
- Modern browser (Chrome, Firefox, Safari, Edge) with WebAuthn support
- Code editor (VS Code recommended)
- Python 3.8+ for backend server

### Setup

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the server:**
   ```bash
   python3 server.py
   ```

3. **Open the lab:**
   - Navigate to the URL shown when you start the server
   - You should see the DPoP Lab interface with ES6 module support

## Lab Structure

### Part 1: Setup & Application (5 minutes)
- Clone the lab repository
- Install Python dependencies (`pip install -r requirements.txt`)
- Start the backend server (`python3 server.py`)
- Understand the project structure and ES6 module architecture

### Part 2: Core Implementation (20 minutes)
- **Step 1a**: Session initialization with CSRF token and registration nonce (3 min)
- **Step 1b**: Implement BIK registration using Web Crypto API (5 min)
- **Step 2**: Implement DPoP binding with JWT creation (5 min)
- **Step 3**: Test API with DPoP proofs (3 min)
- **Step 4a**: Add WebAuthn passkey registration (2 min)
- **Step 4b**: Implement WebAuthn passkey authentication (2 min)
- **Step 5**: Implement cross-device linking with internet service integration (5 min)

### Part 3: Testing & Validation (5 minutes)
- Test the complete flow end-to-end
- Verify security properties and cryptographic operations
- Discuss real-world applications and enterprise integration

## Key Concepts Covered

### Session Management & Security
- **What**: CSRF tokens and registration nonces for secure session establishment
- **Why**: Prevents cross-site request forgery and replay attacks during registration
- **How**: Server-generated tokens stored securely in IndexedDB

### Browser Identity Key (BIK)
- **What**: Non-exportable cryptographic key pair stored in browser using Web Crypto API
- **Why**: Establishes unique browser identity for security operations and prevents key extraction
- **How**: Direct Web Crypto API calls for ECDSA P-256 key generation and JWK export

### DPoP (Demonstration of Proof-of-Possession)
- **What**: Cryptographic proof that client possesses a specific key for each request
- **Why**: Prevents token theft, replay attacks, and ensures request authenticity
- **How**: Manual JWT creation with specific claims (htm, htu, iat, jti) and ES256 signatures

### WebAuthn/Passkeys
- **What**: Standard for passwordless authentication using device biometrics or security keys
- **Why**: Eliminates password vulnerabilities, provides strong authentication factors
- **How**: Public key cryptography with user verification, ArrayBuffer data handling

### Cross-Device Linking with Internet Service
- **What**: Secure communication between devices across different networks and domains
- **Why**: Enables VDI environments, step-up authentication, and cross-domain verification
- **How**: QR codes, dual-service polling (local + internet), and cryptographic verification

## Technical Stack

- **Frontend**: Vanilla JavaScript with ES6 modules, Web Crypto API, WebAuthn, IndexedDB
- **Backend**: FastAPI (Python), JWT verification, cryptographic operations with PyJWT and cryptography
- **Storage**: IndexedDB for client-side key storage and session management
- **Communication**: HTTP APIs with DPoP authentication, internet service integration (dpop.fun)
- **Architecture**: ES6 module system with proper separation of concerns

## Project Structure

```
dpop-lab/
├── README.md              # This file - lab overview and learning objectives
├── LAB_GUIDE.md          # Detailed step-by-step implementation guide
├── app/
│   ├── index.html        # Main lab interface with ES6 module support
│   ├── app.js            # Main application logic (student implementation)
│   ├── app-todo.js       # Template with TODO comments for students
│   ├── app-complete.js   # Complete solution for reference
│   ├── utils.js          # Utility classes (ES6 modules)
│   ├── server.py         # Backend API server with DPoP verification
│   └── requirements.txt  # Python dependencies (PyJWT, cryptography)
```

## Additional Resources

- [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [ES6 Modules](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules)

## Success Criteria

Participants will successfully:
- Initialize secure sessions with CSRF protection
- Generate and store browser identity keys using Web Crypto API
- Create DPoP proofs with proper JWT structure and claims
- Make authenticated API requests with cryptographic verification
- Implement passkey registration and authentication with WebAuthn
- Establish secure cross-device communication via internet service integration
- Understand the security benefits and real-world applications of each component

## Next Steps

After completing this lab, participants can:
- Apply these concepts to their own applications and enterprise systems
- Implement additional security controls (nonce challenges, token binding)
- Explore advanced DPoP features and enterprise identity integration
- Build upon the internet service integration for production cross-device scenarios
- Extend the WebAuthn implementation for multi-factor authentication
