#!/usr/bin/env python3
"""
DPoP Lab Server - Simplified FastAPI implementation
This server provides the backend API endpoints for the DPoP lab.
"""

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import secrets
import json
import base64
import time
import logging
import re
from typing import Dict, Any
import os
import jwt
from jwt.exceptions import InvalidTokenError
            
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title="DPoP Lab Server", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for lab purposes
sessions = {}
links = {}

# Configuration
BASE_DIR = os.path.dirname(__file__)

# Configuration - can be overridden by environment variables
PROXY_PREFIX = os.environ.get('PROXY_PREFIX', '/proxy/8000/')  # e.g., '/proxy/8000/'
HOST = os.environ.get('HOST', '0.0.0.0')
PORT = int(os.environ.get('PORT', 8000))
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

if PROXY_PREFIX:
    logger.info(f"Configured with proxy prefix: {PROXY_PREFIX}")

# Mount static files directory
app.mount("/static", StaticFiles(directory=BASE_DIR), name="static")



def generate_nonce() -> str:
    """Generate a random nonce for DPoP challenges."""
    return base64.urlsafe_b64encode(secrets.token_bytes(18)).decode('utf-8').rstrip('=')

def generate_session_id() -> str:
    """Generate a unique session ID."""
    return secrets.token_urlsafe(18)

def verify_dpop_proof(dpop_header: str, dpop_bind: str, http_method: str, http_uri: str) -> tuple[bool, dict]:
    """
    Verify a DPoP proof JWT.
    
    Args:
        dpop_header: The DPoP header value (JWT)
        dpop_bind: The DPoP-Bind header value (token hash)
        http_method: The HTTP method of the request
        http_uri: The HTTP URI of the request
    
    Returns:
        Tuple of (is_valid, decoded_payload)
    """
    try:
        # Remove 'DPoP ' prefix if present
        if dpop_header.startswith('DPoP '):
            dpop_header = dpop_header[6:]
        
        # Decode JWT header and payload (without verification first)
        import jwt
        from jwt.exceptions import InvalidTokenError
        
        # Parse JWT manually to get both header and payload
        parts = dpop_header.split('.')
        if len(parts) != 3:
            print(f"[ERROR] Invalid JWT format: expected 3 parts, got {len(parts)}")
            return False, {}
        
        # Decode header (first part)
        header_b64 = parts[0]
        header_padding = (4 - len(header_b64) % 4) % 4
        header_padded = header_b64 + '=' * header_padding
        header_json = base64.b64decode(header_padded).decode('utf-8')
        header = json.loads(header_json)
        
        # Decode payload (second part)
        payload_b64 = parts[1]
        payload_padding = (4 - len(payload_b64) % 4) % 4
        payload_padded = payload_b64 + '=' * payload_padding
        payload_json = base64.b64decode(payload_padded).decode('utf-8')
        payload = json.loads(payload_json)
        
        # Extract claims from header and payload
        typ = header.get("typ")  # typ is in header
        alg = header.get("alg")  # alg is in header
        htm = payload.get("htm")  # htm is in payload
        htu = payload.get("htu")  # htu is in payload
        iat = payload.get("iat")  # iat is in payload
        jti = payload.get("jti")  # jti is in payload
        nonce = payload.get("nonce")  # nonce is in payload
        
        # Verify required claims
        if typ != "dpop+jwt":
            print(f"[ERROR] Invalid DPoP type: {typ}")
            return False, {}
        
        if alg != "ES256":
            print(f"[ERROR] Unsupported algorithm: {alg}")
            return False, {}
        
        if htm != http_method:
            print(f"[ERROR] HTTP method mismatch: expected {http_method}, got {htm}")
            return False, {}
        
        # Verify HTTP URI (should match the request URI)
        if htu != http_uri:
            print(f"[ERROR] HTTP URI mismatch: expected {http_uri}, got {htu}")
            return False, {}
        
        # Verify timestamp (not too old, not in future)
        current_time = int(time.time())
        if iat and (current_time - iat > 300):  # 5 minutes max age
            print(f"[ERROR] DPoP proof too old: {current_time - iat} seconds")
            return False, {}
        
        if iat and iat > current_time + 60:  # 1 minute future tolerance
            print(f"[ERROR] DPoP proof timestamp in future: {iat - current_time} seconds")
            return False, {}
        
        # Additional validation: check if this matches the binding claims
        # In a real implementation, you would also:
        # 1. Extract the public key from the DPoP-Bind token
        # 2. Verify the JWT signature using that public key
        # 3. Verify the DPoP-Bind token hash matches the JWT
        
        # Step 1: Extract the public key from the DPoP-Bind token
        if not dpop_bind or not dpop_bind.startswith('bind_'):
            print(f"[ERROR] Invalid DPoP-Bind token format: {dpop_bind}")
            return False, {}
        
        # Find the session that has this binding token
        session_found = None
        for session_id, session_data in sessions.items():
            if session_data.get("dpop_bind") == dpop_bind:
                session_found = session_data
                break
        
        if not session_found:
            print(f"[ERROR] DPoP-Bind token not found in any session: {dpop_bind}")
            return False, {}
        
        # Extract the stored DPoP public key from the session
        dpop_jwk = session_found.get("dpop_jwk")
        if not dpop_jwk:
            print(f"[ERROR] No DPoP public key found in session for binding: {dpop_bind}")
            return False, {}
        
        # Step 2: Verify the JWT signature using the stored public key
        try:
            # Convert JWK to PEM format for PyJWT verification
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            import hashlib
            
            # Extract coordinates from JWK
            x_coord = base64.urlsafe_b64decode(dpop_jwk["x"] + "==")
            y_coord = base64.urlsafe_b64decode(dpop_jwk["y"] + "==")
            
            # Create public key from coordinates
            public_numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x_coord, 'big'),
                int.from_bytes(y_coord, 'big'),
                ec.SECP256R1()
            )
            public_key = public_numbers.public_key()
            
            # Convert to PEM format
            pem_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Verify the JWT signature
            verified_payload = jwt.decode(
                dpop_header, 
                pem_public_key, 
                algorithms=["ES256"],
                options={"verify_signature": True}
            )
            
            print(f"[INFO] JWT signature verified successfully using stored public key")
            
        except Exception as e:
            print(f"[ERROR] JWT signature verification failed: {str(e)}")
            return False, {}
        
        # Step 3: Verify the DPoP-Bind token matches the stored binding JWT
        try:
            # Get the stored binding JWT from the session
            stored_binding_jwt = session_found.get("dpop_binding_jwt")
            if not stored_binding_jwt:
                print(f"[ERROR] No stored binding JWT found in session")
                return False, {}
            
            # Create the expected hash from the stored binding JWT
            stored_parts = stored_binding_jwt.split('.')
            if len(stored_parts) != 3:
                print(f"[ERROR] Invalid stored binding JWT format")
                return False, {}
            
            stored_header_payload = f"{stored_parts[0]}.{stored_parts[1]}"
            expected_hash = hashlib.sha256(stored_header_payload.encode('utf-8')).hexdigest()
            expected_bind_token = f"bind_{expected_hash}"
            
            if dpop_bind != expected_bind_token:
                print(f"[ERROR] DPoP-Bind token mismatch:")
                print(f"  Expected: {expected_bind_token}")
                print(f"  Received: {dpop_bind}")
                print(f"  From stored binding JWT hash: {expected_hash}")
                return False, {}
            
            print(f"[INFO] DPoP-Bind token verified successfully against stored binding JWT")
            
        except Exception as e:
            print(f"[ERROR] DPoP-Bind token verification failed: {str(e)}")
            return False, {}
        
        print(f"[INFO] DPoP proof validation successful")
        print(f"[DEBUG] DPoP claims: typ={typ}, alg={alg}, htm={htm}, htu={htu}, iat={iat}, jti={jti}")
        print(f"[DEBUG] DPoP signature verified with public key from session")
        print(f"[DEBUG] DPoP-Bind token hash verified")
        
        return True, payload
        
    except InvalidTokenError as e:
        print(f"[ERROR] Invalid JWT format: {str(e)}")
        return False, {}
    except Exception as e:
        print(f"[ERROR] DPoP verification error: {str(e)}")
        return False, {}

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main lab page."""
    with open(os.path.join(BASE_DIR, "index.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/config")
async def get_config():
    """Get server configuration including proxy prefix."""
    return {
        "proxy_prefix": PROXY_PREFIX,
        "base_url": "/",
        "static_url": "/static/"
    }



# ============================================================================
# Session Management Endpoints
# ============================================================================

@app.post("/session/init")
async def session_init(request: Request):
    """
    Initialize a new session.
    Returns CSRF token and registration nonce.
    """
    try:
        body = await request.json()
        browser_uuid = body.get("browser_uuid", "unknown")
        
        # Generate session data
        session_id = generate_session_id()
        csrf_token = secrets.token_urlsafe(18)
        reg_nonce = generate_nonce()
        
        # Store session
        sessions[session_id] = {
            "state": "pending-bind",
            "csrf": csrf_token,
            "reg_nonce": reg_nonce,
            "browser_uuid": browser_uuid,
            "created_at": time.time()
        }
        
        # Set session cookie
        response = JSONResponse({
            "csrf": csrf_token,
            "reg_nonce": reg_nonce,
            "state": "pending-bind"
        })
        response.set_cookie("session_id", session_id, httponly=True, secure=False)
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Session initialization failed: {str(e)}")

@app.get("/session/status")
async def session_status(request: Request):
    """
    Get current session status.
    """
    session_id = request.cookies.get("session_id")
    
    if not session_id or session_id not in sessions:
        return {
            "valid": False,
            "state": None,
            "bik_registered": False,
            "dpop_bound": False
        }
    
    session = sessions[session_id]
    state = session.get("state")
    bik_registered = bool(session.get("bik_jkt"))
    dpop_bound = bool(session.get("dpop_jkt"))
    
    return {
        "valid": True,
        "state": state,
        "bik_registered": bik_registered,
        "dpop_bound": dpop_bound
    }

# ============================================================================
# Browser Identity Key (BIK) Registration
# ============================================================================

@app.post("/browser/register")
async def browser_register(request: Request):
    """
    Register a browser identity key.
    Expects a JWS with the public key and nonce verification.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        csrf_token = request.headers.get("X-CSRF-Token")
        
        if csrf_token != session.get("csrf"):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
        
        # Get the JWS from request body
        jws_compact = (await request.body()).decode()
        
        # TODO: Implement JWS verification
        # For lab purposes, we'll accept any JWS and extract a mock thumbprint
        
        # Mock implementation - in real implementation, verify the JWS
        bik_jkt = f"bik_{secrets.token_hex(8)}"
        
        # Update session
        session["bik_jkt"] = bik_jkt
        session["state"] = "bound-bik"
        session["reg_nonce"] = None
        
        return {
            "bik_jkt": bik_jkt,
            "state": "bound-bik"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"BIK registration failed: {str(e)}")

# ============================================================================
# DPoP Binding
# ============================================================================

@app.post("/dpop/bind")
async def dpop_bind(request: Request):
    """
    Bind DPoP key to session.
    Expects a DPoP JWS with the public key.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        csrf_token = request.headers.get("X-CSRF-Token")
        
        if csrf_token != session.get("csrf"):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
        
        if session.get("state") != "bound-bik":
            raise HTTPException(status_code=403, detail="BIK not bound")
        
        # Get the DPoP JWT from request body
        dpop_jwt = (await request.body()).decode()
        print(f"[DEBUG] Received DPoP JWT: {dpop_jwt[:100]}...")  # Log first 100 chars
        
        # Verify and extract DPoP JWT
        try:
            print(f"[DEBUG] Attempting to decode DPoP JWT...")
            
            # Decode the JWT header and payload separately

            
            # Split the JWT into parts
            parts = dpop_jwt.split('.')
            if len(parts) != 3:
                raise HTTPException(status_code=400, detail="Invalid JWT format: not 3 parts")
            
            # Decode header (first part)
            header_b64 = parts[0]
            header_padding = (4 - len(header_b64) % 4) % 4
            header_padded = header_b64 + '=' * header_padding
            header_json = base64.b64decode(header_padded).decode('utf-8')
            header = json.loads(header_json)
            print(f"[DEBUG] JWT header: {header}")
            
            # Decode payload (second part)
            payload_b64 = parts[1]
            payload_padding = (4 - len(payload_b64) % 4) % 4
            payload_padded = payload_b64 + '=' * payload_padding
            payload_json = base64.b64decode(payload_padded).decode('utf-8')
            payload = json.loads(payload_json)
            print(f"[DEBUG] JWT payload: {payload}")
            
            # Extract claims from header and payload
            typ = header.get("typ")
            alg = header.get("alg")
            htm = payload.get("htm")
            htu = payload.get("htu")
            iat = payload.get("iat")
            jti = payload.get("jti")
            
            print(f"[DEBUG] Extracted claims: typ={typ}, alg={alg}, htm={htm}, htu={htu}, iat={iat}, jti={jti}")
            
            if typ != "dpop+jwt":
                print(f"[ERROR] Invalid DPoP type: {typ}")
                raise HTTPException(status_code=400, detail="Invalid DPoP type")
            
            if alg != "ES256":
                print(f"[ERROR] Unsupported algorithm: {alg}")
                raise HTTPException(status_code=400, detail="Unsupported algorithm")
            
            if htm != "POST":
                print(f"[ERROR] Invalid HTTP method: expected POST, got {htm}")
                raise HTTPException(status_code=400, detail="Invalid HTTP method")
            
            print(f"[DEBUG] All DPoP claims validated successfully")
            
            # Extract public key from JWT header (JWK)
            dpop_jwk = header.get("jwk")
            if not dpop_jwk:
                print(f"[ERROR] No JWK found in DPoP JWT header")
                raise HTTPException(status_code=400, detail="No JWK in DPoP JWT")
            
            # Validate JWK structure
            if not all(key in dpop_jwk for key in ["kty", "crv", "x", "y"]):
                print(f"[ERROR] Invalid JWK structure: missing required fields")
                raise HTTPException(status_code=400, detail="Invalid JWK structure")
            
            if dpop_jwk["kty"] != "EC" or dpop_jwk["crv"] != "P-256":
                print(f"[ERROR] Unsupported key type: {dpop_jwk['kty']}, curve: {dpop_jwk['crv']}")
                raise HTTPException(status_code=400, detail="Unsupported key type or curve")
            
            # Store DPoP claims, JWK, and the original binding JWT for future verification
            session["dpop_claims"] = {
                "typ": typ,
                "alg": alg,
                "htm": htm,
                "htu": htu,
                "iat": iat,
                "jti": jti
            }
            session["dpop_jwk"] = dpop_jwk
            session["dpop_binding_jwt"] = dpop_jwt  # Store the original JWT used for binding
            
            print(f"[INFO] DPoP binding successful for session {session_id[:8]}")
            print(f"[DEBUG] DPoP claims: {session['dpop_claims']}")
            print(f"[DEBUG] DPoP JWK stored: {dpop_jwk['kty']}, {dpop_jwk['crv']}")
            
        except Exception as e:
            print(f"[ERROR] DPoP verification failed: {str(e)}")
            print(f"[ERROR] Exception type: {type(e).__name__}")
            import traceback
            print(f"[ERROR] Traceback: {traceback.format_exc()}")
            raise HTTPException(status_code=400, detail=f"DPoP verification failed: {str(e)}")
        
        # Generate binding token based on JWT hash
        import hashlib
        header_payload = f"{parts[0]}.{parts[1]}"
        bind_hash = hashlib.sha256(header_payload.encode('utf-8')).hexdigest()
        bind_token = f"bind_{bind_hash}"
        next_nonce = generate_nonce()
        
        print(f"[DEBUG] Generated binding token: {bind_token}")
        print(f"[DEBUG] From JWT hash: {bind_hash}")
        print(f"[DEBUG] JWT header+payload: {header_payload[:100]}...")
        
        # Update session
        session["dpop_bind"] = bind_token  # Store for lookup in verification
        session["state"] = "bound"
        session["current_nonce"] = next_nonce
        
        # Return response with binding token and nonce
        response = JSONResponse({
            "bind": bind_token,
            "expires_at": int(time.time()) + 3600  # 1 hour
        })
        response.headers["DPoP-Nonce"] = next_nonce
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"DPoP binding failed: {str(e)}")

# ============================================================================
# WebAuthn Passkey Support
# ============================================================================

@app.post("/webauthn/registration/options")
async def webauthn_registration_options(request: Request):
    """
    Get WebAuthn registration options.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Generate registration options
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Get the actual domain from the request
        host = request.headers.get("host", "localhost")
        # Extract just the domain part (remove port if present)
        rp_id = host.split(":")[0]
        
        options = {
            "challenge": challenge,
            "rpId": rp_id,  # WebAuthn expects flat rpId property, not nested rp object
            "rp": {
                "name": "DPoP Lab"
            },
            "user": {
                "id": base64.urlsafe_b64encode(session_id.encode()).decode('utf-8').rstrip('='),
                "name": f"user_{session_id[:8]}",
                "displayName": f"DPoP Lab User {session_id[:8]}"
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -257}  # RS256
            ],
            "timeout": 60000,
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "userVerification": "preferred"
            }
        }
        
        # Store challenge for verification
        session["webauthn_challenge"] = challenge
        
        return options
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate registration options: {str(e)}")

@app.post("/webauthn/registration/verify")
async def webauthn_registration_verify(request: Request):
    """
    Verify WebAuthn registration.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Get attestation from request body
        attestation = await request.json()
        print(f"Received attestation: {attestation}")  # Debug log
        
        # TODO: Implement attestation verification
        # For lab purposes, we'll accept any attestation
        
        # Extract credential ID from the attestation
        # In a real implementation, you would verify the attestation here
        credential_id = attestation.get("id")
        if not credential_id:
            # Fallback to mock ID if not provided
            credential_id = f"cred_{secrets.token_hex(16)}"
        
        # Store credential info
        session["webauthn_credentials"] = session.get("webauthn_credentials", [])
        session["webauthn_credentials"].append({
            "id": credential_id,
            "type": "public-key",
            "transports": ["internal"]
        })
        
        # Debug logging
        print(f"[DEBUG] Stored credential in session: {credential_id}")
        print(f"[DEBUG] Session now has {len(session['webauthn_credentials'])} credentials")
        print(f"[DEBUG] Full session: {session}")
        
        return {"verified": True, "credential_id": credential_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration verification failed: {str(e)}")

@app.post("/webauthn/authentication/options")
async def webauthn_authentication_options(request: Request):
    """
    Get WebAuthn authentication options.
    """
    try:
        session_id = request.cookies.get("session_id")
        print(f"[DEBUG] Authentication options request - session_id: {session_id}")
        print(f"[DEBUG] Available sessions: {list(sessions.keys())}")
        
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        print(f"[DEBUG] Found session: {session}")
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Generate authentication options
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Get the actual domain from the request
        host = request.headers.get("host", "localhost")
        # Extract just the domain part (remove port if present)
        rp_id = host.split(":")[0]
        
        options = {
            "challenge": challenge,
            "rpId": rp_id,
            "timeout": 60000,
            "userVerification": "preferred"
        }
        
        # Add allowed credentials if available
        credentials = session.get("webauthn_credentials", [])
        print(f"Available credentials: {credentials}")  # Debug log
        if credentials:
            options["allowCredentials"] = [
                {
                    "id": cred["id"],  # Keep as base64 string, will be converted to ArrayBuffer by client
                    "type": cred["type"],
                    "transports": cred.get("transports", [])
                }
                for cred in credentials
            ]
        
        # Store challenge for verification
        session["webauthn_challenge"] = challenge
        
        # Debug logging
        print(f"[DEBUG] Generated authentication options: {options}")
        print(f"[DEBUG] Session credentials: {session.get('webauthn_credentials', [])}")
        print(f"[DEBUG] Session state: {session.get('state')}")
        
        return options
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate authentication options: {str(e)}")

@app.post("/webauthn/authentication/verify")
async def webauthn_authentication_verify(request: Request):
    """
    Verify WebAuthn authentication.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Get assertion from request body
        assertion = await request.json()
        
        # TODO: Implement assertion verification
        # For lab purposes, we'll accept any assertion
        
        # Mock implementation - in real implementation, verify the assertion
        return {"verified": True, "user_id": session_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Authentication verification failed: {str(e)}")

# ============================================================================
# Cross-Device Linking
# ============================================================================

@app.post("/link/start")
async def link_start(request: Request):
    """
    Start cross-device linking process.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Generate link ID
        link_id = secrets.token_urlsafe(16)
        
        # Store link information
        links[link_id] = {
            "session_id": session_id,
            "status": "pending",
            "created_at": time.time(),
            "device_info": {}
        }
        
        # Generate linking URL with proxy path support
        # The client is calling this endpoint through APIUtils which handles proxy paths
        # So we need to construct the link URL to match the client's proxy path
        
        # Get the current page's origin and path to construct the correct link URL
        from urllib.parse import urlparse
        current_url = str(request.url)
        parsed_url = urlparse(current_url)
        
        # Extract the proxy path from the current request URL
        proxy_path = ""
        if '/proxy/' in parsed_url.path:
            proxy_match = re.match(r'^(\/proxy\/\d+\/)', parsed_url.path)
            if proxy_match:
                proxy_path = proxy_match.group(1)
        elif '/lab/' in parsed_url.path:
            lab_match = re.match(r'^(\/lab\/)', parsed_url.path)
            if lab_match:
                proxy_path = lab_match.group(1)
        
        # Construct the link URL
        if proxy_path:
            # We're behind a proxy, construct URL with proxy path
            link_url = f"{parsed_url.scheme}://{parsed_url.netloc}{proxy_path}link/{link_id}"
        else:
            # No proxy, use standard URL
            link_url = f"{parsed_url.scheme}://{parsed_url.netloc}/link/{link_id}"
        
        logger.info(f"Linking: request.url = {current_url}")
        logger.info(f"Linking: parsed path = {parsed_url.path}")
        logger.info(f"Linking: detected proxy_path = {proxy_path}")
        logger.info(f"Linking: generated link_url = {link_url}")
        
        return {
            "link_id": link_id,
            "link_url": link_url,
            "status": "pending"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to start linking: {str(e)}")

@app.get("/link/{link_id}")
async def link_page(link_id: str):
    """
    Serve the mobile linking page.
    """
    # For lab purposes, return a simple HTML page
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DPoP Lab - Device Linking</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; padding: 20px; text-align: center; }}
            .status {{ margin: 20px; padding: 10px; border-radius: 5px; }}
            .pending {{ background: #fff3cd; color: #856404; }}
            .linked {{ background: #d4edda; color: #155724; }}
            .completing {{ background: #cce5ff; color: #004085; }}
            button {{ 
                background: #007bff; 
                color: white; 
                border: none; 
                padding: 10px 20px; 
                border-radius: 5px; 
                cursor: pointer; 
                margin: 10px;
            }}
            button:hover {{ background: #0056b3; }}
            button:disabled {{ background: #6c757d; cursor: not-allowed; }}
        </style>
    </head>
    <body>
        <h1>🔗 DPoP Lab - Device Linking</h1>
        <p>Link ID: <code>{link_id}</code></p>
        <div id="status" class="status pending">
            <p>Connecting to desktop device...</p>
            <p>Click the button below to complete the link when ready.</p>
        </div>
        <button onclick="completeLink()" id="completeBtn">Complete Link</button>
        <script>
            async function registerWithInternetService() {{
                try {{
                    // Register this link ID with the internet service (dpop.fun)
                    const response = await fetch('https://dpop.fun/reg-link/{link_id}', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{
                            link_id: '{link_id}',
                            timestamp: Date.now(),
                            source: 'mobile_page'
                        }})
                    }});
                    
                    if (response.ok) {{
                        console.log('Successfully registered with internet service');
                    }} else {{
                        console.warn('Failed to register with internet service, continuing with local only');
                    }}
                }} catch (error) {{
                    console.warn('Could not register with internet service, continuing with local only:', error);
                }}
            }}
            
            async function completeLink() {{
                const statusDiv = document.getElementById('status');
                
                try {{
                    statusDiv.className = 'status completing';
                    statusDiv.innerHTML = '<p>Completing link...</p>';
                    
                    // Send device info to complete the link
                    // Detect proxy path dynamically
                    let proxyPath = '';
                    const pathname = window.location.pathname;
                    if (pathname.includes('/proxy/')) {{
                        const proxyMatch = pathname.match(/^(\/proxy\/\d+\/)/);
                        if (proxyMatch) {{
                            proxyPath = proxyMatch[1];
                        }}
                    }} else if (pathname.includes('/lab/')) {{
                        const labMatch = pathname.match(/^(\/lab\/)/);
                        if (labMatch) {{
                            proxyPath = labMatch[1];
                        }}
                    }}
                    
                    const completeUrl = proxyPath ? `${{proxyPath}}link/complete/{link_id}` : `/link/complete/{link_id}`;
                    const response = await fetch(completeUrl, {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{
                            device_type: 'mobile',
                            user_agent: navigator.userAgent,
                            timestamp: Date.now(),
                            device_info: {{
                                platform: navigator.platform,
                                language: navigator.language,
                                screen_width: screen.width,
                                screen_height: screen.height
                            }}
                        }})
                    }});
                    
                    if (response.ok) {{
                        statusDiv.className = 'status linked';
                        statusDiv.innerHTML = '<p>✅ Successfully linked to desktop device!</p>';
                    }} else {{
                        throw new Error('Link completion failed');
                    }}
                }} catch (error) {{
                    console.error('Link completion failed:', error);
                    statusDiv.className = 'status pending';
                    statusDiv.innerHTML = '<p>Link completion failed. Please refresh the page to try again.</p>';
                }}
            }}
            
            // Register with internet service when page loads
            registerWithInternetService();
            
            // Note: Link completion is now manual - no auto-complete
            // The mobile device should explicitly complete the link when ready
        </script>
    </body>
    </html>
    """
    return HTMLResponse(html)

@app.get("/link/status/{link_id}")
async def link_status(link_id: str):
    """
    Get linking status.
    """
    if link_id not in links:
        raise HTTPException(status_code=404, detail="Link not found")
    
    link_info = links[link_id]
    return {
        "link_id": link_id,
        "status": link_info["status"],
        "device_info": link_info.get("device_info", {})
    }

@app.post("/link/complete/{link_id}")
async def link_complete(link_id: str, request: Request):
    """
    Complete the linking process.
    """
    try:
        if link_id not in links:
            raise HTTPException(status_code=404, detail="Link not found")
        
        link_info = links[link_id]
        device_info = await request.json()
        
        # Update link status
        link_info["status"] = "linked"
        link_info["device_info"] = device_info
        link_info["linked_at"] = time.time()
        
        return {"status": "linked", "link_id": link_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to complete linking: {str(e)}")

# ============================================================================
# API Testing
# ============================================================================

@app.post("/api/test")
async def api_test(request: Request):
    """
    Test API endpoint that requires DPoP authentication.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Check for DPoP header
        dpop_header = request.headers.get("DPoP")
        print(f"[DEBUG] API test - DPoP header: {dpop_header}")
        if not dpop_header:
            raise HTTPException(status_code=401, detail="Missing DPoP header")
        
        # Check for DPoP-Bind header
        dpop_bind = request.headers.get("DPoP-Bind")
        print(f"[DEBUG] API test - DPoP-Bind header: {dpop_bind}")
        if not dpop_bind:
            raise HTTPException(status_code=400, detail="Missing DPoP-Bind header")
        
        # Log all headers for debugging
        print(f"[DEBUG] API test - All headers: {dict(request.headers)}")
        
        # Verify DPoP proof JWT
        try:
            # Decode and verify the DPoP JWT
            dpop_verified, dpop_data = verify_dpop_proof(dpop_header, dpop_bind, request.method, str(request.url))
            
            if not dpop_verified:
                raise HTTPException(status_code=401, detail="Invalid DPoP proof")
            
            # Check if this is a replay attack (verify nonce if available)
            if dpop_data.get("jti"):
                jti = dpop_data["jti"]
                if jti in session.get("used_jtis", set()):
                    raise HTTPException(status_code=401, detail="DPoP proof already used (replay attack)")
                
                # Store used JTI to prevent replay
                if "used_jtis" not in session:
                    session["used_jtis"] = set()
                session["used_jtis"].add(jti)
            
            # Log successful DPoP verification
            print(f"[INFO] DPoP proof verified successfully for session {session_id[:8]}")
            print(f"[DEBUG] DPoP data: {dpop_data}")
            
        except Exception as e:
            print(f"[ERROR] DPoP verification failed: {str(e)}")
            raise HTTPException(status_code=401, detail=f"DPoP verification failed: {str(e)}")
        
        # Get request body
        body = await request.json()
        message = body.get("message", "No message provided")
        
        return {
            "success": True,
            "message": f"API test successful! Received: {message}",
            "timestamp": time.time(),
            "session_id": session_id[:8],
            "dpop_verified": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"API test failed: {str(e)}")

# ============================================================================
# Admin Endpoints
# ============================================================================

@app.post("/admin/flush")
async def admin_flush():
    """
    Flush all server state (for testing).
    """
    global sessions, links
    sessions.clear()
    links.clear()
    return {"message": "Server state flushed successfully"}

if __name__ == "__main__":
    import uvicorn
    import socket
    
    # Get local IP address
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print("🚀 Starting DPoP Lab Server...")
    if PROXY_PREFIX:
        print(f"🔧 Configured with proxy prefix: {PROXY_PREFIX}")
        print(f"📖 Access via proxy at: {PROXY_PREFIX}")
        print(f"🔧 Server will handle routes with prefix: {PROXY_PREFIX}")
    else:
        print(f"📖 Open http://localhost:{PORT} or http://{local_ip}:{PORT} to access the lab")
    print(f"🔧 API documentation: http://localhost:{PORT}/docs")
    
    uvicorn.run(app, host=HOST, port=PORT, reload=False)
