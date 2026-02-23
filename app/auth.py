import requests
from functools import wraps
from flask import request, jsonify
from jose import jwt

OIDC_ISSUER = "http://localhost:8080/realms/health"
JWKS_URL = f"{OIDC_ISSUER}/protocol/openid-connect/certs"
AUDIENCE = "account"

jwks = requests.get(JWKS_URL).json()

def verify_and_decode(token):
    try:
        return jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=OIDC_ISSUER
        )
    except Exception:
        return None


def require_role(required_roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization", None)
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing token"}), 401

            token = auth_header.split()[1]
            claims = verify_and_decode(token)
            print("Decoded claims:", claims)

            if not claims:
                return jsonify({"error": "Invalid token"}), 401

            user_roles = claims.get("realm_access", {}).get("roles", [])
            print("Roles in token:", user_roles)

            # Normalize required_roles to always be a list
            if isinstance(required_roles, str):
                required_roles_list = [required_roles]
            else:
                required_roles_list = required_roles

            # Check if user has at least one required role
            if not any(r in user_roles for r in required_roles_list):
                return jsonify({"error": "Forbidden"}), 403

            return fn(*args, **kwargs)
        return decorated
    return wrapper