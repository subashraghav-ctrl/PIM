#!/usr/bin/env python3
"""Generate a cryptographically secure random secret key."""
import secrets

key = secrets.token_urlsafe(48)
print(f"SECRET_KEY={key}")
print(f"\nCopy the value above into your .env file.")
