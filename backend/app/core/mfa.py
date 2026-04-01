import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64

from app.config import settings


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def get_totp_uri(secret: str, username: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=settings.MFA_ISSUER_NAME)


def get_qr_code_base64(uri: str) -> str:
    """Returns base64-encoded PNG QR code for embedding in HTML/JSON."""
    img = qrcode.make(uri)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()
