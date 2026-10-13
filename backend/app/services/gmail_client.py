from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from app.config import get_settings
from app.models import User
from app.services.crypto import decrypt

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def build_gmail_service(user: User):
    """Read-only Gmail client; the access token is fetched/refreshed automatically."""
    if not user.gmail_refresh_token_enc:
        raise ValueError("gmail not connected")
    s = get_settings()
    creds = Credentials(
        token=None,
        refresh_token=decrypt(user.gmail_refresh_token_enc),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=s.GOOGLE_CLIENT_ID,
        client_secret=s.GOOGLE_CLIENT_SECRET,
        scopes=[GMAIL_SCOPE],
    )
    return build("gmail", "v1", credentials=creds, cache_discovery=False)
