from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "postgresql+psycopg://evedentia:evedentia@localhost:5432/evedentia"
    SECRET_KEY: str = "change-me"
    FERNET_KEY: str = ""
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"
    ALLOWED_EMAIL_DOMAIN: str = ""
    ADMIN_EMAILS: str = ""  # comma-separated
    FRONTEND_URL: str = "http://localhost:5173"
    PUBLIC_BASE_URL: str = "http://localhost:8000"
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "evedentia@localhost"
    IT_SECURITY_EMAIL: str = "security@localhost"
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_WHATSAPP_FROM: str = ""
    GMAIL_POLL_SECONDS: int = 60
    DISABLE_SCHEDULER: bool = False  # tests set this

    @property
    def admin_emails(self) -> list[str]:
        return [e.strip().lower() for e in self.ADMIN_EMAILS.split(",") if e.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
