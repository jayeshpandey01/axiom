from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", ".env.local"), extra="ignore")

    app_env: str = "development"
    database_url: str = "sqlite:///./scan_tool.db"
    auth_mode: str = "api_key"
    api_key: str = "development-only-change-me"
    admin_api_key: str = "development-only-change-me-admin"
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_role_claim: str = "roles"
    rate_limit_redis_url: str | None = None
    rate_limit_requests_per_minute: int = 60
    result_storage_bucket: str | None = None
    result_storage_region: str = "ap-south-1"
    result_storage_endpoint_url: str | None = None
    result_storage_kms_key_id: str | None = None
    result_encryption_key: str | None = None
    result_retention_days: int = 30
    controller_shared_secret: str = "development-only-change-me"
    max_targets_per_scan: int = 10
    log_level: str = "INFO"

    def validate_production(self) -> None:
        if self.app_env.lower() != "production":
            return
        if self.auth_mode != "oidc":
            raise RuntimeError("production requires AUTH_MODE=oidc")
        if not all([self.oidc_issuer, self.oidc_audience, self.oidc_jwks_url]):
            raise RuntimeError("production requires OIDC_ISSUER, OIDC_AUDIENCE, and OIDC_JWKS_URL")
        if not self.rate_limit_redis_url:
            raise RuntimeError("production requires RATE_LIMIT_REDIS_URL")
        if not self.result_storage_bucket or not self.result_encryption_key:
            raise RuntimeError("production requires RESULT_STORAGE_BUCKET and RESULT_ENCRYPTION_KEY")
        if self.result_retention_days < 1:
            raise RuntimeError("RESULT_RETENTION_DAYS must be at least one day")


@lru_cache
def get_settings() -> Settings:
    return Settings()
