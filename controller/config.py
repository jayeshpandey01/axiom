from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_BUNDLED_WORDLIST = str(Path(__file__).parent.parent / "scripts" / "wordlists" / "common.txt")
_AXIOM_WORDLIST = str(Path.home() / ".axiom" / "wordlists" / "common.txt")


class ControllerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CONTROLLER_", env_file=(".env", ".env.local"), extra="ignore")

    axiom_bin_path: str = str(Path.home() / ".axiom" / "interact")
    max_fleet_size: int = 2
    scan_timeout_seconds: int = 900
    droplet_ttl_minutes: int = 30
    work_dir: str = str(Path("./runs").resolve())
    api_endpoint: str | None = None
    shared_secret: str = "development-only-change-me"
    dry_run: bool = True
    # Path to the FFUF wordlist used in content-discovery profile.
    # Override with CONTROLLER_FFUF_WORDLIST env var on the controller VPS.
    ffuf_wordlist: str = _AXIOM_WORDLIST if Path(_AXIOM_WORDLIST).exists() else _BUNDLED_WORDLIST
    # Interactsh OOB callback infrastructure configuration
    interactsh_server: str | None = None
    interactsh_token: str | None = None
    interactsh_disable: bool = False
    interactsh_poll_duration_sec: int = 15


settings = ControllerSettings()
