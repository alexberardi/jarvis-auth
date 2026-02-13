import logging
import os

from jarvis_log_client import JarvisLogHandler, JarvisLogger, init as init_log_client

_logger: JarvisLogger | None = None
_jarvis_handler: JarvisLogHandler | None = None
_initialized: bool = False


def setup_logging() -> None:
    """Initialize Jarvis logging and attach Uvicorn handlers."""
    global _initialized, _logger, _jarvis_handler
    if _initialized:
        return

    console_level = os.getenv("JARVIS_LOG_CONSOLE_LEVEL", "WARNING")
    remote_level = os.getenv("JARVIS_LOG_REMOTE_LEVEL", "DEBUG")

    logging.basicConfig(
        level=getattr(logging, console_level.upper(), logging.WARNING),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    app_id = os.getenv("JARVIS_APP_ID", "jarvis-auth")
    app_key = os.getenv("JARVIS_APP_KEY")
    if app_key:
        init_log_client(app_id=app_id, app_key=app_key)

    if _logger is None:
        effective_remote_level = remote_level if app_key else "CRITICAL"
        _logger = JarvisLogger(
            service="jarvis-auth",
            console_level=console_level,
            remote_level=effective_remote_level,
        )

    if app_key and _jarvis_handler is None:
        _jarvis_handler = JarvisLogHandler(
            service="jarvis-auth",
            level=getattr(logging, remote_level.upper(), logging.DEBUG),
        )
        for logger_name in ["uvicorn", "uvicorn.error", "uvicorn.access"]:
            logging.getLogger(logger_name).addHandler(_jarvis_handler)

    _logger.info("Jarvis logging initialized", remote_enabled=bool(app_key))
    _initialized = True


def get_logger() -> JarvisLogger:
    if _logger is None:
        setup_logging()
    return _logger
