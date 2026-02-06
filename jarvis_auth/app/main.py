import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from jarvis_settings_client import create_settings_router

from jarvis_auth.app.api import auth as auth_routes
from jarvis_auth.app.api import admin_app_clients
from jarvis_auth.app.api import admin_nodes
from jarvis_auth.app.api import admin_users
from jarvis_auth.app.api import households
from jarvis_auth.app.api import internal
from jarvis_auth.app.api.deps import require_settings_auth
from jarvis_auth.app.db import base, session as db_session
from jarvis_auth.app.services.settings_service import get_settings_service

# Set up logging
console_level = os.getenv("JARVIS_LOG_CONSOLE_LEVEL", "WARNING")
logging.basicConfig(
    level=getattr(logging, console_level.upper(), logging.WARNING),
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("uvicorn")

_jarvis_handler = None


def _setup_remote_logging() -> None:
    """Set up remote logging to jarvis-logs server."""
    global _jarvis_handler
    try:
        from jarvis_log_client import init as init_log_client, JarvisLogHandler

        app_id = os.getenv("JARVIS_APP_ID", "jarvis-auth")
        app_key = os.getenv("JARVIS_APP_KEY")
        if not app_key:
            return

        init_log_client(app_id=app_id, app_key=app_key)

        remote_level = os.getenv("JARVIS_LOG_REMOTE_LEVEL", "DEBUG")
        _jarvis_handler = JarvisLogHandler(
            service="jarvis-auth",
            level=getattr(logging, remote_level.upper(), logging.DEBUG),
        )

        for logger_name in ["uvicorn", "uvicorn.error", "uvicorn.access"]:
            logging.getLogger(logger_name).addHandler(_jarvis_handler)

        logger.info("📡 Remote logging enabled to jarvis-logs")
    except ImportError as exc:
        logger.debug("jarvis_log_client not available, remote logging disabled: %s", exc)


def create_app() -> FastAPI:
    app = FastAPI(title="Jarvis Auth")

    _allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:5173").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_routes.router, tags=["auth"])
    app.include_router(admin_app_clients.router, tags=["admin"])
    app.include_router(admin_nodes.router, tags=["admin-nodes"])
    app.include_router(admin_users.router, tags=["admin-users"])
    app.include_router(households.router, tags=["households"])
    app.include_router(internal.router, tags=["internal"])

    # Settings router from shared library
    # Uses combined auth: superuser JWT OR app-to-app credentials
    settings_router = create_settings_router(
        service=get_settings_service(),
        auth_dependency=require_settings_auth,
    )
    app.include_router(settings_router, prefix="/settings", tags=["settings"])

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()


@app.on_event("startup")
def on_startup():
    base.Base.metadata.create_all(bind=db_session.engine)
    _setup_remote_logging()

