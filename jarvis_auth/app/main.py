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
from jarvis_auth.app.api.deps import require_settings_auth, require_superuser
from jarvis_auth.app.core.logging import get_logger, setup_logging
from jarvis_auth.app.db import base, session as db_session
from jarvis_auth.app.services.settings_service import get_settings_service

logger = get_logger()


def create_app() -> FastAPI:
    setup_logging()
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
    # Reads: superuser JWT OR app-to-app credentials
    # Writes: superuser JWT only (defense in depth)
    settings_router = create_settings_router(
        service=get_settings_service(),
        auth_dependency=require_settings_auth,
        write_auth_dependency=require_superuser,
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
    logger.info("Startup complete")

