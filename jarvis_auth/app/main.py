from fastapi import FastAPI

from jarvis_auth.app.api import auth as auth_routes
from jarvis_auth.app.api import admin_app_clients
from jarvis_auth.app.api import internal
from jarvis_auth.app.db import base, session as db_session


def create_app() -> FastAPI:
    app = FastAPI(title="Jarvis Auth")
    app.include_router(auth_routes.router, tags=["auth"])
    app.include_router(admin_app_clients.router, tags=["admin"])
    app.include_router(internal.router, tags=["internal"])

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()


@app.on_event("startup")
def on_startup():
    base.Base.metadata.create_all(bind=db_session.engine)

