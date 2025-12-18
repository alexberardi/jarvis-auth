from fastapi import APIRouter, Depends

from jarvis_auth.app.api.dependencies.app_auth import require_app_client
from jarvis_auth.app.db import models

router = APIRouter()


@router.get("/internal/app-ping")
def app_ping(app_client: models.AppClient = Depends(require_app_client)):
    return {"app_id": app_client.app_id, "name": app_client.name}

