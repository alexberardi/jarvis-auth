from fastapi import Header, HTTPException, Request, status

from jarvis_auth.app.core.settings import reload_settings


def require_admin_token(
    request: Request,
    x_jarvis_admin_token: str | None = Header(None),
):
    settings = reload_settings()
    header_token = x_jarvis_admin_token or request.headers.get("x-jarvis-admin-token")
    if not header_token or header_token != settings.admin_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    return True

