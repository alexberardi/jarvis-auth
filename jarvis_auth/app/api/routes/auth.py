from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from jarvis_auth.app import schemas
from jarvis_auth.app.api import deps
from jarvis_auth.app.core import security
from jarvis_auth.app.services import auth_service

router = APIRouter()


@router.post("/register", response_model=schemas.user.UserRead, status_code=status.HTTP_201_CREATED)
def register_user(payload: schemas.auth.RegisterRequest, db: Session = Depends(deps.get_db)):
    user = auth_service.register_user(db, payload)
    return user


@router.post("/login", response_model=schemas.auth.TokenResponse)
def login(payload: schemas.auth.LoginRequest, db: Session = Depends(deps.get_db)):
    user = auth_service.authenticate_user(db, payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = security.create_access_token({"sub": str(user.id), "email": user.email})
    refresh_token, refresh_hash, expires_at = auth_service.build_refresh_token()
    auth_service.store_refresh_token(db, user, refresh_hash, expires_at)

    return schemas.auth.TokenResponse(access_token=access_token, refresh_token=refresh_token, user=user)


@router.post("/refresh", response_model=schemas.auth.TokenResponse)
def refresh(payload: schemas.auth.RefreshRequest, db: Session = Depends(deps.get_db)):
    access_token = auth_service.refresh_access_token(db, payload.refresh_token)
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    return schemas.auth.TokenResponse(access_token=access_token, refresh_token=payload.refresh_token, user=None)


@router.get("/me", response_model=schemas.user.UserRead)
def read_me(current_user=Depends(deps.get_current_user)):
    return current_user


@router.post("/logout")
def logout(payload: schemas.auth.LogoutRequest, db: Session = Depends(deps.get_db)):
    success = auth_service.revoke_refresh_token(db, payload.refresh_token)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token")
    return {"detail": "Logged out"}

