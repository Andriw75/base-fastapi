from typing import Callable
import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, status, Response, Request, Header, WebSocket
from fastapi.security import OAuth2PasswordRequestForm

from domain.models.auth import UserResponse, UserDb
from domain.ports.auth import IDataUser, IJWTManager, ICrypt


class AuthRouter:
    """
    Clase que encapsula el router de autenticación y dependencias relacionadas.
    """

    def __init__(
        self,
        data_user_service: IDataUser,
        crypt_manager: ICrypt,
        jwt_manager: IJWTManager,
    ):
        """
        Inicializa el router de autenticación.

        Args:
            data_user_service (IDataUser): Servicio para obtener usuarios de la base de datos.
            crypt_manager (ICrypt): Servicio para encriptar/verificar contraseñas.
            jwt_manager (IJWTManager): Servicio para crear y verificar tokens JWT.
        """
        self.data_user_service = data_user_service
        self.crypt_manager = crypt_manager
        self.jwt_manager = jwt_manager

        self.router = APIRouter(tags=['auth'], prefix='/auth')
        self._init_routes()

    def _init_routes(self):
        """Define todas las rutas del router de autenticación."""
        self.router.get("/me", response_model=UserResponse)(self.me)
        self.router.post("/token")(self.token)
        self.router.post("/logout")(self.logout)

    async def get_current_user(self, request: Request, response: Response) -> UserDb:
        """
        Obtiene el usuario actual a partir del token en cookies.

        Renueva el token si queda menos de 5 minutos de validez.

        Args:
            request (Request): Objeto Request de FastAPI.
            response (Response): Objeto Response para actualizar cookies.

        Returns:
            UserDb: Usuario autenticado.
        """
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No se encontró token de autenticación",
            )

        try:
            payload = self.jwt_manager.verify_token(token)
            exp_timestamp = payload.get("exp")

            if exp_timestamp:
                now = datetime.now(timezone.utc).timestamp()
                tiempo_restante = exp_timestamp - now
                if tiempo_restante < 300:
                    # Renueva el token si queda menos de 5 minutos
                    new_token = self.jwt_manager.create_access_token(
                        data={k: v for k, v in payload.items() if k != "exp"}
                    )
                    response.set_cookie(
                        key="access_token",
                        value=new_token,
                        httponly=True,
                        max_age=900,
                        secure=False,
                        samesite="Lax",
                        # secure=True,
                        # samesite='none',
                    )

            return UserDb(**payload)

        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido o expirado",
            )

    def permission_required(self, permission: str) -> Callable:
        """
        Crea una dependencia de FastAPI que verifica si el usuario tiene un permiso específico.

        Args:
            permission (str): Permiso requerido.

        Returns:
            Callable: Dependencia de FastAPI que valida el permiso.
        """
        def dependency(current: UserDb = Depends(self.get_current_user)):
            if permission not in current.permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permiso '{permission}' requerido"
                )
            return current
        return dependency

    # TODO: MEJORAR EL API KEY PARA EMPLEAR UNA MEJOR LOGICA INDICANDO SI CONSUME CREDITOS ETC ETC
    def api_key_required(self) -> Callable:
        """
        Crea una dependencia que valida la API Key en headers.

        Returns:
            Callable: Dependencia que valida la API Key.
        """
        async def dependency(x_api_key: str = Header(..., alias="x-api-key")):
            if x_api_key != os.getenv("SUPER_API_KEY"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="API Key inválida o no autorizada"
                )
            return x_api_key
        return dependency

    async def me(self, current_user: UserDb = Depends(get_current_user)) -> UserResponse:
        """
        Retorna información del usuario actual autenticado.

        Args:
            current_user (UserDb): Usuario autenticado.

        Returns:
            UserResponse: Datos del usuario.
        """
        return UserResponse(
            name=current_user.name,
            permissions=current_user.permissions
        )

    async def token(
        self,
        response: Response,
        form_data: OAuth2PasswordRequestForm = Depends()
    ) -> UserResponse:
        """
        Autentica al usuario y genera un token de acceso.

        Args:
            response (Response): Objeto Response para almacenar la cookie.
            form_data (OAuth2PasswordRequestForm): Datos del formulario de login.

        Returns:
            UserResponse: Datos del usuario autenticado.
        """
        user: UserDb = await self.data_user_service.get_user(form_data.username)

        if not user or not self.crypt_manager.verify_password(form_data.password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario o contraseña inválidos"
            )

        access_token = self.jwt_manager.create_access_token(data=user.model_dump())
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            max_age=900,
            secure=False,
            samesite="Lax",
            # secure=True,
            # samesite='none',
        )

        return UserResponse(name=user.name, permissions=user.permissions)

    async def logout(self, response: Response):
        """
        Cierra la sesión del usuario eliminando la cookie de acceso.

        Args:
            response (Response): Objeto Response para eliminar la cookie.

        Returns:
            dict: Mensaje de confirmación.
        """
        response.delete_cookie(key="access_token", secure=False, samesite="Lax") # secure=True, samesite='none',
        return {"detail": "Sesión cerrada"}

    async def validate_user_ws(self, ws: WebSocket, permiso: str) -> UserDb | None:
        """
        Valida un usuario a través de WebSocket verificando el token y permisos.

        Args:
            ws (WebSocket): Conexión WebSocket.
            permiso (str): Permiso requerido.

        Returns:
            UserDb | None: Usuario validado o None si no tiene permisos.
        """
        token = ws.cookies.get("access_token")
        if not token:
            return None

        try:
            payload = self.jwt_manager.verify_token(token)
            user = UserDb(**payload)
            if permiso not in user.permissions:
                return None
            return user
        except Exception:
            return None
