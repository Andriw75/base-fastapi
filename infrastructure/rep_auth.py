import os
from datetime import timedelta,datetime,timezone

import jwt
from fastapi import HTTPException, status
from domain.ports.auth import IJWTManager

class JWTManagerImpl(IJWTManager):
    def __init__(self):
        """
        Inicializa el gestor de JWT.
        :param secret_key: Clave secreta para firmar el token.
        :param algorithm: Algoritmo de encriptación (por defecto HS256).
        :param default_expires_minutes: Tiempo de expiración por defecto en minutos.
        """
        self.secret_key = os.environ.get("SECRET_KEY")
        self.algorithm = os.environ.get("ALGORITHM")
        self.default_expires_minutes = 15

    def create_access_token(self, data: dict, expires_delta: timedelta|None = None) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.default_expires_minutes)
        to_encode.update({"exp": expire})
        token = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return token

    def verify_token(self, token: str) -> dict:
        """
        Verifica el token JWT y retorna la carga útil si es válido.
        :param token: Token JWT.
        :return: Payload del token.
        :raises HTTPException: Si el token es inválido o ha expirado.
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Token expirado")
        except jwt.PyJWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Token inválido")

import bcrypt
from domain.ports.auth import ICrypt

class BcryptMnjCrypt(ICrypt):
    def __init__(self):...
        
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verifica si la contraseña en texto plano corresponde al hash utilizando bcrypt.

        :param plain_password: Contraseña en texto plano.
        :param hashed_password: Contraseña hasheada.
        :return: True si la contraseña es correcta, False en caso contrario.
        """
        try:
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
        except ValueError:
            return False


from domain.models.auth import UserResponse, UserDb
from domain.ports.auth import IDataUser
import bcrypt

class UserService(IDataUser):
    def __init__(self):
        self._users_db = {
            "user" : UserDb(id=1, name="user", password=self._hash_password("123"), permissions=["Rep_RecImg"]),
            "andriwdv": UserDb(id=2, name="andriwdv", password=self._hash_password("abc1okv14"), permissions=["Rep_RecImg", "DatasetDetectionRep","ModelsDetectRep"])
        }

    def _hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    async def get_user(self, user_name: str) -> UserResponse|None:
        return self._users_db.get(user_name,None)

