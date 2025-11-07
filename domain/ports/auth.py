from abc import ABC,abstractmethod
from datetime import timedelta
from domain.models.auth import UserResponse

class IDataUser(ABC):

    @abstractmethod
    def get_user(self, user_name: str) -> UserResponse | None:
        """
        Retorna el objeto usuario si existe, o None.
        """
        ...
    
class ICrypt(ABC):
    """
    Interfaz para la gestión de encriptación y verificación de contraseñas.
    """
    @abstractmethod
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verifica si la contraseña en texto plano coincide con la contraseada.
        """
        ...

class IJWTManager(ABC):
    """
    Interfaz para la creación y verificación de tokens JWT.
    """
    @abstractmethod
    def create_access_token(self, data: dict, expires_delta: timedelta|None = None) -> str:
        """
        Crea un token de acceso JWT con los datos proporcionados.
        """
        ...

    @abstractmethod
    def verify_token(self, token: str) -> dict:
        """
        Verifica la validez de un token JWT y retorna su payload.
        """
        ...
