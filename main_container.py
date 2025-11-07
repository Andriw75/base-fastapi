import inspect
from enum import Enum
from collections.abc import Callable

class ServiceLifetime(Enum):
    SINGLETON = "singleton"
    TRANSIENT = "transient"


class ServiceContainer:
    """
    from fastapi import FastAPI
    from main_container import ServiceContainer
    from application.auth.auth import create
    from domain.ports.auth import IDataUser, ICrypt, IJWTManager
    from infrastructure.rep_auth import UserService, BcryptMnjCrypt, JWTManagerImpl

    # Crear el contenedor
    container = ServiceContainer()

    # Registrar servicios
    container.register(IDataUser, UserService)
    container.register(ICrypt, BcryptMnjCrypt)
    container.register(IJWTManager, JWTManagerImpl)

    # Resolver servicios y generar routers o funciones
    auth_router, get_current_user, permission_required, get_api_key, validar_usuario_ws = container.call(create)

    # Crear la app FastAPI
    app = FastAPI()
    app.include_router(auth_router)

    # Ejemplo de inyección automática en funciones
    # user_service = container.resolve(IDataUser)
    # crypt_service = container.resolve(ICrypt)
    """


    def __init__(self) -> None:
        self._services: dict[type, dict[str, object]] = {}
        self._singletons: dict[type, object] = {}

    def register(
        self,
        interface: type,
        implementation: type,
        lifetime: ServiceLifetime = ServiceLifetime.SINGLETON
    ) -> None:
        """
        Registra un servicio/interface con su implementación y ciclo de vida.
        """
        if interface in self._services:
            raise ValueError(f"Service {interface} is already registered")

        self._services[interface] = {
            "implementation": implementation,
            "lifetime": lifetime,
        }

    def resolve(self, interface: type) -> object:
        """
        Resuelve la implementación de una interfaz o clase, inyectando dependencias automáticamente.
        """
        # Retornar singleton si ya existe
        if interface in self._singletons:
            return self._singletons[interface]

        # Determinar implementación
        if interface not in self._services:
            impl = interface
            lifetime = ServiceLifetime.TRANSIENT
        else:
            service_info = self._services[interface]
            impl = service_info["implementation"]
            lifetime = service_info["lifetime"]

        # Inspeccionar dependencias del constructor
        sig = inspect.signature(impl.__init__)
        deps: list[object] = []

        for name, param in list(sig.parameters.items())[1:]:  # skip self
            if param.default is not inspect.Parameter.empty:
                continue
            if param.annotation is inspect.Parameter.empty:
                raise TypeError(
                    f"Missing type annotation for parameter '{name}' in {impl.__name__}"
                )
            deps.append(self.resolve(param.annotation))

        instance = impl(*deps)

        if lifetime is ServiceLifetime.SINGLETON:
            self._singletons[interface] = instance

        return instance

    def call(self, func: Callable[..., object]) -> object:
        """
        Inyecta dependencias automáticamente en funciones (como factories, routers, etc.)
        """
        sig = inspect.signature(func)
        args = []
        for param in sig.parameters.values():
            if param.annotation is inspect.Parameter.empty:
                raise TypeError(
                    f"Missing type annotation for parameter '{param.name}' in function {func.__name__}"
                )
            args.append(self.resolve(param.annotation))
        return func(*args)
