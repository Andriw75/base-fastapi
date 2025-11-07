########################################
# INICIAMOS VARIABLES DE ENTORNO
########################################
from dotenv import load_dotenv
load_dotenv(dotenv_path=".env")

########################################
# REGISTRAMOS SERVICIOS
########################################
from main_container import ServiceContainer
from domain.ports.auth import IDataUser, ICrypt, IJWTManager
from infrastructure.rep_auth import JWTManagerImpl, BcryptMnjCrypt, UserService

container = ServiceContainer()
container.register(IDataUser,UserService)
container.register(ICrypt,BcryptMnjCrypt)
container.register(IJWTManager,JWTManagerImpl)

########################################
# IMPLEMENTAMOS RAUTERS
########################################
from fastapi import FastAPI
from application.auth.auth import AuthRouter

app = FastAPI()
instance_auth:AuthRouter = container.call(AuthRouter)
app.include_router(instance_auth.router)



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app,host='0.0.0.0', port=8000)

