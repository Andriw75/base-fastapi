# base-fastapi

Plantilla base para proyectos **FastAPI** con autenticación y contenedor de servicios.

---

## Requisitos

* Python 3.10+
* FastAPI, Uvicorn

---

## Instalación

1. Crear entorno virtual:

```bash
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows
```

2. Instalar dependencias:

```bash
pip install fastapi uvicorn
```

3. Copiar y configurar variables de entorno:

```bash
cp .env.example .env
# Edita .env y coloca tu SUPER_API_KEY
```

---

## Ejecución

```bash
python main.py
```

La API correrá por defecto en `http://127.0.0.1:8000`.

---

## Estructura rápida

* `main.py` → entrada principal.
* `main_container.py` → contenedor de servicios e inyección de dependencias.
* `application/auth/` → lógica y router de autenticación.
* `domain/models/` → modelos Pydantic.
* `domain/ports/` → interfaces de servicios (auth, crypt, JWT).
* `infrastructure/` → implementaciones concretas de servicios.

---

## Notas rápidas

* El contenedor de servicios (`ServiceContainer`) se usa para registrar y resolver dependencias automáticamente.
* `AuthRouter` maneja login, logout, verificación de permisos y API Key.
* Para detalles de implementación y rutas, revisar `application/auth/auth.py`.
