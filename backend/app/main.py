from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes_capture import router as capture_router
from app.api.routes_inventory import router as inventory_router
from app.api.routes_vulns import router as vulns_router
from app.capture.live_capture import live_capture_manager
from app.db import init_db

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield
    live_capture_manager.stop_all()


app = FastAPI(
    title="TridentyOT",
    description=(
        "Inventario de activos y análisis de vulnerabilidades a partir de captura pasiva de "
        "tráfico de red (tcpdump/tshark) en entornos IT/OT."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(capture_router)
app.include_router(inventory_router)
app.include_router(vulns_router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="dashboard")
