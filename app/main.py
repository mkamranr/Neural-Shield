"""
NeuralShield - AI-Driven Cyber Defense System
Main FastAPI Application
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pathlib import Path
import logging
import uvicorn

from app.database import init_db
from app.api import router as api_router
from config import HOST, PORT, DEBUG

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    logger.info("Starting NeuralShield...")
    init_db()
    logger.info("NeuralShield started successfully")
    
    yield
    
    logger.info("Shutting down NeuralShield...")


app = FastAPI(
    title="NeuralShield - AI Cyber Defense",
    description="AI-Driven Cyber Defense System for detecting and preventing cyber attacks",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

templates_dir = BASE_DIR / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

app.include_router(api_router)


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main dashboard"""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": {}, "title": "NeuralShield - Dashboard"}
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the dashboard page"""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": {}, "title": "NeuralShield - Dashboard"}
    )


@app.get("/threats", response_class=HTMLResponse)
async def threats_page():
    """Serve the threats page"""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": {}, "title": "NeuralShield - Threat Monitor"}
    )


@app.get("/firewall", response_class=HTMLResponse)
async def firewall_page():
    """Serve the firewall page"""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": {}, "title": "NeuralShield - Firewall"}
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page():
    """Serve the settings page"""
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": {}, "title": "NeuralShield - Settings"}
    )


def main():
    """Run the application"""
    uvicorn.run(
        "app.main:app",
        host=HOST,
        port=PORT,
        reload=DEBUG,
        log_level="info"
    )


if __name__ == "__main__":
    main()
