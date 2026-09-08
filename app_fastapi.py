#!/usr/bin/env python3
"""
NetGuard AI - FastAPI Backend Service Alternative
Provides the identical REST API endpoints using FastAPI & Uvicorn.
Run with: uvicorn app_fastapi:app --reload --port 5050
"""

import os
import json
import random
import datetime
import numpy as np
import pandas as pd
import joblib

try:
    from fastapi import FastAPI, UploadFile, File, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
except ImportError:
    # Fallback placeholder if fastapi is not yet installed in the current environment
    FastAPI = None

if FastAPI:
    app = FastAPI(title="NetGuard AI - ML Intrusion Detection System", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    STATIC_DIR = os.path.join(BASE_DIR, "static")

    if os.path.exists(STATIC_DIR):
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def read_root():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    # ... Full endpoints matching app.py
else:
    app = None
