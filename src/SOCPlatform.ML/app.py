"""
SOC Platform – ML Microservice
================================
Production-grade anomaly detection service with three ML models:
 1. Isolation Forest – Login pattern anomalies
 2. DBSCAN         – UEBA behavioral baselines
 3. Modified Z-Score – Network activity outliers

Runs on FastAPI, integrates with the .NET backend via REST.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from contextlib import asynccontextmanager
import logging
import sys
from datetime import datetime

from models import LoginAnomalyDetector, UEBADetector, NetworkOutlierDetector

# ──────────────────────────────────────────────────
#  Logging
# ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("soc_ml")

# ──────────────────────────────────────────────────
#  Model Singletons
# ──────────────────────────────────────────────────
login_detector = LoginAnomalyDetector()
ueba_detector = UEBADetector()
network_detector = NetworkOutlierDetector(threshold=3.5)


# ──────────────────────────────────────────────────
#  Lifespan – auto-load persisted models on startup
# ──────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Loading persisted ML models...")
    login_detector._load_model()
    ueba_detector._load_model()
    network_detector._load_model()

    loaded = sum([login_detector.is_trained, ueba_detector.is_trained, network_detector.is_trained])
    logger.info(f"{loaded}/3 models loaded from disk.")

    if loaded == 0:
        logger.info("No saved models found — auto-training with synthetic baselines.")
        login_detector.train([])
        ueba_detector.train([])
        network_detector.train([])

    yield  # Serve
    logger.info("ML service shutting down.")


# ──────────────────────────────────────────────────
#  FastAPI Application
# ──────────────────────────────────────────────────
app = FastAPI(
    title="SOC Platform ML Service",
    description="Anomaly detection, UEBA, and network outlier analysis for the SOC platform",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────
#  Request / Response Models
# ──────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    """Event to analyze. The model is chosen based on event_category."""
    event_category: str = Field(
        ...,
        description="Category of the event: 'authentication', 'user_behavior', or 'network'"
    )
    event_action: str = Field(default="", description="Action type (login, access, transfer)")
    source_ip: Optional[str] = None
    username: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    success: Optional[bool] = None
    metadata: Optional[dict] = Field(
        default=None,
        description="Extra fields: connections, dest_ports, bytes_sent, dest_ips, event_type, resource, etc."
    )


class AnalyzeResponse(BaseModel):
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    reason: Optional[str] = None
    model_used: str
    details: Optional[dict] = None


class TrainRequest(BaseModel):
    """Optional training data. If empty, synthetic baseline is used."""
    model: str = Field(
        default="all",
        description="Which model to train: 'login', 'ueba', 'network', or 'all'"
    )
    events: Optional[list[dict]] = None


class TrainResponse(BaseModel):
    status: str
    models_trained: list[str]
    stats: dict


class HealthResponse(BaseModel):
    status: str
    version: str
    models: dict
    timestamp: datetime


# ──────────────────────────────────────────────────
#  Endpoints
# ──────────────────────────────────────────────────

@app.get("/api/ml/status", response_model=HealthResponse)
async def health_check():
    """Health check – reports which models are trained and ready."""
    return HealthResponse(
        status="healthy",
        version="2.0.0",
        models={
            "isolation_forest": {
                "trained": login_detector.is_trained,
                "stats": login_detector.training_stats,
            },
            "dbscan_ueba": {
                "trained": ueba_detector.is_trained,
                "stats": ueba_detector.training_stats,
            },
            "zscore_network": {
                "trained": network_detector.is_trained,
                "stats": network_detector.training_stats,
            },
        },
        timestamp=datetime.utcnow(),
    )


@app.post("/api/ml/analyze", response_model=AnalyzeResponse)
async def analyze_event(request: AnalyzeRequest):
    """
    Analyze a security event for anomalies.

    The correct ML model is automatically selected based on event_category:
      - 'authentication' → Isolation Forest
      - 'user_behavior'  → DBSCAN UEBA
      - 'network'        → Modified Z-Score
    """
    category = request.event_category.lower().strip()

    # Build the event dict for the model
    event = {
        "timestamp": request.timestamp.isoformat(),
        "username": request.username or "unknown",
        "source_ip": request.source_ip or "0.0.0.0",
        "success": request.success if request.success is not None else True,
        "event_action": request.event_action,
    }
    if request.metadata:
        event.update(request.metadata)

    # Route to the correct model
    if category in ("authentication", "login", "auth"):
        result = login_detector.predict(event)
    elif category in ("user_behavior", "ueba", "behavior", "user"):
        event.setdefault("event_type", request.event_action)
        event.setdefault("resource", event.get("resource", "default"))
        result = ueba_detector.predict(event)
    elif category in ("network", "traffic", "connection"):
        result = network_detector.predict(event)
    else:
        # Default: run all models, return the most anomalous result
        results = [
            login_detector.predict(event),
            ueba_detector.predict(event),
            network_detector.predict(event),
        ]
        result = max(results, key=lambda r: r["anomaly_score"])

    # Extract extra details (z_scores, cluster info, raw_score)
    details = {k: v for k, v in result.items()
               if k not in ("is_anomaly", "anomaly_score", "confidence", "reason", "model_used")}

    return AnalyzeResponse(
        is_anomaly=result["is_anomaly"],
        anomaly_score=result["anomaly_score"],
        confidence=result["confidence"],
        reason=result.get("reason"),
        model_used=result["model_used"],
        details=details or None,
    )


@app.post("/api/ml/train", response_model=TrainResponse)
async def train_models(request: TrainRequest = TrainRequest()):
    """
    Train or retrain ML models.

    If no events are provided, synthetic baselines are used for cold-start.
    Specify `model` to train a single model, or 'all' for all three.
    """
    events = request.events or []
    target = request.model.lower().strip()
    trained = []
    all_stats = {}

    try:
        if target in ("login", "all", "isolation_forest"):
            stats = login_detector.train(events)
            trained.append("isolation_forest")
            all_stats["isolation_forest"] = stats

        if target in ("ueba", "all", "dbscan", "dbscan_ueba"):
            stats = ueba_detector.train(events)
            trained.append("dbscan_ueba")
            all_stats["dbscan_ueba"] = stats

        if target in ("network", "all", "zscore", "zscore_network"):
            stats = network_detector.train(events)
            trained.append("zscore_network")
            all_stats["zscore_network"] = stats

        if not trained:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown model: '{request.model}'. Use 'login', 'ueba', 'network', or 'all'."
            )

    except Exception as e:
        logger.exception("Training failed")
        raise HTTPException(status_code=500, detail=str(e))

    return TrainResponse(
        status="trained",
        models_trained=trained,
        stats=all_stats,
    )


@app.post("/api/ml/analyze/batch")
async def analyze_batch(events: list[AnalyzeRequest]):
    """Analyze a batch of events. Returns a list of results."""
    if len(events) > 500:
        raise HTTPException(status_code=400, detail="Batch size limited to 500 events")

    results = []
    for ev in events:
        resp = await analyze_event(ev)
        results.append(resp.model_dump())

    summary = {
        "total": len(results),
        "anomalies": sum(1 for r in results if r["is_anomaly"]),
        "max_score": max((r["anomaly_score"] for r in results), default=0.0),
    }

    return {"results": results, "summary": summary}


# ──────────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
