from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from model_pipeline import FEATURES_PATH, META_PATH, MODEL_PATH, load_model, load_model_meta, predict_one, train_model
from realtime.pipeline import RealtimeEngine


ROOT = Path(__file__).resolve().parents[1]
TRAIN_PATH = ROOT / "Train_data.csv"
TEST_PATH = ROOT / "Test_data.csv"

app = FastAPI(title="IDS Pipeline API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

model = None
feature_columns: list[str] = []
model_meta = None
realtime_engine: RealtimeEngine | None = None


class TrainResponse(BaseModel):
    status: str
    accuracy: float
    train_rows: int
    test_rows: int
    feature_count: int
    report: str


class PredictRequest(BaseModel):
    features: dict[str, Any] = Field(..., description="Feature map keyed by column name")


class PredictResponse(BaseModel):
    label: str
    prediction: int
    probabilities: dict[str, float] | None = None


class RealtimeConfig(BaseModel):
    mode: str = Field(default="live", description="live or pcap")
    interface: str | None = None
    pcap_path: str | None = None


@app.on_event("startup")
def startup() -> None:
    global model, feature_columns, model_meta, realtime_engine
    if MODEL_PATH.exists() and FEATURES_PATH.exists() and META_PATH.exists():
        model, feature_columns = load_model()
        model_meta = load_model_meta()
        realtime_engine = RealtimeEngine(db_path=ROOT / "backend" / "artifacts" / "events.sqlite3")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/schema")
def schema() -> dict[str, Any]:
    if not TRAIN_PATH.exists():
        raise HTTPException(status_code=404, detail="Train_data.csv not found")
    columns = pd.read_csv(TRAIN_PATH, nrows=2).columns.tolist()
    feature_cols = columns[:-1]
    return {"feature_columns": feature_cols, "target_column": columns[-1]}


@app.post("/train", response_model=TrainResponse)
def train() -> TrainResponse:
    global model, feature_columns, model_meta, realtime_engine
    if not TRAIN_PATH.exists():
        raise HTTPException(status_code=404, detail="Train_data.csv not found")
    result = train_model(TRAIN_PATH)
    model, feature_columns = load_model()
    model_meta = load_model_meta()
    realtime_engine = RealtimeEngine(db_path=ROOT / "backend" / "artifacts" / "events.sqlite3")
    return TrainResponse(status="trained", **result.__dict__)


@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest) -> PredictResponse:
    if model is None or not feature_columns or model_meta is None:
        raise HTTPException(status_code=400, detail="Model not trained yet. Run /train first.")
    response = predict_one(model, feature_columns, request.features, meta=model_meta, strict=True)
    return PredictResponse(**response)


@app.post("/evaluate")
def evaluate() -> dict[str, Any]:
    if model is None or not feature_columns:
        raise HTTPException(status_code=400, detail="Model not trained yet. Run /train first.")
    if not TEST_PATH.exists():
        raise HTTPException(status_code=404, detail="Test_data.csv not found")

    df = pd.read_csv(TEST_PATH)
    x = df[feature_columns]
    y = df.iloc[:, -1].astype(str).str.lower().apply(lambda x: 1 if x in {"anomaly", "attack"} else 0)
    y_pred = model.predict(x)
    accuracy = float((y_pred == y).mean())

    return {"accuracy": accuracy, "samples": int(len(df))}


@app.post("/realtime/start")
def realtime_start(config: RealtimeConfig) -> dict[str, Any]:
    if realtime_engine is None:
        raise HTTPException(status_code=400, detail="Model not trained yet. Run /train first.")
    realtime_engine.configure(mode=config.mode, interface=config.interface, pcap_path=config.pcap_path)
    realtime_engine.start()
    return {"status": "started", **realtime_engine.status()}


@app.post("/realtime/stop")
def realtime_stop() -> dict[str, Any]:
    if realtime_engine is None:
        return {"status": "idle"}
    realtime_engine.stop()
    return {"status": "stopping"}


@app.get("/realtime/status")
def realtime_status() -> dict[str, Any]:
    if realtime_engine is None:
        return {"running": False, "detail": "Model not trained yet"}
    return realtime_engine.status()


@app.get("/realtime/events")
def realtime_events(limit: int = 100, severity: str | None = None) -> dict[str, Any]:
    if realtime_engine is None:
        return {"events": []}
    return {"events": realtime_engine.store.list_events(limit=limit, severity=severity)}


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    if realtime_engine is None:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    last_id = 0
    try:
        while True:
            events = realtime_engine.store.list_events(limit=25)
            fresh = [e for e in reversed(events) if e["id"] > last_id]
            for event in fresh:
                await websocket.send_json({"type": "alert", "event": event, "metrics": realtime_engine.metrics.snapshot()})
                last_id = max(last_id, event["id"])
            await websocket.send_json(realtime_engine.heartbeat())
            await asyncio.sleep(1.0)
    except (WebSocketDisconnect, RuntimeError):
        pass
