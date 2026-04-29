from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


MODEL_DIR = Path(__file__).resolve().parent / "artifacts"
MODEL_PATH = MODEL_DIR / "model.joblib"
FEATURES_PATH = MODEL_DIR / "feature_columns.joblib"
META_PATH = MODEL_DIR / "model_meta.joblib"


@dataclass
class TrainingResult:
    accuracy: float
    report: str
    train_rows: int
    test_rows: int
    feature_count: int


@dataclass
class ModelMeta:
    feature_columns: list[str]
    categorical_columns: list[str]
    numeric_columns: list[str]
    default_values: dict[str, Any]


def _build_pipeline(df: pd.DataFrame) -> tuple[Pipeline, list[str]]:
    feature_columns = list(df.columns[:-1])
    features = df[feature_columns]

    categorical_cols = features.select_dtypes(include=["object"]).columns.tolist()
    numeric_cols = [col for col in feature_columns if col not in categorical_cols]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
            ("num", StandardScaler(), numeric_cols),
        ]
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", RandomForestClassifier(n_estimators=250, random_state=42, n_jobs=-1)),
        ]
    )
    return pipeline, feature_columns


def _build_target(df: pd.DataFrame) -> pd.Series:
    labels = df.iloc[:, -1].astype(str).str.lower()
    # Support both anomaly/normal and attack/normal conventions.
    return labels.apply(lambda x: 1 if x in {"anomaly", "attack"} else 0)


def train_model(train_csv_path: Path) -> TrainingResult:
    df = pd.read_csv(train_csv_path)
    y = _build_target(df)

    model, feature_columns = _build_pipeline(df)
    x = df[feature_columns]
    categorical_columns = x.select_dtypes(include=["object"]).columns.tolist()
    numeric_columns = [col for col in feature_columns if col not in categorical_columns]

    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.2, random_state=42, stratify=y
    )

    model.fit(x_train, y_train)
    y_pred = model.predict(x_test)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(feature_columns, FEATURES_PATH)
    default_values = {}
    for col in categorical_columns:
        mode_series = x[col].mode(dropna=True)
        default_values[col] = str(mode_series.iloc[0]) if not mode_series.empty else "unknown"
    for col in numeric_columns:
        default_values[col] = float(pd.to_numeric(x[col], errors="coerce").fillna(0).median())
    meta = ModelMeta(
        feature_columns=feature_columns,
        categorical_columns=categorical_columns,
        numeric_columns=numeric_columns,
        default_values=default_values,
    )
    joblib.dump(meta, META_PATH)

    return TrainingResult(
        accuracy=float(accuracy_score(y_test, y_pred)),
        report=classification_report(y_test, y_pred, target_names=["normal", "intrusion"]),
        train_rows=len(x_train),
        test_rows=len(x_test),
        feature_count=len(feature_columns),
    )


def load_model() -> tuple[Pipeline, list[str]]:
    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(FEATURES_PATH)
    return model, feature_columns


def load_model_meta() -> ModelMeta:
    if META_PATH.exists():
        return joblib.load(META_PATH)
    feature_columns = joblib.load(FEATURES_PATH)
    return ModelMeta(feature_columns=feature_columns, categorical_columns=[], numeric_columns=[], default_values={})


def normalize_features(payload: dict[str, Any], meta: ModelMeta, strict: bool = False) -> tuple[dict[str, Any], list[str]]:
    normalized: dict[str, Any] = {}
    errors: list[str] = []
    for col in meta.feature_columns:
        raw = payload.get(col, meta.default_values.get(col))
        if col in meta.numeric_columns:
            try:
                normalized[col] = float(raw if raw is not None else 0.0)
            except (TypeError, ValueError):
                if strict:
                    errors.append(f"{col} must be numeric")
                normalized[col] = float(meta.default_values.get(col, 0.0))
        else:
            normalized[col] = str(raw) if raw is not None else str(meta.default_values.get(col, "unknown"))
    return normalized, errors


def predict_one(
    model: Pipeline,
    feature_columns: list[str],
    payload: dict[str, Any],
    meta: ModelMeta | None = None,
    strict: bool = False,
) -> dict[str, Any]:
    meta = meta or ModelMeta(feature_columns=feature_columns, categorical_columns=[], numeric_columns=[], default_values={})
    row, errors = normalize_features(payload, meta=meta, strict=strict)
    if strict and errors:
        raise ValueError("; ".join(errors))
    sample_df = pd.DataFrame([row], columns=feature_columns)
    prediction = int(model.predict(sample_df)[0])

    probabilities = None
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(sample_df)[0].tolist()
        probabilities = {"normal": float(probs[0]), "intrusion": float(probs[1])}

    return {
        "label": "intrusion" if prediction == 1 else "normal",
        "prediction": prediction,
        "probabilities": probabilities,
    }
