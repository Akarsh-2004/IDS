from model_pipeline import ModelMeta
from realtime.features import flow_to_model_features


def test_flow_to_model_features_emits_required_schema_fields() -> None:
    meta = ModelMeta(
        feature_columns=["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "count", "srv_count"],
        categorical_columns=["protocol_type", "service", "flag"],
        numeric_columns=["duration", "src_bytes", "dst_bytes", "count", "srv_count"],
        default_values={},
    )
    flow = {
        "duration": 1.2,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 100,
        "dst_bytes": 50,
        "count": 2,
        "srv_count": 1,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
    }
    features, details = flow_to_model_features(flow, meta)
    assert set(features.keys()) == set(meta.feature_columns)
    assert features["protocol_type"] == "tcp"
    assert details["src_ip"] == "10.0.0.1"
