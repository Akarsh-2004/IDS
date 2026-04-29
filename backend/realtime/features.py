from __future__ import annotations

from typing import Any

from model_pipeline import ModelMeta, normalize_features


def _default_kdd_fields() -> dict[str, Any]:
    return {
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "srv_serror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 0,
        "dst_host_srv_count": 0,
        "dst_host_same_srv_rate": 0.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }


def flow_to_model_features(flow_stats: dict[str, Any], meta: ModelMeta) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = _default_kdd_fields()
    raw.update(
        {
            "duration": flow_stats.get("duration", 0),
            "protocol_type": flow_stats.get("protocol_type", "tcp"),
            "service": flow_stats.get("service", "other"),
            "flag": flow_stats.get("flag", "SF"),
            "src_bytes": flow_stats.get("src_bytes", 0),
            "dst_bytes": flow_stats.get("dst_bytes", 0),
            "count": flow_stats.get("count", 0),
            "srv_count": flow_stats.get("srv_count", 0),
            "serror_rate": flow_stats.get("serror_rate", 0),
            "rerror_rate": flow_stats.get("rerror_rate", 0),
            "same_srv_rate": flow_stats.get("same_srv_rate", 0),
            "is_guest_login": 1 if flow_stats.get("service") in {"ftp", "ftp_data"} else 0,
        }
    )
    normalized, _ = normalize_features(raw, meta=meta, strict=False)
    details = {
        "flow_key": flow_stats.get("flow_key"),
        "src_ip": flow_stats.get("src_ip"),
        "dst_ip": flow_stats.get("dst_ip"),
        "service": flow_stats.get("service"),
        "protocol_type": flow_stats.get("protocol_type"),
    }
    return normalized, details
