from realtime.alerts import AlertPolicy


def test_alert_policy_severity_and_dedupe() -> None:
    policy = AlertPolicy(dedupe_window_sec=60)
    pred = {"label": "intrusion", "prediction": 1, "probabilities": {"intrusion": 0.92, "normal": 0.08}}
    details = {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "service": "http"}
    event = policy.build_event(pred, details, source="live")
    assert event is not None
    assert event["severity"] == "critical"
    duplicate = policy.build_event(pred, details, source="live")
    assert duplicate is None
