from scripts.build_vpn_demo import build_evidence


def test_demo_uses_real_signature_engine_with_positive_and_negative_controls():
    evidence = build_evidence()
    assert evidence['mode'] == 'synthetic-offline'
    assert evidence['positive_alert_count'] == 1
    assert evidence['negative_alert_count'] == 0
    assert evidence['alerts'][0]['rule_name'] == 'Demo restricted service access'
    assert evidence['alerts'][0]['engine'] == 'signature'
