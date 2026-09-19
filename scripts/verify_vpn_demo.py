"""Browser acceptance for the local demo; start its loopback server first."""
import json
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1050})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto("http://127.0.0.1:8765", wait_until="networkidle")
        expect(page.get_by_role("button", name="Replay synthetic alert")).to_be_enabled()
        expect(page.locator("#approved-count")).to_have_text("2")
        page.get_by_label("Fictional device name").fill('<img src=x onerror=alert(1)>')
        page.get_by_role("button", name="Add demo device").click()
        assert page.locator("#device-list img").count() == 0
        page.get_by_role("button", name="Approve <img src=x onerror=alert(1)>", exact=True).click()
        expect(page.locator("#approved-count")).to_have_text("3")
        page.get_by_role("button", name="Revoke <img src=x onerror=alert(1)>", exact=True).click()
        expect(page.locator("#approved-count")).to_have_text("2")
        for state, label in [("failed", "Capture failed"), ("stale", "Capture stale"), ("idle", "Capture idle"), ("healthy", "Capture healthy")]:
            page.get_by_label("Explore a monitoring state").select_option(state)
            expect(page.locator("#health-label")).to_have_text(label)
            expect(page.locator("#device-list .revoked")).to_have_count(1)
        page.get_by_role("button", name="Replay synthetic alert").click()
        expect(page.locator("#alert-count")).to_have_text("1")
        expect(page.locator("#alerts")).to_contain_text("Demo restricted service access")
        with page.expect_download() as download:
            page.get_by_role("button", name="Export demo report").click()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            download.value.save_as(target)
            report = json.loads(target.read_text())
            assert report["mode"] == "demo-only"
            assert len(report["replayed_alerts"]) == 1
            assert report["devices"][-1]["state"] == "revoked"
        screenshot = Path(tempfile.gettempdir()) / "fusion-vpn-demo-desktop.png"
        page.screenshot(path=str(screenshot), full_page=True)
        page.get_by_role("button", name="Reset demo").click()
        expect(page.locator("#alert-count")).to_have_text("0")
        expect(page.locator("#device-list tr")).to_have_count(3)
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.screenshot(path=str(Path(tempfile.gettempdir()) / "fusion-vpn-demo-mobile.png"), full_page=True)
        page.keyboard.press("Tab")
        assert page.evaluate("document.activeElement !== document.body")
        page.route("**/evidence.json", lambda route: route.fulfill(status=404, body="missing"))
        page.reload(wait_until="networkidle")
        expect(page.locator("#replay")).to_be_disabled()
        expect(page.locator("#evidence-status")).to_contain_text("Evidence unavailable")
        page.unroute("**/evidence.json")
        page.route("**/evidence.json", lambda route: route.fulfill(json={
            "mode": "synthetic-offline", "positive_alert_count": 1,
            "negative_alert_count": 0, "alerts": [{}],
        }))
        page.reload(wait_until="networkidle")
        expect(page.locator("#replay")).to_be_disabled()
        expect(page.locator("#evidence-status")).to_contain_text("Evidence unavailable")
        assert not errors, errors
        browser.close()
        print(f"PASS: device lifecycle, text safety, four health states, replay, export, reset, mobile layout, keyboard focus, missing/malformed evidence. Screenshot: {screenshot}")


if __name__ == "__main__":
    main()
