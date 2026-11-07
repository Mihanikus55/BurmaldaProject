import re

from burmalda.crypto import load_keys, public_keys
from burmalda.observer import create_observer


def test_dashboard_session_csrf_and_no_external_assets(tmp_path):
    signing, encryption = load_keys(tmp_path / "observer")
    app = create_observer(tmp_path, {"observer": public_keys(signing, encryption)})
    with app.test_client() as client:
        assert client.get("/api/state").status_code == 401
        response = client.get("/")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "https://" not in html and "cdn." not in html
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        csrf = re.search(r'name="demo-csrf" content="([^"]+)"', html).group(1)
        assert client.post("/api/actions/reset", json={}).status_code == 403
        assert client.post("/api/actions/reset", json={}, headers={"X-Demo-CSRF": csrf, "Origin": "http://evil.test"}).status_code == 403
        assert client.get("/", headers={"Host": "evil.test"}).status_code == 403
