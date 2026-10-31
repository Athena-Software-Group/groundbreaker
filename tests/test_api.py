def test_healthz(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_auth_required():
    from conftest import anon_client

    anon = anon_client()
    r = anon.get("/api/cases")
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Basic")
    page = anon.get("/", follow_redirects=False)
    assert page.status_code == 303 and page.headers["location"].startswith("/login")


def test_case_trace_graph_and_orders_via_api(client, case):
    cid = case.id
    r = client.post(f"/api/cases/{cid}/trace", params={"mode": "fixture"})
    assert r.status_code == 200 and r.json()["status"] == "complete"
    run_id = r.json()["id"]

    g = client.get(f"/api/cases/{cid}/trace/{run_id}/graph").json()
    assert g["summary"]["nodes"] > 10
    assert {"ethereum", "tron", "bitcoin"} <= set(g["summary"]["chains"])
    # Cytoscape reserves `source`/`target`; our provenance field must not collide
    assert all("data_source" in e["data"] for e in g["elements"]["edges"])

    cands = client.get(f"/api/cases/{cid}/trace/{run_id}/freeze-candidates").json()
    assert cands and cands[0]["priority"] >= cands[-1]["priority"]

    r = client.post(f"/api/cases/{cid}/stop-orders")
    # the uncontacted targets only (app.blocks.freeze_board.generator_plan): never a second request to one already
    # contacted (KuCoin, Rainbet, SWFT); those come back in X-Aegis-Skipped
    assert r.status_code == 201 and len(r.json()) >= 2 and ":sent:" in r.headers["x-aegis-skipped"]
    oid = r.json()[0]["id"]
    r = client.patch(f"/api/cases/{cid}/stop-orders/{oid}", json={"status": "sent", "external_ref": "TCK-1"})
    assert r.json()["status"] == "sent" and r.json()["sent_at"]
    r = client.get(f"/api/cases/{cid}/stop-orders/{oid}/docx")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/vnd.openxmlformats")
    # exports land in the test temp dir, never in the repository
    from pathlib import Path

    from app import services

    repo_root = Path(__file__).resolve().parents[1]
    assert not services.EXPORT_DIR.resolve().is_relative_to(repo_root)
    assert list(services.EXPORT_DIR.glob("DEMO-2026-001_*.docx"))


def test_html_pages(client, case):
    assert client.get("/").status_code == 200
    page = client.get(f"/cases/{case.id}")
    assert page.status_code == 200
    assert "DEMO-2026-001" in page.text and "Exempla Holding AG" in page.text
    assert client.get("/cases/new").status_code == 403  # a case admin is not thereby a case creator


def test_every_case_tab_renders(client, case):
    from app.web.tabs import TABS

    for t in TABS:
        page = client.get(f"/cases/{case.id}", params={"tab": t.key})
        assert page.status_code == 200, t.key
        assert f'id="tab-{t.key}"' in page.text, t.key
    # fund flow carries the graph data and the vendored scripts; an unknown tab falls back to the first
    assert 'id="graph-data"' in client.get(f"/cases/{case.id}?tab=fund_flow").text
    assert 'id="tab-overview"' in client.get(f"/cases/{case.id}?tab=nope").text


def test_case_tab_labels(client, case):
    from app.web.tabs import TABS

    labels = {t.key: t.label for t in TABS}  # the keys (and so the URLs) stay; the visible names changed
    assert labels["authorities"] == "Authorities" and labels["assistant"] == "AI Assistant (Pythia)"
    page = client.get(f"/cases/{case.id}?tab=assistant").text
    assert 'data-tab="authorities">Authorities</a>' in page and 'data-tab="assistant">AI Assistant (Pythia)</a>' in page
    assert "stop orders</a>" not in page.split('class="case-tabs"')[1].split("</nav>")[0]


def test_basic_auth_against_users_on_api(basic_client, case):
    r = basic_client.get("/api/cases")
    assert r.status_code == 200 and case.reference in {c["reference"] for c in r.json()}
    # Basic is for the API only: pages still need a session
    assert basic_client.get("/", follow_redirects=False).status_code == 303
    basic_client.headers["Authorization"] = "Basic " + __import__("base64").b64encode(b"admin@tests.example:nope").decode()
    assert basic_client.get("/api/cases").status_code == 401


def test_feature_placeholder_routes_redirect_to_their_tab(client, case):
    for path, tab in (("trace", "fund_flow"), ("authorities", "authorities"), ("evidence", "evidence"),
                      ("team", "team"), ("notifications", "notifications"), ("assistant", "assistant")):
        r = client.get(f"/cases/{case.id}/{path}", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == f"/cases/{case.id}?tab={tab}", path
