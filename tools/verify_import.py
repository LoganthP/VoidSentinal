"""Verify upload -> validation -> import -> dashboard using the deployed protocol.

Local:  python tools/verify_import.py path/to/archive.zip
Remote: python tools/verify_import.py path/to/archive.zip --url https://example.vercel.app --username admin
Remote passwords are prompted or read from VS_VERIFY_PASSWORD, never printed.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--url")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--dataset-id", type=int, help="Resume and verify an existing import instead of uploading again")
    args = parser.parse_args()
    temporary = None
    if args.url:
        import httpx
        client = httpx.Client(base_url=args.url, timeout=310,
                              headers=json.loads(os.environ.get("VS_VERIFY_HEADERS", "{}")))
        password = os.environ.get("VS_VERIFY_PASSWORD") or getpass.getpass("Admin password: ")
    else:
        temporary = tempfile.TemporaryDirectory(prefix="vs-verification-", ignore_cleanup_errors=True)
        os.environ["VS_DATA_DIR"] = temporary.name
        os.environ["VS_ADMIN_PASSWORD"] = "local-verification-password"
        os.environ["VS_ANALYST_PASSWORD"] = "local-verification-analyst-password"
        os.environ.pop("VERCEL", None)
        os.environ.pop("TURSO_DATABASE_URL", None)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
        from fastapi.testclient import TestClient
        from voidsentinel.api import app
        client = TestClient(app)
        password = os.environ["VS_ADMIN_PASSWORD"]

    def call(method, path, **kw):
        r = client.request(method, "/api" + path, headers={"X-VS-Request": "1"}, **kw)
        if not r.is_success:
            raise RuntimeError(f"{method} {path}: {r.status_code} {r.text[:500]}")
        return r.json()

    started = time.monotonic()
    with client:
        call("POST", "/auth/login", json={"username": args.username, "password": password})
        if args.dataset_id:
            ds_id = args.dataset_id
        else:
            size = args.archive.stat().st_size
            job = call("POST", "/datasets/uploads", json={"filename": args.archive.name, "size": size})
            token = job["token"]
            with args.archive.open("rb") as fh:
                n = 0
                while chunk := fh.read(job["chunk_bytes"]):
                    call("PUT", f"/datasets/uploads/{token}/chunks/{n}", content=chunk)
                    n += 1
            print(f"Uploaded {size:,} bytes in {n} chunks", flush=True)
            call("POST", f"/datasets/uploads/{token}/complete")
            status = call("POST", f"/datasets/uploads/{token}/process")
            assert status["state"] == "ready", status
            report = status["report"]
            print(f"Validated {report['accepted_rows']:,} accepted rows, {report['rejected_rows']:,} rejected", flush=True)
            dataset = call("POST", "/datasets/import", json={"token": token, "name": args.archive.stem})
            ds_id = dataset["id"]
        while True:
            call("POST", f"/datasets/{ds_id}/process")
            dataset = call("GET", f"/datasets/{ds_id}")
            print(f"{dataset['stage']} ({dataset['progress']:.0%})", flush=True)
            if dataset["status"] != "importing":
                break
        assert dataset["status"] == "ready", dataset
        scope = f"ds:{ds_id}"
        overview = call("GET", f"/overview?scope={scope}")
        assert overview["sessions"]["total"] == dataset["sessions"]
        sessions = call("GET", f"/sessions?scope={scope}&limit=5")
        alerts = call("GET", f"/alerts?scope={scope}&status=all&limit=5")
        assert sessions["items"] and alerts["items"]
        sid = next((a["session_id"] for a in alerts["items"] if a.get("session_id")), sessions["items"][0]["id"])
        detail = call("GET", f"/sessions/{sid}")
        assert detail["events"]
        model = call("GET", f"/ml/status?scope={scope}")
        if dataset["sessions"] >= model["min_train"]:
            assert model["active_version"] and model["scored_sessions"] == dataset["sessions"], model
        print(json.dumps({k: dataset[k] for k in ("id", "events", "sessions", "alerts", "duplicate_rows")}), flush=True)
        print(f"Overview, sessions, alert evidence and anomaly model verified in {time.monotonic() - started:.1f}s", flush=True)
    if temporary:
        temporary.cleanup()


if __name__ == "__main__":
    main()
