"""A failed write must never advance its publication checkpoint."""
import sqlite3

import httpx
import pytest

from voidsentinel import db


@pytest.mark.parametrize("fail", [False, True])
def test_remote_batch_commits_data_and_checkpoint_together(monkeypatch, fail):
    server = sqlite3.connect(":memory:")
    server.executescript("CREATE TABLE data(id INTEGER); CREATE TABLE progress(n INTEGER); INSERT INTO progress VALUES(0);")

    def post(url, *, headers, json, timeout):
        # Minimal Hrana server backed by SQLite. Evaluate the actual batch's
        # conditions, including its rollback branch, rather than mocking success.
        results, errors = [], []

        def condition(c):
            if c["type"] == "ok":
                return results[c["step"]] is not None
            if c["type"] == "not":
                return not condition(c["cond"])
            return all(condition(v) for v in c["conds"])

        for step in json["requests"][0]["batch"]["steps"]:
            result, error = None, None
            if not step.get("condition") or condition(step["condition"]):
                stmt = step["stmt"]
                args = [int(v["value"]) if v["type"] == "integer" else v.get("value") for v in stmt.get("args", [])]
                try:
                    cursor = server.execute(stmt["sql"], args)
                    result = {"affected_row_count": cursor.rowcount}
                except sqlite3.Error as exc:
                    error = {"message": str(exc)}
            results.append(result)
            errors.append(error)
        return httpx.Response(200, request=httpx.Request("POST", "https://database.test/v2/pipeline"), json={"results": [{"type": "ok", "response": {
            "type": "batch", "result": {"step_results": results, "step_errors": errors}}}]})

    monkeypatch.setattr(httpx, "post", post)
    remote = db.RemoteConnection(None)
    statements = [("INSERT INTO data(id) VALUES(?)", (42,)),
                  ("UPDATE missing_table SET n=1" if fail else "UPDATE progress SET n=1", ())]
    if fail:
        with pytest.raises(RuntimeError, match="missing_table"):
            remote.atomic_batch(statements)
    else:
        remote.atomic_batch(statements)
    assert server.execute("SELECT COUNT(*) FROM data").fetchone()[0] == (0 if fail else 1)
    assert server.execute("SELECT n FROM progress").fetchone()[0] == (0 if fail else 1)
    assert not server.in_transaction
    server.close()
