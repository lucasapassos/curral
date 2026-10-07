"""End-to-end check of the Python client against a running curral.

    CURRAL_URL=http://127.0.0.1:8080 uv run --with pyarrow --with pytest pytest clients/python
"""

import os
import warnings

import pytest

from curral import Client, CurralError, TruncatedResultWarning

URL = os.environ.get("CURRAL_URL", "http://127.0.0.1:8080")


def analyst():
    return Client(URL, user="analyst", password="analyst-pw")


def test_query_arrow():
    t = Client(URL, user="admin", password="admin-pw").query("SELECT id, amount FROM orders WHERE id < $1 ORDER BY id", [3])
    assert t.num_rows == 3
    assert t.column("id").to_pylist() == [0, 1, 2]
    assert str(t.schema.field("amount").type).startswith("decimal")


def test_rows_and_params():
    rows = analyst().rows("SELECT id, $1 AS tag FROM orders WHERE id < 2 ORDER BY id", ["x"])
    assert rows == [{"id": 0, "tag": "x"}, {"id": 1, "tag": "x"}]


def test_forbidden_and_bad_credentials():
    with pytest.raises(CurralError) as e:
        analyst().rows("SELECT * FROM salaries")
    assert e.value.status == 403 and e.value.request_id
    with pytest.raises(CurralError) as e:
        Client(URL, user="analyst", password="wrong").rows("SELECT 1")
    assert e.value.status == 401


def test_dry_run():
    d = analyst().dry_run("DELETE FROM orders")
    assert d["decision"] == "deny" and d["targets"] == ["sales.main.orders"]


def test_truncation_warning():
    # The example policy limits analysts to 10000 rows.
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        t = analyst().query("SELECT * FROM orders")
    assert t.num_rows == 10000
    assert any(issubclass(x.category, TruncatedResultWarning) for x in w)
