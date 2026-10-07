"""Minimal Python client for curral.

Only the standard library is needed for the HTTP side; pyarrow is needed for
query() (Arrow results), and pandas/polars only if you convert the table.

    from curral import Client

    c = Client("https://curral.example.com", token="curral_...")      # API key or OIDC token
    c = Client("http://127.0.0.1:8080", user="analyst", password="...")

    table = c.query("SELECT * FROM orders WHERE amount > $1", [100])  # pyarrow.Table
    df = table.to_pandas()          # or polars.from_arrow(table)
    rows = c.rows("SELECT id FROM orders LIMIT 5")                     # list of dicts
    print(c.dry_run("DELETE FROM orders"))                             # decision, tables...
"""

from __future__ import annotations

import base64
import io
import json
import ssl
import urllib.error
import urllib.request
import warnings
from typing import Any, Iterator, Sequence

__all__ = ["Client", "CurralError", "TruncatedResultWarning"]


class CurralError(Exception):
    """A request curral refused or failed. status/request_id help find it in the audit log."""

    def __init__(self, status: int, message: str, request_id: str | None):
        super().__init__(f"{status}: {message} (request {request_id})")
        self.status, self.message, self.request_id = status, message, request_id


class TruncatedResultWarning(UserWarning):
    """The result has exactly the server's row limit, so it may have been cut."""


class Client:
    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str | None = None,
        cafile: str | None = None,
        timeout: float | None = None,
    ):
        self.url = url.rstrip("/") + "/v1/query"
        self.database, self.timeout = database, timeout
        if token:
            self._auth = "Bearer " + token.strip()
        elif user is not None:
            cred = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
            self._auth = "Basic " + cred
        else:
            raise ValueError("pass token=... or user=/password=")
        self._ssl = ssl.create_default_context(cafile=cafile) if cafile else None

    # -- public API -----------------------------------------------------

    def query(self, sql: str, params: Sequence[Any] = (), *, database: str | None = None):
        """Run sql and return a pyarrow.Table (fastest path for large results)."""
        import pyarrow.ipc as ipc  # imported lazily: only this method needs it

        with self._post(sql, params, "arrow", database) as resp:
            body = resp.read()
            table = ipc.open_stream(io.BytesIO(body)).read_all()
            self._check_truncation(resp, table.num_rows)
            return table

    def rows(self, sql: str, params: Sequence[Any] = (), *, database: str | None = None) -> list[dict]:
        """Run sql and return the rows as dicts (NDJSON; fine for small results)."""
        return list(self.iter_rows(sql, params, database=database))

    def iter_rows(self, sql: str, params: Sequence[Any] = (), *, database: str | None = None) -> Iterator[dict]:
        """Stream rows as dicts without holding the whole result."""
        with self._post(sql, params, "ndjson", database) as resp:
            n = 0
            for line in resp:
                if line.strip():
                    n += 1
                    yield json.loads(line)
            self._check_truncation(resp, n)

    def dry_run(self, sql: str, params: Sequence[Any] = (), *, database: str | None = None) -> dict:
        """Inspection and policy decision for sql, without executing it."""
        with self._post(sql, params, "json", database, dry_run=True) as resp:
            return json.load(resp)

    # -- internals ------------------------------------------------------

    def _post(self, sql, params, fmt, database, dry_run=False):
        body = {"sql": sql, "params": list(params), "format": fmt, "dry_run": dry_run}
        if database or self.database:
            body["database"] = database or self.database
        req = urllib.request.Request(
            self.url,
            data=json.dumps(body).encode(),
            headers={"Authorization": self._auth, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            return urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                msg = json.loads(raw).get("error", raw.decode())
            except ValueError:
                msg = raw.decode(errors="replace")
            raise CurralError(e.code, msg, e.headers.get("X-Request-Id")) from None

    @staticmethod
    def _check_truncation(resp, rows: int) -> None:
        # Trailers (X-Curral-Error) are not visible to urllib; the row limit
        # is announced up front instead. A real failure mid-stream aborts the
        # connection, which surfaces as an exception while reading.
        limit = resp.headers.get("X-Curral-Max-Rows")
        if limit and rows >= int(limit):
            warnings.warn(
                f"result has {rows} rows, the server's row limit: it may be truncated "
                f"(request {resp.headers.get('X-Request-Id')})",
                TruncatedResultWarning,
                stacklevel=3,
            )
