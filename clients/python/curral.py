"""Minimal Python client for curral.

Only the standard library is needed for the HTTP side; pyarrow is needed for
query() (Arrow results), and pandas/polars only if you convert the table.

    from curral import Client

    c = Client("https://curral.example.com", token="curral_...")      # API key or OIDC token
    c = Client("http://127.0.0.1:8080", user="analyst", password="...")

    table = c.query("SELECT * FROM orders WHERE amount > $1", [100])  # pyarrow.Table
    df = table.to_pandas()          # or polars.from_arrow(table)
    rows = c.rows("SELECT id FROM orders LIMIT 5")                     # list of dicts
    sample = c.rows("SELECT * FROM orders", max_rows=100)             # at most 100 rows
    print(c.dry_run("DELETE FROM orders"))                             # decision, tables...

    # Semantic documents (/v1/docs, servers started with --docs-dir)
    notes = c.docs(table="orders")                                     # list of dicts
    hits = c.search_docs("monthly revenue per customer")["results"]    # best first
    d = c.create_doc({"header": {"title": "Revenue"}, "context": {"body": "..."}})
    d = c.patch_doc(d["id"], {"header": {"used_for": ["finance"]}}, if_match=d.etag)
    c.delete_doc(d["id"])
"""

from __future__ import annotations

import base64
import io
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
import warnings
from typing import Any, Iterator, Sequence

__all__ = ["Client", "CurralError", "Doc", "TruncatedResultWarning"]


class CurralError(Exception):
    """A request curral refused or failed. status/request_id help find it in the audit log."""

    def __init__(self, status: int, message: str, request_id: str | None):
        super().__init__(f"{status}: {message} (request {request_id})")
        self.status, self.message, self.request_id = status, message, request_id


class TruncatedResultWarning(UserWarning):
    """The result has exactly the server's row limit, so it may have been cut."""


class Doc(dict):
    """A semantic document; etag is its version, for if_match= on later writes."""

    etag: str | None = None


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
        self.base = url.rstrip("/")
        self.url = self.base + "/v1/query"
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

    def query(self, sql: str, params: Sequence[Any] = (), *, database: str | None = None, max_rows: int | None = None):
        """Run sql and return a pyarrow.Table (fastest path for large results)."""
        import pyarrow.ipc as ipc  # imported lazily: only this method needs it

        with self._post(sql, params, "arrow", database, max_rows=max_rows) as resp:
            body = resp.read()
            table = ipc.open_stream(io.BytesIO(body)).read_all()
            self._check_truncation(resp, table.num_rows, max_rows)
            return table

    def rows(self, sql: str, params: Sequence[Any] = (), *, database: str | None = None, max_rows: int | None = None) -> list[dict]:
        """Run sql and return the rows as dicts (NDJSON; fine for small results)."""
        return list(self.iter_rows(sql, params, database=database, max_rows=max_rows))

    def iter_rows(self, sql: str, params: Sequence[Any] = (), *, database: str | None = None, max_rows: int | None = None) -> Iterator[dict]:
        """Stream rows as dicts without holding the whole result."""
        with self._post(sql, params, "ndjson", database, max_rows=max_rows) as resp:
            n = 0
            for line in resp:
                if line.strip():
                    n += 1
                    yield json.loads(line)
            self._check_truncation(resp, n, max_rows)

    def dry_run(self, sql: str, params: Sequence[Any] = (), *, database: str | None = None, max_rows: int | None = None) -> dict:
        """Inspection and policy decision for sql, without executing it."""
        with self._post(sql, params, "json", database, dry_run=True, max_rows=max_rows) as resp:
            return json.load(resp)

    # -- semantic documents (/v1/docs) ----------------------------------

    def docs(self, *, table: str | None = None, schema: str | None = None, q: str | None = None, headers_only: bool = False) -> list[dict]:
        """Documents, most recently updated first; table/schema/q narrow the list,
        headers_only leaves out body and sqls."""
        query = {k: v for k, v in {"table": table, "schema": schema, "q": q}.items() if v}
        if headers_only:
            query["fields"] = "header"
        path = "/v1/docs" + ("?" + urllib.parse.urlencode(query) if query else "")
        with self._request("GET", path) as resp:
            return json.load(resp)["docs"]

    def search_docs(self, q: str, *, table: str | None = None, schema: str | None = None, limit: int | None = None, headers_only: bool = False) -> dict:
        """The documents that best fit the question q, best first:
        {"ranker", "results": [{"score", "judged", "doc"}], "below_threshold"?}."""
        body = {k: v for k, v in {"q": q, "table": table, "schema": schema, "limit": limit}.items() if v}
        if headers_only:
            body["fields"] = "header"
        with self._request("POST", "/v1/docs/search", body) as resp:
            return json.load(resp)

    def doc(self, doc_id: str) -> Doc:
        """One document, with its etag."""
        return self._doc("GET", doc_id)

    def create_doc(self, doc: dict) -> Doc:
        """Create a document ({"header": {...}, "context": {...}}); returns it with id and etag."""
        return self._doc("POST", None, doc)

    def update_doc(self, doc_id: str, doc: dict, *, if_match: str | None = None) -> Doc:
        """Replace a document's content. With if_match, fails (412) if it changed since."""
        return self._doc("PUT", doc_id, doc, if_match)

    def patch_doc(self, doc_id: str, patch: dict, *, if_match: str | None = None) -> Doc:
        """Apply a JSON merge patch (RFC 7396): None removes a field."""
        return self._doc("PATCH", doc_id, patch, if_match, "application/merge-patch+json")

    def delete_doc(self, doc_id: str, *, if_match: str | None = None) -> None:
        self._request("DELETE", self._doc_path(doc_id), if_match=if_match).close()

    # -- internals ------------------------------------------------------

    @staticmethod
    def _doc_path(doc_id: str | None) -> str:
        return "/v1/docs" + ("/" + urllib.parse.quote(doc_id, safe="") if doc_id else "")

    def _doc(self, method, doc_id, body=None, if_match=None, content_type="application/json") -> Doc:
        with self._request(method, self._doc_path(doc_id), body, if_match=if_match, content_type=content_type) as resp:
            d = Doc(json.load(resp))
            d.etag = resp.headers.get("ETag")
            return d

    def _post(self, sql, params, fmt, database, dry_run=False, max_rows=None):
        body = {"sql": sql, "params": list(params), "format": fmt, "dry_run": dry_run}
        if max_rows:
            body["max_rows"] = max_rows  # can only lower the server's limit
        if database or self.database:
            body["database"] = database or self.database
        return self._request("POST", "/v1/query", body)

    def _request(self, method, path, body=None, *, if_match=None, content_type="application/json"):
        headers = {"Authorization": self._auth}
        if body is not None:
            headers["Content-Type"] = content_type
        if if_match:
            headers["If-Match"] = if_match
        req = urllib.request.Request(
            self.base + path,
            data=None if body is None else json.dumps(body).encode(),
            headers=headers,
            method=method,
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
    def _check_truncation(resp, rows: int, asked: int | None = None) -> None:
        # Trailers (X-Curral-Error) are not visible to urllib; the row limit
        # is announced up front instead. A real failure mid-stream aborts the
        # connection, which surfaces as an exception while reading.
        limit = resp.headers.get("X-Curral-Max-Rows")
        if asked and limit and int(limit) == asked:
            return  # the caller asked for at most this many rows
        if limit and rows >= int(limit):
            warnings.warn(
                f"result has {rows} rows, the server's row limit: it may be truncated "
                f"(request {resp.headers.get('X-Request-Id')})",
                TruncatedResultWarning,
                stacklevel=3,
            )
