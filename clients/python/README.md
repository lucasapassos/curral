# curral Python client

One file, standard library only for HTTP; `pyarrow` for Arrow results.

```python
from curral import Client, CurralError

c = Client("https://curral.example.com", token="curral_...")   # API key or OIDC ID token
# c = Client("http://127.0.0.1:8080", user="analyst", password="...")

t = c.query("SELECT * FROM orders WHERE amount > $1", [100])     # pyarrow.Table (Arrow)
df = t.to_pandas()                                               # or polars.from_arrow(t)

for row in c.iter_rows("SELECT id, amount FROM orders"):         # dicts, streamed (NDJSON)
    ...

print(c.dry_run("DELETE FROM orders"))   # decision, tables, targets, limits; nothing runs
```

Semantic documents (`/v1/docs`, on servers started with `--docs-dir`):

```python
notes = c.docs(table="orders", q="revenue")          # list of dicts; headers_only=True skips bodies
d = c.create_doc({"header": {"title": "Revenue"}, "context": {"body": "...", "tables": ["sales.main.orders"]}})
d = c.patch_doc(d["id"], {"header": {"used_for": ["finance"]}}, if_match=d.etag)   # merge patch
d = c.update_doc(d["id"], {**c.doc(d["id"]), "context": {"body": "rewritten"}})    # full replace
c.delete_doc(d["id"])
```

- **Versions:** `doc()`, `create_doc()`, `update_doc()` and `patch_doc()`
  return a `Doc` (a dict) whose `etag` can go in `if_match=`; a write over a
  newer version then fails with 412 instead of overwriting it.

- **Errors:** a refused or failed request raises `CurralError` with
  `status` and `request_id`. The `request_id` is the one in the audit log.
- **Row limit:** if the result has exactly the server's row limit
  (`X-Curral-Max-Rows`), a `TruncatedResultWarning` is issued.
- **Mid-stream failures:** the server aborts the connection, so reading
  raises an exception instead of returning a short result.
- **Custom CA:** use `cafile=` for a server with its own CA.

Tests (need a running curral with the example config):

```sh
CURRAL_URL=http://127.0.0.1:8080 uv run --no-project --with pyarrow --with pytest pytest clients/python
```
