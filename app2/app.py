#!/usr/bin/env python3
"""Local-only Python security training app with intentionally unsafe examples."""

from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sqlite3
from urllib.parse import parse_qs, urlsplit


HOST = "127.0.0.1"
PORT = 8002
PUBLIC_DIR = Path(__file__).parent / "public"


class DemoServer(HTTPServer):
    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.database = sqlite3.connect(":memory:")
        self.database.execute("CREATE TABLE items (name TEXT NOT NULL)")
        self.database.executemany(
            "INSERT INTO items (name) VALUES (?)",
            [("Notebook",), ("Pencil",), ("Backpack",)],
        )


class DemoHandler(BaseHTTPRequestHandler):
    def send_page(self, body: str, status: int = 200) -> None:
        page = f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Python Security Playground</title>
<body><h1>Python Security Playground</h1>{body}</body></html>"""
        encoded = page.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        request = urlsplit(self.path)
        params = parse_qs(request.query)

        if request.path == "/":
            self.send_page(
                '<p>A local Python app for security review practice.</p>'
                '<form action="/search"><label>Search products '
                '<input name="q"></label><button>Search</button></form>'
                '<form action="/read"><label>Read a file in public/ '
                '<input name="name" value="readme.txt"></label>'
                '<button>Read</button></form>'
                '<p>Use demo data on localhost only.</p>'
            )
            return

        if request.path == "/search":
            term = params.get("q", [""])[0]
            # Training flaw: user input is joined into SQL instead of bound as a parameter.
            sql = "SELECT name FROM items WHERE name LIKE '%" + term + "%'"
            try:
                rows = self.server.database.execute(sql).fetchall()
            except sqlite3.Error:
                self.send_page("<p>Invalid query.</p>", status=400)
                return
            results = "".join(f"<li>{escape(row[0])}</li>" for row in rows)
            self.send_page(f"<h2>Ket qua</h2><ul>{results}</ul>")
            return

        if request.path == "/read":
            filename = params.get("name", ["readme.txt"])[0]
            # Training flaw: the requested path is not checked to stay under PUBLIC_DIR.
            file_path = PUBLIC_DIR / filename
            try:
                content = file_path.read_text(encoding="utf-8")[:4000]
            except (OSError, UnicodeError):
                self.send_page("<p>Could not read the file.</p>", status=404)
                return
            self.send_page(f"<pre>{escape(content)}</pre>")
            return

        self.send_page("<p>Page not found.</p>", status=404)


if __name__ == "__main__":
    print(f"Python demo running at http://{HOST}:{PORT} (press Ctrl+C to stop)")
    try:
        DemoServer((HOST, PORT), DemoHandler).serve_forever()
    except KeyboardInterrupt:
        print("\nPython demo stopped.")
