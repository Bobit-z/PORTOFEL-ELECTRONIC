import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import urllib.parse
import webbrowser
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path


IS_CLOUD = "PORT" in os.environ
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "5000"))
OPEN_BROWSER = os.environ.get("OPEN_BROWSER", "0" if IS_CLOUD else "1") == "1"
DATA_FILE = Path(__file__).with_name("wallet_secure_data.json")
SESSIONS = {}
ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")


def now_text():
    return datetime.now().strftime("%d.%m.%Y %H:%M:%S")


def hash_secret(secret, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 150_000)
    return base64.b64encode(salt + digest).decode("ascii")


def verify_secret(secret, stored):
    raw = base64.b64decode(stored.encode("ascii"))
    salt, old_digest = raw[:16], raw[16:]
    new_digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 150_000)
    return hmac.compare_digest(old_digest, new_digest)


def new_address():
    return "0x" + secrets.token_hex(20)


def new_tx_hash():
    return "0x" + secrets.token_hex(32)


def default_data():
    return {
        "clients": [
            {"id": "ana", "name": "Ana", "password_hash": hash_secret("1234")},
            {"id": "bogdan", "name": "Bogdan", "password_hash": hash_secret("2222")},
            {"id": "magazin", "name": "Magazin", "password_hash": hash_secret("9999")},
        ],
        "wallets": [
            {
                "id": "w_ana",
                "owner_id": "ana",
                "label": "Portofel principal Ana",
                "address": "0xA100000000000000000000000000000000000001",
                "unlock_hash": hash_secret("1234"),
                "balance": 250.0,
                "primary": True,
                "deleted": False,
            },
            {
                "id": "w_bogdan",
                "owner_id": "bogdan",
                "label": "Portofel principal Bogdan",
                "address": "0xB200000000000000000000000000000000000002",
                "unlock_hash": hash_secret("2222"),
                "balance": 140.0,
                "primary": True,
                "deleted": False,
            },
            {
                "id": "w_magazin",
                "owner_id": "magazin",
                "label": "Portofel Magazin",
                "address": "0xC300000000000000000000000000000000000003",
                "unlock_hash": hash_secret("9999"),
                "balance": 500.0,
                "primary": True,
                "deleted": False,
            },
        ],
        "transactions": [],
    }


def load_data():
    if DATA_FILE.exists():
        with DATA_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    data = default_data()
    save_data(data)
    return data


def save_data(data):
    with DATA_FILE.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def esc(value):
    return html.escape(str(value), quote=True)


def money(value):
    return f"{float(value):.6f} vETH"


def short_address(address):
    if len(address) <= 14:
        return address
    return f"{address[:6]}...{address[-4:]}"


def find_client(data, client_id):
    return next((c for c in data["clients"] if c["id"] == client_id), None)


def find_wallet(data, wallet_id):
    return next((w for w in data["wallets"] if w["id"] == wallet_id), None)


def find_wallet_by_address(data, address):
    normalized = address.strip().lower()
    return next((w for w in data["wallets"] if w["address"].lower() == normalized), None)


def wallets_for(data, client_id, include_deleted=False):
    items = [w for w in data["wallets"] if w["owner_id"] == client_id]
    return items if include_deleted else [w for w in items if not w.get("deleted")]


def tx_url(tx_hash):
    return f"https://sepolia.etherscan.io/tx/{urllib.parse.quote(tx_hash)}"


def qr_url(tx_hash):
    return "https://api.qrserver.com/v1/create-qr-code/?size=130x130&data=" + urllib.parse.quote(tx_url(tx_hash))


def pdf_bytes(text):
    lines = text.splitlines()
    content = "BT /F1 12 Tf 50 780 Td " + " ".join(
        f"({line.replace(chr(92), chr(92)*2).replace('(', chr(92)+'(').replace(')', chr(92)+')')}) Tj 0 -18 Td"
        for line in lines
    ) + " ET"
    stream = content.encode("latin-1", errors="replace")
    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n",
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
        b"5 0 obj << /Length " + str(len(stream)).encode() + b" >> stream\n" + stream + b"\nendstream endobj\n",
    ]
    pdf = b"%PDF-1.4\n"
    offsets = []
    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj
    xref = len(pdf)
    pdf += b"xref\n0 6\n0000000000 65535 f \n"
    for offset in offsets:
        pdf += f"{offset:010d} 00000 n \n".encode()
    pdf += b"trailer << /Size 6 /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF"
    return pdf


STYLE = """
<style>
:root{--bg:#f4f7fb;--panel:#fff;--text:#172033;--muted:#627084;--line:#d7deea;--blue:#1769ff;--blue2:#0c4ec2;--green:#067647;--red:#b42318;--amber:#a15c00;--shadow:0 14px 34px rgba(31,42,68,.11)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
.shell{min-height:100vh;display:grid;grid-template-columns:250px 1fr}aside{background:#111827;color:#fff;padding:22px;display:flex;flex-direction:column;gap:18px}.brand strong{display:block;font-size:20px;margin-bottom:6px}.brand span{color:#b8c3d4;font-size:13px;line-height:1.4}
nav{display:grid;gap:8px}nav a{border-radius:8px;padding:12px;color:#dce5f2}nav a:hover{background:#1f2a44;color:#fff;text-decoration:none}main{padding:28px;display:grid;gap:18px;align-content:start}
h1,h2,h3,p{margin:0}h1{font-size:28px}h2{font-size:19px}.muted{color:var(--muted);line-height:1.45}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:16px}.span4{grid-column:span 4}.span8{grid-column:span 8}.span12{grid-column:span 12}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px;box-shadow:var(--shadow)}form{display:grid;gap:12px}label{display:grid;gap:6px;font-size:14px;font-weight:700;color:#334155}input,select{width:100%;border:1px solid var(--line);border-radius:8px;padding:11px 12px;background:#fff;color:var(--text);font:inherit}
input:focus,select:focus{outline:3px solid rgba(23,105,255,.14);border-color:var(--blue)}.btn{min-height:40px;border:0;border-radius:8px;padding:10px 13px;color:#fff;background:var(--blue);font-weight:700;cursor:pointer;display:inline-flex;justify-content:center;align-items:center}.btn:hover{background:var(--blue2);text-decoration:none}.secondary{color:var(--text);background:#edf2f7;border:1px solid var(--line)}.secondary:hover{background:#e2e8f0}.danger{background:var(--red)}.green{background:var(--green)}
.actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.wallet-list{display:grid;gap:12px}.wallet{display:grid;gap:10px;border:1px solid var(--line);border-radius:8px;padding:14px;background:#fbfcff}.wallet-top{display:flex;justify-content:space-between;gap:10px;align-items:start}.balance{font-size:26px;font-weight:800}.address{overflow-wrap:anywhere;font-family:Consolas,monospace;font-size:13px;color:#42526b}.tag{display:inline-flex;width:fit-content;border-radius:999px;padding:5px 9px;font-size:12px;font-weight:700;background:#eef4ff;color:#0b54c8}.tag.green{background:#e8f7ef;color:var(--green)}.tag.red{background:#ffebe9;color:var(--red)}.tag.amber{background:#fff3da;color:var(--amber)}.flash{border:1px solid #f2c94c;background:#fff9e6;color:#5c4200;padding:12px;border-radius:8px}table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:#475569;font-size:13px}.qr{width:92px;height:92px;border:1px solid var(--line);border-radius:8px;background:#fff}.login{max-width:440px;margin:8vh auto}
@media(max-width:920px){.shell{grid-template-columns:1fr}aside{position:sticky;top:0;z-index:5}nav{grid-template-columns:repeat(4,1fr)}main{padding:18px}.span4,.span8{grid-column:span 12}}
</style>
"""


class App(BaseHTTPRequestHandler):
    def send_html(self, body, title="Wallet EL", status=200):
        data = self.session
        client = data.get("client")
        flash = data.pop("flash", "")
        self.set_session(data)
        flash_html = f"<div class='flash'>{esc(flash)}</div>" if flash else ""
        if client:
            html_page = f"""<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>{STYLE}</head><body><div class="shell"><aside><div class="brand"><strong>Wallet EL</strong><span>Client: {esc(client["name"])}<br>Portofel local securizat demo</span></div><nav><a href="/dashboard">Dashboard</a><a href="/transfer">Transfer</a><a href="/history">Istoric</a><a href="/logout">Log out</a></nav></aside><main>{flash_html}{body}</main></div></body></html>"""
        else:
            html_page = f"""<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>{STYLE}</head><body><main class="login">{flash_html}{body}</main></body></html>"""
        raw = html_page.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self' https://api.qrserver.com; style-src 'unsafe-inline'; img-src 'self' https://api.qrserver.com; form-action 'self'; base-uri 'self'")
        self.end_headers()
        self.wfile.write(raw)

    def redirect(self, path):
        self.send_response(303)
        self.send_header("Location", path)
        self.end_headers()

    def send_download(self, content, filename, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f"attachment; filename={filename}")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def parse_form(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        values = urllib.parse.parse_qs(body)
        return {k: v[0] for k, v in values.items()}

    def get_session_id(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        sid = jar.get("sid")
        if sid and sid.value in SESSIONS:
            return sid.value
        sid = secrets.token_urlsafe(32)
        SESSIONS[sid] = {"csrf": secrets.token_urlsafe(24)}
        return sid

    @property
    def session(self):
        if not hasattr(self, "_sid"):
            self._sid = self.get_session_id()
        return SESSIONS.setdefault(self._sid, {"csrf": secrets.token_urlsafe(24)})

    def set_session(self, data):
        SESSIONS[self._sid] = data
        morsel = cookies.SimpleCookie()
        morsel["sid"] = self._sid
        morsel["sid"]["httponly"] = True
        morsel["sid"]["samesite"] = "Strict"
        morsel["sid"]["path"] = "/"
        self.extra_cookie = morsel.output(header="").strip()

    def end_headers(self):
        if hasattr(self, "_sid"):
            morsel = cookies.SimpleCookie()
            morsel["sid"] = self._sid
            morsel["sid"]["httponly"] = True
            morsel["sid"]["samesite"] = "Strict"
            morsel["sid"]["path"] = "/"
            self.send_header("Set-Cookie", morsel.output(header="").strip())
        super().end_headers()

    def flash(self, text):
        data = self.session
        data["flash"] = text
        self.set_session(data)

    def current(self):
        data = load_data()
        client_id = self.session.get("client_id")
        client = find_client(data, client_id) if client_id else None
        if client:
            self.session["client"] = {"id": client["id"], "name": client["name"]}
        return data, client

    def require_login(self):
        data, client = self.current()
        if not client:
            self.redirect("/login")
            return None, None
        return data, client

    def csrf_input(self):
        return f'<input type="hidden" name="csrf" value="{esc(self.session["csrf"])}">'

    def check_csrf(self, form):
        return hmac.compare_digest(form.get("csrf", ""), self.session.get("csrf", ""))

    def is_unlocked(self, wallet_id):
        return wallet_id in self.session.get("unlocked", [])

    def do_GET(self):
        _ = self.session
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            self.redirect("/dashboard" if self.session.get("client_id") else "/login")
        elif path == "/login":
            self.login_page()
        elif path == "/logout":
            SESSIONS[self._sid] = {"csrf": secrets.token_urlsafe(24)}
            self.redirect("/login")
        elif path == "/dashboard":
            self.dashboard()
        elif path == "/transfer":
            self.transfer_page()
        elif path == "/history":
            self.history_page()
        elif path.startswith("/wallet/") and path.endswith("/edit"):
            self.edit_wallet(path.split("/")[2])
        elif path.startswith("/wallet/") and path.endswith("/export.json"):
            self.export_json(path.split("/")[2])
        elif path.startswith("/wallet/") and path.endswith("/export.pdf"):
            self.export_pdf(path.split("/")[2])
        else:
            self.send_html("<section class='panel'><h1>404</h1><p>Pagina nu exista.</p></section>", "404", 404)

    def do_POST(self):
        _ = self.session
        path = urllib.parse.urlparse(self.path).path
        form = self.parse_form()
        if path != "/login" and not self.check_csrf(form):
            self.flash("Cerere blocata: token de securitate invalid.")
            self.redirect("/dashboard")
        elif path == "/login":
            self.login_post(form)
        elif path == "/wallet/add":
            self.add_wallet(form)
        elif path.startswith("/wallet/") and path.endswith("/unlock"):
            self.unlock_wallet(path.split("/")[2], form)
        elif path.startswith("/wallet/") and path.endswith("/delete"):
            self.delete_wallet(path.split("/")[2])
        elif path.startswith("/wallet/") and path.endswith("/primary"):
            self.primary_wallet(path.split("/")[2])
        elif path.startswith("/wallet/") and path.endswith("/edit"):
            self.edit_wallet_post(path.split("/")[2], form)
        elif path == "/deposit":
            self.deposit(form)
        elif path == "/transfer":
            self.transfer_post(form)
        else:
            self.redirect("/dashboard")

    def login_page(self):
        data = load_data()
        opts = "".join(f"<option value='{esc(c['id'])}'>{esc(c['name'])} ({esc(c['id'])})</option>" for c in data["clients"])
        body = f"""<section class="panel"><h1>Log in</h1><form method="post"><label>Client<select name="client_id">{opts}</select></label><label>Parola client<input type="password" name="password" required></label><button class="btn" type="submit">Log in</button></form></section>"""
        self.send_html(body, "Log in")

    def login_post(self, form):
        data = load_data()
        client = find_client(data, form.get("client_id", "").strip().lower())
        if client and verify_secret(form.get("password", ""), client["password_hash"]):
            SESSIONS[self._sid] = {"csrf": secrets.token_urlsafe(24), "client_id": client["id"], "client": {"id": client["id"], "name": client["name"]}, "unlocked": []}
            self.flash("Autentificare reusita.")
            self.redirect("/dashboard")
        else:
            self.flash("Client sau parola gresita.")
            self.redirect("/login")

    def dashboard(self):
        data, client = self.require_login()
        if not client:
            return
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("q", [""])[0].strip().lower()
        wallets = wallets_for(data, client["id"])
        if q:
            wallets = [w for w in wallets if q in w["label"].lower() or q in w["address"].lower()]
        total = sum(w["balance"] for w in wallets_for(data, client["id"]))
        cards = ""
        for w in wallets:
            lock = "<span class='tag green'>unlocked</span>" if self.is_unlocked(w["id"]) else "<span class='tag red'>locked</span>"
            primary = "<span class='tag amber'>principal</span>" if w.get("primary") else ""
            cards += f"""<article class="wallet"><div class="wallet-top"><div><h3>{esc(w['label'])}</h3><p class="address">{esc(w['address'])}</p></div><div class="actions">{primary}{lock}</div></div><div class="balance">{money(w['balance'])}</div><div class="actions"><form method="post" action="/wallet/{esc(w['id'])}/unlock">{self.csrf_input()}<input name="unlock_key" type="password" placeholder="cheie privata/parola" required><button class="btn green" type="submit">Unlock</button></form><a class="btn secondary" href="/wallet/{esc(w['id'])}/edit">Editare</a><a class="btn secondary" href="/wallet/{esc(w['id'])}/export.json">JSON</a><a class="btn secondary" href="/wallet/{esc(w['id'])}/export.pdf">PDF</a><form method="post" action="/wallet/{esc(w['id'])}/primary">{self.csrf_input()}<button class="btn secondary" type="submit">Stea principal</button></form><form method="post" action="/wallet/{esc(w['id'])}/delete">{self.csrf_input()}<button class="btn danger" type="submit">Sterge</button></form></div></article>"""
        options = "".join(f"<option value='{esc(w['id'])}'>{esc(w['label'])}</option>" for w in wallets_for(data, client["id"]))
        body = f"""<div class="actions" style="justify-content:space-between"><div><h1>Portofelele mele</h1><p class="muted">Total virtual: {money(total)}</p></div><form method="get" action="/dashboard" class="actions"><input name="q" value="{esc(q)}" placeholder="Cauta portofel sau adresa"><button class="btn secondary" type="submit">Cauta</button></form></div><section class="grid"><div class="panel span8"><h2>Lista portofele</h2><div class="wallet-list">{cards or "<p class='muted'>Nu ai portofele gasite.</p>"}</div></div><div class="panel span4"><h2>Adauga portofel</h2><form method="post" action="/wallet/add">{self.csrf_input()}<label>Nume portofel<input name="label" required></label><label>Adresa existenta optionala<input name="address" placeholder="0x..."></label><label>Cheie privata/parola unlock<input name="unlock_key" type="password" required></label><button class="btn" type="submit">Adauga</button></form></div><div class="panel span4"><h2>Alimentare Sepolia demo</h2><form method="post" action="/deposit">{self.csrf_input()}<label>Portofel<select name="wallet_id">{options}</select></label><label>Suma vETH<input name="amount" type="number" min="0.0001" step="0.0001" required></label><label>Tx hash Sepolia optional<input name="tx_hash" placeholder="0x..."></label><button class="btn green" type="submit">Adauga din Sepolia</button></form></div></section>"""
        self.send_html(body, "Dashboard")

    def add_wallet(self, form):
        data, client = self.require_login()
        if not client:
            return
        label = form.get("label", "").strip()
        address = form.get("address", "").strip() or new_address()
        key = form.get("unlock_key", "")
        if not label or len(key) < 4 or not ETH_ADDRESS_RE.match(address):
            self.flash("Date invalide. Adresa trebuie sa fie 0x + 40 caractere hex, cheia minim 4 caractere.")
        else:
            existing = find_wallet_by_address(data, address)
            if existing and existing["owner_id"] != client["id"]:
                self.flash("Adresa exista deja la alt client.")
            elif existing:
                existing["deleted"] = False
                existing["label"] = label
                existing["unlock_hash"] = hash_secret(key)
                self.flash("Portofel readaugat dupa adresa.")
            else:
                data["wallets"].append({"id": "w_" + secrets.token_hex(8), "owner_id": client["id"], "label": label, "address": address, "unlock_hash": hash_secret(key), "balance": 0.0, "primary": not wallets_for(data, client["id"]), "deleted": False})
                self.flash("Portofel adaugat.")
            save_data(data)
        self.redirect("/dashboard")

    def unlock_wallet(self, wallet_id, form):
        data, client = self.require_login()
        if not client:
            return
        w = find_wallet(data, wallet_id)
        if w and w["owner_id"] == client["id"] and verify_secret(form.get("unlock_key", ""), w["unlock_hash"]):
            unlocked = set(self.session.get("unlocked", []))
            unlocked.add(wallet_id)
            self.session["unlocked"] = sorted(unlocked)
            self.flash("Portofel unlocked.")
        else:
            self.flash("Cheie gresita.")
        self.redirect("/dashboard")

    def delete_wallet(self, wallet_id):
        data, client = self.require_login()
        if client:
            w = find_wallet(data, wallet_id)
            if w and w["owner_id"] == client["id"]:
                w["deleted"] = True
                w["primary"] = False
                save_data(data)
                self.flash("Portofel sters. Il poti readauga dupa adresa.")
        self.redirect("/dashboard")

    def primary_wallet(self, wallet_id):
        data, client = self.require_login()
        if client:
            w = find_wallet(data, wallet_id)
            if w and w["owner_id"] == client["id"] and not w.get("deleted"):
                for item in wallets_for(data, client["id"], True):
                    item["primary"] = False
                w["primary"] = True
                save_data(data)
                self.flash("Portofel principal setat.")
        self.redirect("/dashboard")

    def edit_wallet(self, wallet_id):
        data, client = self.require_login()
        if not client:
            return
        w = find_wallet(data, wallet_id)
        if not w or w["owner_id"] != client["id"]:
            self.redirect("/dashboard")
            return
        body = f"""<section class="panel"><h1>Editare portofel</h1><form method="post" action="/wallet/{esc(wallet_id)}/edit">{self.csrf_input()}<label>Nume<input name="label" value="{esc(w['label'])}" required></label><label>Adresa<input name="address" value="{esc(w['address'])}" required></label><label>Cheie noua optionala<input name="unlock_key" type="password"></label><button class="btn" type="submit">Salveaza</button><a class="btn secondary" href="/dashboard">Inapoi</a></form></section>"""
        self.send_html(body, "Editare")

    def edit_wallet_post(self, wallet_id, form):
        data, client = self.require_login()
        if client:
            w = find_wallet(data, wallet_id)
            address = form.get("address", "").strip()
            if w and w["owner_id"] == client["id"] and ETH_ADDRESS_RE.match(address):
                w["label"] = form.get("label", w["label"]).strip()
                w["address"] = address
                if form.get("unlock_key", ""):
                    w["unlock_hash"] = hash_secret(form["unlock_key"])
                save_data(data)
                self.flash("Portofel editat.")
            else:
                self.flash("Date invalide.")
        self.redirect("/dashboard")

    def deposit(self, form):
        data, client = self.require_login()
        if not client:
            return
        w = find_wallet(data, form.get("wallet_id", ""))
        try:
            amount = float(form.get("amount", "0").replace(",", "."))
        except ValueError:
            amount = 0
        tx_hash = form.get("tx_hash", "").strip() or new_tx_hash()
        if not w or w["owner_id"] != client["id"] or amount <= 0 or not TX_HASH_RE.match(tx_hash):
            self.flash("Alimentare invalida.")
        else:
            w["balance"] = round(w["balance"] + amount, 6)
            data["transactions"].append({"id": "tx_" + secrets.token_hex(8), "type": "Sepolia deposit", "from": "Sepolia faucet/demo", "to": w["address"], "amount": amount, "tx_hash": tx_hash, "date": now_text(), "client_id": client["id"]})
            save_data(data)
            self.flash("Fonduri virtuale adaugate din Sepolia demo.")
        self.redirect("/dashboard")

    def transfer_page(self):
        data, client = self.require_login()
        if not client:
            return
        own = wallets_for(data, client["id"])
        all_wallets = [w for w in data["wallets"] if not w.get("deleted")]
        body = f"""<section class="panel"><h1>Transfer</h1><p class="muted">Transferul merge doar daca portofelul sursa este unlocked.</p><form method="post" action="/transfer">{self.csrf_input()}<label>Din portofel<select name="source_wallet_id">{''.join(f"<option value='{esc(w['id'])}'>{esc(w['label'])} - {money(w['balance'])}</option>" for w in own)}</select></label><label>Catre portofel<select name="dest_address">{''.join(f"<option value='{esc(w['address'])}'>{esc(w['label'])} - {esc(short_address(w['address']))}</option>" for w in all_wallets)}</select></label><label>Suma vETH<input name="amount" type="number" min="0.0001" step="0.0001" required></label><button class="btn" type="submit">Trimite bani virtuali</button></form></section>"""
        self.send_html(body, "Transfer")

    def transfer_post(self, form):
        data, client = self.require_login()
        if not client:
            return
        source = find_wallet(data, form.get("source_wallet_id", ""))
        dest = find_wallet_by_address(data, form.get("dest_address", ""))
        try:
            amount = float(form.get("amount", "0").replace(",", "."))
        except ValueError:
            amount = 0
        if not source or source["owner_id"] != client["id"]:
            self.flash("Portofel sursa invalid.")
        elif not self.is_unlocked(source["id"]):
            self.flash("Portofelul sursa trebuie unlocked.")
        elif not dest or dest.get("deleted"):
            self.flash("Adresa destinatie nu exista.")
        elif source["id"] == dest["id"]:
            self.flash("Nu poti trimite catre acelasi portofel.")
        elif amount <= 0 or source["balance"] < amount:
            self.flash("Suma invalida sau sold insuficient.")
        else:
            source["balance"] = round(source["balance"] - amount, 6)
            dest["balance"] = round(dest["balance"] + amount, 6)
            data["transactions"].append({"id": "tx_" + secrets.token_hex(8), "type": "Transfer local", "from": source["address"], "to": dest["address"], "amount": amount, "tx_hash": new_tx_hash(), "date": now_text(), "client_id": client["id"]})
            save_data(data)
            self.flash("Transfer realizat. QR-ul este in istoric.")
        self.redirect("/transfer")

    def history_page(self):
        data, client = self.require_login()
        if not client:
            return
        addresses = {w["address"] for w in wallets_for(data, client["id"], True)}
        rows = ""
        for tx in reversed(data["transactions"]):
            if tx["from"] in addresses or tx["to"] in addresses or tx.get("client_id") == client["id"]:
                rows += f"""<tr><td>{esc(tx['date'])}<br><span class="tag">{esc(tx['type'])}</span></td><td><span class="address">{esc(tx['from'])}</span></td><td><span class="address">{esc(tx['to'])}</span></td><td>{money(tx['amount'])}</td><td><a href="{esc(tx_url(tx['tx_hash']))}" target="_blank">Etherscan</a><br><span class="address">{esc(tx['tx_hash'])}</span></td><td><img class="qr" src="{esc(qr_url(tx['tx_hash']))}" alt="QR"></td></tr>"""
        body = f"""<section class="panel"><h1>Istoric comenzi / tranzactii</h1><p class="muted">QR-ul deschide tranzactia pe Sepolia Etherscan.</p><table><thead><tr><th>Data</th><th>De la</th><th>Catre</th><th>Suma</th><th>Tx</th><th>QR</th></tr></thead><tbody>{rows or "<tr><td colspan='6'>Nu exista tranzactii.</td></tr>"}</tbody></table></section>"""
        self.send_html(body, "Istoric")

    def export_json(self, wallet_id):
        data, client = self.require_login()
        if not client:
            return
        w = find_wallet(data, wallet_id)
        if not w or w["owner_id"] != client["id"]:
            self.redirect("/dashboard")
            return
        safe = {k: v for k, v in w.items() if k != "unlock_hash"}
        self.send_download(json.dumps(safe, indent=4, ensure_ascii=False).encode("utf-8"), f"{wallet_id}.json", "application/json")

    def export_pdf(self, wallet_id):
        data, client = self.require_login()
        if not client:
            return
        w = find_wallet(data, wallet_id)
        if not w or w["owner_id"] != client["id"]:
            self.redirect("/dashboard")
            return
        text = f"""Wallet EL - Date portofel
Client: {client['name']}
Nume: {w['label']}
Adresa: {w['address']}
Sold: {money(w['balance'])}
Principal: {'da' if w.get('primary') else 'nu'}
Exportat la: {now_text()}

Nota: cheia privata/parola nu este inclusa in export."""
        self.send_download(pdf_bytes(text), f"{wallet_id}.pdf", "application/pdf")


def main():
    load_data()
    local_url = f"http://127.0.0.1:{PORT}/"
    print(f"Aplicatia ruleaza local la {local_url}")
    print("Pentru alte dispozitive din aceeasi retea, foloseste IP-ul acestui PC, de exemplu: http://IP-UL-TAU:5000/")
    if OPEN_BROWSER:
        webbrowser.open(local_url)
    ThreadingHTTPServer((HOST, PORT), App).serve_forever()


if __name__ == "__main__":
    main()
