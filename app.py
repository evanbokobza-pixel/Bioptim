from __future__ import annotations

import hashlib
import html
import mimetypes
import os
import secrets
import shutil
import sqlite3
import traceback
import warnings
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse

warnings.simplefilter("ignore", DeprecationWarning)
import cgi  # noqa: E402


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "bioptim.db"
UPLOAD_DIR = BASE_DIR / "uploads"
SESSION_COOKIE = "bioptim_session"
APP_PORT = int(os.environ.get("PORT", "8010"))
MAX_FILE_SIZE = 8 * 1024 * 1024
APP_SECRET = os.environ.get("BIOPTIM_SECRET", "bioptim-dev-secret-change-me")

PLANS = {
    "subscription": {
        "label": "Abonnement mensuel",
        "amount_cents": 4900,
        "description": "Pour transmettre vos analyses au fil du temps et conserver un suivi dans votre espace.",
    },
    "single": {
        "label": "Analyse unique",
        "amount_cents": 6900,
        "description": "Pour une demande ponctuelle, sans engagement.",
    },
}

STATUS_LABELS = {
    "submitted": "Dossier recu",
    "reviewing": "Analyse en cours",
    "answered": "Compte rendu disponible",
    "closed": "Dossier cloture",
}

STATUS_CLASSES = {
    "submitted": "badge badge-amber",
    "reviewing": "badge badge-blue",
    "answered": "badge badge-green",
    "closed": "badge badge-slate",
}

PAYMENT_STATUS_LABELS = {
    "confirmed": "Confirme",
    "pending": "En attente",
    "failed": "Echoue",
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def e(value: object | None) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def format_money(cents: int) -> str:
    euros = cents / 100
    if euros.is_integer():
        return f"{int(euros)} EUR"
    return f"{euros:.2f} EUR"


def format_datetime(raw: str | None) -> str:
    dt = parse_iso(raw)
    if not dt:
        return "-"
    return dt.astimezone().strftime("%d/%m/%Y a %H:%M")


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    real_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        real_salt.encode("utf-8"),
        240_000,
    )
    return real_salt, digest.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, candidate = hash_password(password, salt=salt)
    return secrets.compare_digest(candidate, expected_hash)


def password_strength_ok(password: str) -> bool:
    return len(password) >= 8 and any(char.isdigit() for char in password)


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    UPLOAD_DIR.mkdir(exist_ok=True)
    with db() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'patient',
                subscription_expires_at TEXT,
                single_request_credits INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_code TEXT NOT NULL,
                plan_label TEXT NOT NULL,
                amount_cents INTEGER NOT NULL,
                status TEXT NOT NULL,
                fake_reference TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                request_type TEXT NOT NULL,
                status TEXT NOT NULL,
                age TEXT NOT NULL,
                sex TEXT NOT NULL,
                context TEXT,
                symptoms TEXT,
                comment TEXT,
                patient_email_copy INTEGER NOT NULL DEFAULT 0,
                interpretation TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS case_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                mime_type TEXT,
                size_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (iso(now_utc()),))

        admin = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            ("admin@bioptim.local",),
        ).fetchone()
        if not admin:
            salt, password_hash = hash_password("DemoAdmin123!")
            conn.execute(
                """
                INSERT INTO users (
                    full_name,
                    email,
                    password_salt,
                    password_hash,
                    role,
                    subscription_expires_at,
                    single_request_credits,
                    created_at
                )
                VALUES (?, ?, ?, ?, 'admin', ?, 999, ?)
                """,
                (
                    "Bioptim Admin",
                    "admin@bioptim.local",
                    salt,
                    password_hash,
                    iso(now_utc() + timedelta(days=3650)),
                    iso(now_utc()),
                ),
            )


def fetch_user(user_id: int | None):
    if not user_id:
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def subscription_active(user) -> bool:
    expiry = parse_iso(user["subscription_expires_at"]) if user else None
    return bool(expiry and expiry > now_utc())


def available_requests(user) -> str:
    if not user:
        return "Aucune formule active"
    if user["role"] == "admin":
        return "Acces administrateur"
    if subscription_active(user):
        expiry = format_datetime(user["subscription_expires_at"])
        return f"Votre abonnement est actif jusqu'au {expiry}"
    credits = user["single_request_credits"]
    if credits > 0:
        label = "demande ponctuelle disponible" if credits == 1 else "demandes ponctuelles disponibles"
        return f"{credits} {label}"
    return "Aucune formule active"


def has_submission_access(user) -> bool:
    return bool(user and (user["role"] == "admin" or subscription_active(user) or user["single_request_credits"] > 0))


def query_notice(parsed_url) -> str:
    params = parse_qs(parsed_url.query)
    return params.get("notice", [""])[0]


def safe_next(raw: str | None) -> str:
    if raw and raw.startswith("/") and not raw.startswith("//"):
        return raw
    return "/dashboard"


def with_notice(path: str, message: str) -> str:
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}{urlencode({'notice': message})}"


def render_status_badge(status: str) -> str:
    label = STATUS_LABELS.get(status, status)
    class_name = STATUS_CLASSES.get(status, "badge badge-slate")
    return f"<span class='{class_name}'>{e(label)}</span>"


def payment_status_label(status: str) -> str:
    return PAYMENT_STATUS_LABELS.get(status, status)


def text_block(raw: str | None) -> str:
    safe = e(raw or "").replace("\r\n", "\n").replace("\n", "<br>")
    return safe or "<span class='muted'>Aucune information renseignee.</span>"


def page_layout(*, title: str, body: str, user, session, notice: str = "") -> bytes:
    if user:
        user_actions = f"""
        <div class="nav-right">
            <a class="nav-link" href="/dashboard">Mon espace</a>
            <a class="nav-link" href="/request/new">Nouvelle demande</a>
            {'<a class="nav-link" href="/admin">Admin</a>' if user['role'] == 'admin' else ''}
            <form method="post" action="/logout" class="inline-form">
                <input type="hidden" name="csrf_token" value="{e(session['csrf_token'])}">
                <button class="button button-ghost" type="submit">Se deconnecter</button>
            </form>
        </div>
        """
    else:
        user_actions = """
        <div class="nav-right">
            <a class="nav-link" href="/login">Connexion</a>
            <a class="button button-small" href="/signup">Creer un compte</a>
        </div>
        """

    notice_html = f"<div class='notice'>{e(notice)}</div>" if notice else ""
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{e(title)} | Bioptim</title>
    <meta name="description" content="Bioptim centralise l'inscription, le paiement et l'envoi des bilans biologiques.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Source+Serif+4:wght@600;700&family=Source+Sans+3:wght@400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/app.css">
</head>
<body>
    <div class="app-shell">
        <header class="topbar">
            <a class="brand" href="/">
                <img src="/logo-bioptim.svg" alt="" width="54" height="54">
                <span>
                    <strong>Bioptim</strong>
                    <small>Interpretation de bilans biologiques</small>
                </span>
            </a>
            {user_actions}
        </header>
        {notice_html}
        {body}
    </div>
</body>
</html>
""".encode("utf-8")


class BioptimHandler(BaseHTTPRequestHandler):
    server_version = "Bioptim/1.0"

    def setup(self):
        self.pending_headers: list[tuple[str, str]] = []
        self.session = None
        self.user = None
        super().setup()

    def do_GET(self):
        try:
            self.bootstrap_context()
            parsed = urlparse(self.path)
            path = parsed.path
            if path in {"/app.css", "/logo-bioptim.svg"}:
                self.serve_static(path)
            elif path == "/":
                self.render_home(query_notice(parsed))
            elif path == "/signup":
                self.render_signup(query_notice(parsed))
            elif path == "/login":
                self.render_login(query_notice(parsed))
            elif path == "/dashboard":
                self.render_dashboard(query_notice(parsed))
            elif path == "/checkout":
                self.render_checkout(query_notice(parsed), parse_qs(parsed.query).get("plan", ["subscription"])[0])
            elif path == "/request/new":
                self.render_new_request(query_notice(parsed))
            elif path.startswith("/cases/"):
                self.render_case_detail(path)
            elif path == "/admin":
                self.render_admin_dashboard(query_notice(parsed))
            elif path.startswith("/admin/cases/"):
                self.render_admin_case(path, query_notice(parsed))
            elif path.startswith("/files/"):
                self.serve_uploaded_file(path)
            else:
                self.send_error_page(404, "Page introuvable", "Cette page n'existe pas sur Bioptim.")
        except Exception:
            traceback.print_exc()
            self.send_error_page(500, "Erreur serveur", "Une erreur inattendue est survenue.")

    def do_POST(self):
        try:
            self.bootstrap_context()
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/signup":
                self.handle_signup()
            elif path == "/login":
                self.handle_login()
            elif path == "/logout":
                self.handle_logout()
            elif path == "/checkout":
                self.handle_checkout()
            elif path == "/request/new":
                self.handle_new_request()
            elif path.startswith("/admin/cases/"):
                self.handle_admin_case_update(path)
            else:
                self.send_error_page(404, "Route introuvable", "Cette action n'est pas disponible.")
        except Exception:
            traceback.print_exc()
            self.send_error_page(500, "Erreur serveur", "Le traitement de la requete a echoue.")

    def bootstrap_context(self):
        session_id = self.read_cookie(SESSION_COOKIE)
        self.session = self.find_session(session_id)
        if not self.session:
            self.session = self.create_session(user_id=None)
        self.user = fetch_user(self.session["user_id"])
        if self.session["user_id"] and not self.user:
            self.session = self.create_session(user_id=None, replace_current=True)

    def read_cookie(self, name: str) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie()
        jar.load(raw)
        if name not in jar:
            return None
        return jar[name].value

    def find_session(self, session_id: str | None):
        if not session_id:
            return None
        with db() as conn:
            return conn.execute(
                "SELECT * FROM sessions WHERE id = ? AND expires_at > ?",
                (session_id, iso(now_utc())),
            ).fetchone()

    def create_session(self, user_id: int | None, replace_current: bool = False):
        current_id = self.session["id"] if replace_current and self.session else None
        new_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(24)
        expires_at = iso(now_utc() + timedelta(days=30))
        created_at = iso(now_utc())
        with db() as conn:
            if current_id:
                conn.execute("DELETE FROM sessions WHERE id = ?", (current_id,))
            conn.execute(
                """
                INSERT INTO sessions (id, user_id, csrf_token, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (new_id, user_id, csrf_token, expires_at, created_at),
            )
            session = conn.execute("SELECT * FROM sessions WHERE id = ?", (new_id,)).fetchone()
        self.set_cookie(SESSION_COOKIE, new_id, max_age=30 * 24 * 60 * 60)
        return session

    def clear_session_cookie(self):
        header = f"{SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
        self.pending_headers.append(("Set-Cookie", header))

    def set_cookie(self, name: str, value: str, *, max_age: int):
        header = f"{name}={value}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Lax"
        self.pending_headers.append(("Set-Cookie", header))

    def attach_user_to_session(self, user_id: int):
        self.session = self.create_session(user_id=user_id, replace_current=True)
        self.user = fetch_user(user_id)

    def require_auth(self):
        if self.user:
            return True
        next_path = safe_next(self.path)
        self.redirect(f"/login?{urlencode({'next': next_path})}")
        return False

    def require_admin(self):
        if self.user and self.user["role"] == "admin":
            return True
        self.send_error_page(403, "Acces refuse", "Cette zone est reservee a l'administration.")
        return False

    def require_csrf(self, form_data) -> bool:
        token = form_data.get("csrf_token", "")
        if token == self.session["csrf_token"]:
            return True
        self.send_error_page(403, "Formulaire invalide", "Le jeton de securite est invalide ou a expire.")
        return False

    def parse_simple_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {key: values[0].strip() for key, values in parsed.items()}

    def parse_multipart_form(self):
        return cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
            },
            keep_blank_values=True,
        )

    def send_html(self, body: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in self.pending_headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_bytes(self, body: bytes, *, content_type: str, status: int = 200, extra_headers: list[tuple[str, str]] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers:
                self.send_header(key, value)
        for key, value in self.pending_headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str):
        self.send_response(303)
        self.send_header("Location", location)
        for key, value in self.pending_headers:
            self.send_header(key, value)
        self.end_headers()

    def serve_static(self, path: str):
        file_map = {
            "/app.css": BASE_DIR / "app.css",
            "/logo-bioptim.svg": BASE_DIR / "logo-bioptim.svg",
        }
        target = file_map.get(path)
        if not target or not target.exists():
            self.send_error_page(404, "Fichier introuvable", "La ressource demandee n'existe pas.")
            return
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_bytes(target.read_bytes(), content_type=content_type)

    def send_error_page(self, status: int, title: str, message: str):
        body = page_layout(
            title=title,
            body=f"""
            <main class="page page-narrow">
                <section class="panel center">
                    <p class="eyebrow">Bioptim</p>
                    <h1>{e(title)}</h1>
                    <p class="lede">{e(message)}</p>
                    <a class="button" href="/">Retour a l'accueil</a>
                </section>
            </main>
            """,
            user=self.user,
            session=self.session,
        )
        self.send_html(body, status=status)

    def render_home(self, notice: str):
        cta = "/dashboard" if self.user else "/signup"
        primary_label = "Ouvrir mon espace" if self.user else "Creer un compte"
        secondary = "/checkout" if self.user else "/login"
        secondary_label = "Choisir une formule" if self.user else "Se connecter"
        dashboard_link = """
        <section class="panel stats-banner">
            <div>
                <strong>Votre espace</strong>
                <span>{}</span>
            </div>
            <a class="button button-light" href="/dashboard">Voir mes demandes</a>
        </section>
        """.format(e(available_requests(self.user))) if self.user else ""

        body = f"""
        <main class="page">
            <section class="hero hero-grid">
                <div class="panel hero-copy">
                    <p class="eyebrow">Bioptim</p>
                    <h1>Envoyez vos analyses.<br>Recevez une explication claire et ecrite.</h1>
                    <p class="lede">Transmettez vos resultats biologiques en ligne et recevez un compte rendu structure, lisible et personnalise dans votre espace.</p>
                    <div class="hero-actions">
                        <a class="button" href="{cta}">{primary_label}</a>
                        <a class="button button-light" href="{secondary}">{secondary_label}</a>
                    </div>
                    <ul class="check-list">
                        <li>Depot simple de vos analyses en PDF ou en photo</li>
                        <li>Questionnaire rapide pour mieux contextualiser votre situation</li>
                        <li>Compte rendu ecrit accessible depuis votre espace personnel</li>
                        <li>Suivi clair de vos demandes et de vos reponses</li>
                    </ul>
                </div>
                <aside class="panel stack">
                    <div class="mini-card">
                        <span class="label">Comment ça marche</span>
                        <ol>
                            <li><strong>Choisissez votre formule</strong></li>
                            <li><strong>Envoyez vos analyses</strong></li>
                            <li><strong>Recevez votre réponse écrite</strong></li>
                        </ol>
                    </div>
                    <div class="mini-card accent-card">
                        <span class="label">Pourquoi Bioptim</span>
                        <p>Un parcours simple pour mieux comprendre vos bilans biologiques et conserver vos documents au meme endroit.</p>
                    </div>
                </aside>
            </section>

            {dashboard_link}

            <section class="grid cols-3">
                <article class="panel">
                    <p class="eyebrow">Simple</p>
                    <h2>Un parcours fluide</h2>
                    <p>Vous creez votre compte, choisissez votre formule, envoyez vos analyses et retrouvez tout dans votre espace personnel.</p>
                </article>
                <article class="panel">
                    <p class="eyebrow">Clair</p>
                    <h2>Une lecture ecrite</h2>
                    <p>Chaque demande est accompagnee d'une synthese claire, redigee pour etre facile a relire et a conserver.</p>
                </article>
                <article class="panel">
                    <p class="eyebrow">Rassurant</p>
                    <h2>Un espace personnel</h2>
                    <p>Vos demandes, vos documents et vos reponses restent centralises dans un meme espace simple a utiliser.</p>
                </article>
            </section>

            <section class="panel">
                <div class="section-head">
                    <div>
                        <p class="eyebrow">Les offres</p>
                        <h2>Choisissez la formule qui vous convient</h2>
                    </div>
                    <a class="button button-light" href="/checkout">Voir les formules</a>
                </div>
                <div class="grid cols-2">
                    <article class="pricing-card pricing-card-highlight">
                        <strong>Abonnement mensuel</strong>
                        <p class="price">49 EUR / mois</p>
                        <p>Pour envoyer vos analyses au fil du temps et retrouver votre historique dans votre espace.</p>
                        <a class="button" href="/checkout?plan=subscription">Choisir l'abonnement</a>
                    </article>
                    <article class="pricing-card">
                        <strong>Analyse unique</strong>
                        <p class="price">69 EUR</p>
                        <p>Pour une demande ponctuelle, sans engagement, avec reponse ecrite dans votre espace.</p>
                        <a class="button button-light" href="/checkout?plan=single">Choisir cette formule</a>
                    </article>
                </div>
            </section>
        </main>
        """
        self.send_html(page_layout(title="Accueil", body=body, user=self.user, session=self.session, notice=notice))

    def render_signup(self, notice: str, error: str = "", values: dict[str, str] | None = None):
        values = values or {}
        next_value = safe_next(parse_qs(urlparse(self.path).query).get("next", ["/dashboard"])[0])
        error_html = f"<div class='form-error'>{e(error)}</div>" if error else ""
        body = f"""
        <main class="page page-narrow">
            <section class="panel auth-panel">
                <p class="eyebrow">Creer un compte</p>
                <h1>Ouvrez votre espace Bioptim</h1>
                <p class="lede">Creez votre espace personnel pour transmettre vos analyses, suivre vos demandes et consulter vos reponses.</p>
                {error_html}
                <form method="post" class="form-grid">
                    <input type="hidden" name="csrf_token" value="{e(self.session['csrf_token'])}">
                    <input type="hidden" name="next" value="{e(next_value)}">
                    <label>
                        Nom et prenom
                        <input type="text" name="full_name" value="{e(values.get('full_name', ''))}" placeholder="Exemple : Claire Martin" required>
                    </label>
                    <label>
                        Adresse email
                        <input type="email" name="email" value="{e(values.get('email', ''))}" placeholder="nom@email.fr" required>
                    </label>
                    <label>
                        Mot de passe
                        <input type="password" name="password" placeholder="Au moins 8 caracteres avec 1 chiffre" required>
                    </label>
                    <label>
                        Confirmation du mot de passe
                        <input type="password" name="password_confirm" placeholder="Retapez votre mot de passe" required>
                    </label>
                    <button class="button" type="submit">Creer mon compte</button>
                </form>
                <p class="form-footnote">Vous avez deja un compte ? <a href="/login">Se connecter</a></p>
            </section>
        </main>
        """
        self.send_html(page_layout(title="Inscription", body=body, user=self.user, session=self.session, notice=notice))

    def render_login(self, notice: str, error: str = "", values: dict[str, str] | None = None):
        values = values or {}
        next_value = safe_next(parse_qs(urlparse(self.path).query).get("next", ["/dashboard"])[0])
        error_html = f"<div class='form-error'>{e(error)}</div>" if error else ""
        body = f"""
        <main class="page page-narrow">
            <section class="panel auth-panel">
                <p class="eyebrow">Connexion</p>
                <h1>Retrouvez votre espace patient</h1>
                <p class="lede">Connectez-vous pour retrouver vos demandes, vos documents et les reponses deja disponibles.</p>
                {error_html}
                <form method="post" class="form-grid">
                    <input type="hidden" name="csrf_token" value="{e(self.session['csrf_token'])}">
                    <input type="hidden" name="next" value="{e(next_value)}">
                    <label>
                        Adresse email
                        <input type="email" name="email" value="{e(values.get('email', ''))}" placeholder="nom@email.fr" required>
                    </label>
                    <label>
                        Mot de passe
                        <input type="password" name="password" placeholder="Votre mot de passe" required>
                    </label>
                    <button class="button" type="submit">Se connecter</button>
                </form>
                <p class="form-footnote">Pas encore de compte ? <a href="/signup">Creer un compte</a></p>
            </section>
        </main>
        """
        self.send_html(page_layout(title="Connexion", body=body, user=self.user, session=self.session, notice=notice))

    def render_dashboard(self, notice: str):
        if not self.require_auth():
            return

        with db() as conn:
            my_cases = conn.execute(
                """
                SELECT c.*, COUNT(cf.id) AS files_count
                FROM cases c
                LEFT JOIN case_files cf ON cf.case_id = c.id
                WHERE c.user_id = ?
                GROUP BY c.id
                ORDER BY c.created_at DESC
                """,
                (self.user["id"],),
            ).fetchall()
            payments = conn.execute(
                """
                SELECT *
                FROM payments
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 5
                """,
                (self.user["id"],),
            ).fetchall()
        answered_cases = sum(1 for case in my_cases if case["interpretation"])

        case_cards = "".join(
            f"""
            <article class="case-card">
                <div class="case-head">
                    <strong>Demande #{case['id']}</strong>
                    {render_status_badge(case['status'])}
                </div>
                <p class="muted">Type : {e(case['request_type'])} - {e(case['files_count'])} fichier(s) - Creee le {e(format_datetime(case['created_at']))}</p>
                <p>{"Compte rendu disponible." if case['interpretation'] else "Votre demande est en cours de traitement."}</p>
                <a class="link-arrow" href="/cases/{case['id']}">Voir le dossier</a>
            </article>
            """
            for case in my_cases
        ) or "<div class='empty-state'>Aucune demande pour le moment. Vous pouvez choisir une formule puis transmettre vos premieres analyses.</div>"

        payment_items = "".join(
            f"""
            <tr>
                <td>{e(payment['plan_label'])}</td>
                <td>{e(format_money(payment['amount_cents']))}</td>
                <td>{e(payment_status_label(payment['status']))}</td>
                <td>{e(format_datetime(payment['created_at']))}</td>
            </tr>
            """
            for payment in payments
        ) or "<tr><td colspan='4'>Aucune commande enregistree.</td></tr>"

        body = f"""
        <main class="page">
            <section class="panel dashboard-hero">
                <div>
                    <p class="eyebrow">Mon espace</p>
                    <h1>Bonjour {e(self.user['full_name'])}</h1>
                    <p class="lede">Retrouvez ici vos demandes, vos documents transmis et les reponses disponibles dans votre espace.</p>
                </div>
                <div class="hero-actions">
                    <a class="button" href="/request/new">Nouvelle demande</a>
                    <a class="button button-light" href="/checkout">Choisir une formule</a>
                </div>
            </section>

            <section class="grid cols-3">
                <article class="panel stat-card">
                    <span class="label">Formule active</span>
                    <strong>{e(available_requests(self.user))}</strong>
                </article>
                <article class="panel stat-card">
                    <span class="label">Demandes envoyees</span>
                    <strong>{len(my_cases)}</strong>
                </article>
                <article class="panel stat-card">
                    <span class="label">Reponses disponibles</span>
                    <strong>{answered_cases}</strong>
                </article>
            </section>

            <section class="grid cols-2">
                <div class="panel">
                    <div class="section-head">
                        <div>
                            <p class="eyebrow">Demandes</p>
                            <h2>Vos dossiers biologiques</h2>
                        </div>
                        <a class="button button-light" href="/request/new">Deposer des analyses</a>
                    </div>
                    <div class="stack">{case_cards}</div>
                </div>

                <div class="panel">
                    <div class="section-head">
                        <div>
                            <p class="eyebrow">Facturation</p>
                            <h2>Historique de vos formules</h2>
                        </div>
                        <a class="button button-light" href="/checkout">Choisir une formule</a>
                    </div>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Offre</th>
                                <th>Montant</th>
                                <th>Statut</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>{payment_items}</tbody>
                    </table>
                </div>
            </section>
        </main>
        """
        self.send_html(page_layout(title="Tableau de bord", body=body, user=self.user, session=self.session, notice=notice))

    def render_checkout(self, notice: str, selected_plan: str):
        if not self.require_auth():
            return
        selected_plan = selected_plan if selected_plan in PLANS else "subscription"
        selected = PLANS[selected_plan]
        plan_cards = []
        for code, plan in PLANS.items():
            selected_class = "pricing-card pricing-card-highlight" if code == selected_plan else "pricing-card"
            action = "Plan selectionne" if code == selected_plan else "Choisir ce plan"
            link_class = "button" if code == selected_plan else "button button-light"
            plan_cards.append(
                f"""
                <article class="{selected_class}">
                    <strong>{e(plan['label'])}</strong>
                    <p class="price">{e(format_money(plan['amount_cents']))}{' / mois' if code == 'subscription' else ''}</p>
                    <p>{e(plan['description'])}</p>
                    <a class="{link_class}" href="/checkout?plan={code}">{action}</a>
                </article>
                """
            )

        body = f"""
        <main class="page">
            <section class="panel dashboard-hero">
                <div>
                    <p class="eyebrow">Paiement securise</p>
                    <h1>Choisissez votre formule</h1>
                    <p class="lede">Selectionnez l'offre qui vous convient puis confirmez votre commande en quelques informations.</p>
                </div>
            </section>

            <section class="grid cols-2">
                <div class="panel">
                    <div class="section-head">
                        <div>
                            <p class="eyebrow">Choix du plan</p>
                            <h2>Offres disponibles</h2>
                        </div>
                    </div>
                    <div class="grid">{''.join(plan_cards)}</div>
                </div>

                <section class="panel">
                    <p class="eyebrow">Validation</p>
                    <h2>{e(selected['label'])}</h2>
                    <p class="lede">{e(selected['description'])}</p>
                    <form method="post" class="form-grid">
                        <input type="hidden" name="csrf_token" value="{e(self.session['csrf_token'])}">
                        <input type="hidden" name="plan_code" value="{e(selected_plan)}">
                        <label>
                            Nom du titulaire
                            <input type="text" name="cardholder_name" placeholder="Exemple : Claire Martin" required>
                        </label>
                        <label>
                            Numero de carte
                            <input type="text" name="card_number" value="4242 4242 4242 4242" required>
                        </label>
                        <label>
                            Code postal de facturation
                            <input type="text" name="postal_code" placeholder="75008" required>
                        </label>
                        <label class="checkbox-row">
                            <input type="checkbox" name="consent" value="yes" required>
                            <span>Je confirme les informations de ma commande et j'accepte les conditions de l'offre selectionnee.</span>
                        </label>
                        <button class="button" type="submit">Confirmer ma commande</button>
                    </form>
                </section>
            </section>
        </main>
        """
        self.send_html(page_layout(title="Paiement", body=body, user=self.user, session=self.session, notice=notice))

    def render_new_request(self, notice: str, error: str = "", values: dict[str, str] | None = None):
        if not self.require_auth():
            return
        values = values or {}
        if not has_submission_access(self.user):
            self.redirect(with_notice("/checkout?plan=single", "Choisissez une formule avant d'envoyer vos analyses."))
            return

        error_html = f"<div class='form-error'>{e(error)}</div>" if error else ""
        body = f"""
        <main class="page">
            <section class="panel auth-panel">
                <p class="eyebrow">Depot de dossier</p>
                <h1>Envoyez vos analyses biologiques</h1>
                <p class="lede">Ajoutez vos analyses et quelques informations utiles pour recevoir une interpretation ecrite claire dans votre espace.</p>
                <div class="highlight-row">
                    <span class="label">Ma formule</span>
                    <strong>{e(available_requests(self.user))}</strong>
                </div>
                {error_html}
                <form method="post" enctype="multipart/form-data" class="form-grid">
                    <input type="hidden" name="csrf_token" value="{e(self.session['csrf_token'])}">
                    <div class="file-drop">
                        <strong>Selectionnez vos documents</strong>
                        <span>Formats conseilles : PDF, JPG ou PNG. Vous pouvez joindre plusieurs fichiers.</span>
                        <input type="file" name="analysis_files" multiple required>
                    </div>
                    <div class="grid cols-2 compact-grid">
                        <label>
                            Age
                            <input type="text" name="age" value="{e(values.get('age', ''))}" placeholder="Exemple : 58 ans" required>
                        </label>
                        <label>
                            Sexe
                            <select name="sex" required>
                                <option value="">Choisir</option>
                                <option value="Femme" {'selected' if values.get('sex') == 'Femme' else ''}>Femme</option>
                                <option value="Homme" {'selected' if values.get('sex') == 'Homme' else ''}>Homme</option>
                                <option value="Autre" {'selected' if values.get('sex') == 'Autre' else ''}>Autre</option>
                            </select>
                        </label>
                    </div>
                    <label>
                        Contexte medical
                        <textarea name="context" rows="4" placeholder="Expliquez en quelques mots pourquoi vous souhaitez une interpretation.">{e(values.get('context', ''))}</textarea>
                    </label>
                    <label>
                        Symptomes ou elements utiles
                        <textarea name="symptoms" rows="4" placeholder="Expliquez ce que vous observez ou ressentez.">{e(values.get('symptoms', ''))}</textarea>
                    </label>
                    <label>
                        Commentaire libre
                        <textarea name="comment" rows="4" placeholder="Ajoutez toute precision utile.">{e(values.get('comment', ''))}</textarea>
                    </label>
                    <label class="checkbox-row">
                        <input type="checkbox" name="patient_email_copy" value="yes" {'checked' if values.get('patient_email_copy') == 'yes' else ''}>
                        <span>Je souhaite recevoir un email lorsqu'une reponse sera disponible dans mon espace.</span>
                    </label>
                    <button class="button" type="submit">Envoyer ma demande</button>
                </form>
            </section>
        </main>
        """
        self.send_html(page_layout(title="Nouvelle demande", body=body, user=self.user, session=self.session, notice=notice))

    def render_case_detail(self, path: str):
        if not self.require_auth():
            return
        try:
            case_id = int(path.rstrip("/").split("/")[-1])
        except ValueError:
            self.send_error_page(404, "Dossier introuvable", "Le numero de dossier demande est invalide.")
            return

        with db() as conn:
            case = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if not case:
                self.send_error_page(404, "Dossier introuvable", "Cette demande n'existe pas.")
                return
            if case["user_id"] != self.user["id"] and self.user["role"] != "admin":
                self.send_error_page(403, "Acces refuse", "Vous n'avez pas acces a ce dossier.")
                return
            files = conn.execute("SELECT * FROM case_files WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()

        files_html = "".join(
            f"""
            <li>
                <a class="link-arrow" href="/files/{file['id']}">{e(file['original_name'])}</a>
                <span class="muted">{e(file['size_bytes'])} octets</span>
            </li>
            """
            for file in files
        ) or "<li class='muted'>Aucun fichier enregistre.</li>"

        interpretation_html = (
            f"<div class='response-box'>{text_block(case['interpretation'])}</div>"
            if case["interpretation"]
            else "<div class='empty-state'>Votre reponse sera ajoutee dans cet espace des qu'elle sera disponible.</div>"
        )

        body = f"""
        <main class="page">
            <section class="panel dashboard-hero">
                <div>
                    <p class="eyebrow">Mon dossier</p>
                    <h1>Demande #{case['id']}</h1>
                    <p class="lede">Soumise le {e(format_datetime(case['created_at']))}</p>
                    <div class="hero-actions">{render_status_badge(case['status'])}</div>
                </div>
                <div class="hero-actions">
                    <a class="button button-light" href="/dashboard">Retour au tableau de bord</a>
                    {'<a class="button" href="/admin/cases/%s">Voir cote admin</a>' % case['id'] if self.user['role'] == 'admin' else ''}
                </div>
            </section>

            <section class="grid cols-2">
                <article class="panel">
                    <p class="eyebrow">Informations transmises</p>
                    <h2>Contexte du patient</h2>
                    <dl class="detail-list">
                        <div><dt>Type de demande</dt><dd>{e(case['request_type'])}</dd></div>
                        <div><dt>Age</dt><dd>{e(case['age'])}</dd></div>
                        <div><dt>Sexe</dt><dd>{e(case['sex'])}</dd></div>
                        <div><dt>Contexte</dt><dd>{text_block(case['context'])}</dd></div>
                        <div><dt>Symptomes</dt><dd>{text_block(case['symptoms'])}</dd></div>
                        <div><dt>Commentaire</dt><dd>{text_block(case['comment'])}</dd></div>
                    </dl>
                </article>

                <article class="panel">
                    <p class="eyebrow">Fichiers et reponse</p>
                    <h2>Documents transmis</h2>
                    <ul class="file-list">{files_html}</ul>
                    <h3 class="subheading">Votre reponse</h3>
                    {interpretation_html}
                </article>
            </section>
        </main>
        """
        self.send_html(page_layout(title=f"Dossier {case['id']}", body=body, user=self.user, session=self.session))

    def render_admin_dashboard(self, notice: str):
        if not self.require_admin():
            return

        with db() as conn:
            patients_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'patient'").fetchone()[0]
            total_cases = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            pending_cases = conn.execute("SELECT COUNT(*) FROM cases WHERE status IN ('submitted', 'reviewing')").fetchone()[0]
            total_payments = conn.execute("SELECT COUNT(*) FROM payments WHERE status = 'confirmed'").fetchone()[0]
            cases = conn.execute(
                """
                SELECT c.*, u.full_name, u.email
                FROM cases c
                JOIN users u ON u.id = c.user_id
                ORDER BY c.created_at DESC
                LIMIT 12
                """
            ).fetchall()
            payments = conn.execute(
                """
                SELECT p.*, u.full_name
                FROM payments p
                JOIN users u ON u.id = p.user_id
                ORDER BY p.created_at DESC
                LIMIT 8
                """
            ).fetchall()

        case_rows = "".join(
            f"""
            <tr>
                <td><a href="/admin/cases/{case['id']}">#{case['id']}</a></td>
                <td>{e(case['full_name'])}</td>
                <td>{render_status_badge(case['status'])}</td>
                <td>{e(case['request_type'])}</td>
                <td>{e(format_datetime(case['created_at']))}</td>
            </tr>
            """
            for case in cases
        ) or "<tr><td colspan='5'>Aucune demande recue.</td></tr>"

        payment_rows = "".join(
            f"""
            <tr>
                <td>{e(payment['full_name'])}</td>
                <td>{e(payment['plan_label'])}</td>
                <td>{e(format_money(payment['amount_cents']))}</td>
                <td>{e(payment['fake_reference'])}</td>
            </tr>
            """
            for payment in payments
        ) or "<tr><td colspan='4'>Aucun paiement.</td></tr>"

        body = f"""
        <main class="page">
            <section class="panel dashboard-hero">
                <div>
                    <p class="eyebrow">Administration</p>
                    <h1>Suivi des dossiers Bioptim</h1>
                    <p class="lede">Vue d'ensemble des patients, des demandes en cours et des paiements enregistres.</p>
                </div>
            </section>

            <section class="grid cols-4">
                <article class="panel stat-card"><span class="label">Patients</span><strong>{patients_count}</strong></article>
                <article class="panel stat-card"><span class="label">Demandes</span><strong>{total_cases}</strong></article>
                <article class="panel stat-card"><span class="label">En attente</span><strong>{pending_cases}</strong></article>
                <article class="panel stat-card"><span class="label">Paiements confirmes</span><strong>{total_payments}</strong></article>
            </section>

            <section class="grid cols-2">
                <article class="panel">
                    <div class="section-head">
                        <div>
                            <p class="eyebrow">Demandes recentes</p>
                            <h2>Dossiers patients</h2>
                        </div>
                    </div>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Patient</th>
                                <th>Statut</th>
                                <th>Type</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>{case_rows}</tbody>
                    </table>
                </article>

                <article class="panel">
                    <div class="section-head">
                        <div>
                            <p class="eyebrow">Paiements recents</p>
                            <h2>Historique</h2>
                        </div>
                    </div>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Patient</th>
                                <th>Plan</th>
                                <th>Montant</th>
                                <th>Reference</th>
                            </tr>
                        </thead>
                        <tbody>{payment_rows}</tbody>
                    </table>
                </article>
            </section>
        </main>
        """
        self.send_html(page_layout(title="Administration", body=body, user=self.user, session=self.session, notice=notice))

    def render_admin_case(self, path: str, notice: str, error: str = ""):
        if not self.require_admin():
            return
        try:
            case_id = int(path.rstrip("/").split("/")[-1])
        except ValueError:
            self.send_error_page(404, "Dossier introuvable", "Le numero de dossier demande est invalide.")
            return

        with db() as conn:
            case = conn.execute(
                """
                SELECT c.*, u.full_name, u.email
                FROM cases c
                JOIN users u ON u.id = c.user_id
                WHERE c.id = ?
                """,
                (case_id,),
            ).fetchone()
            if not case:
                self.send_error_page(404, "Dossier introuvable", "Cette demande n'existe pas.")
                return
            files = conn.execute("SELECT * FROM case_files WHERE case_id = ? ORDER BY id", (case_id,)).fetchall()

        error_html = f"<div class='form-error'>{e(error)}</div>" if error else ""
        files_html = "".join(
            f"<li><a class='link-arrow' href='/files/{file['id']}'>{e(file['original_name'])}</a></li>"
            for file in files
        ) or "<li class='muted'>Aucun fichier.</li>"

        body = f"""
        <main class="page">
            <section class="panel dashboard-hero">
                <div>
                    <p class="eyebrow">Traitement admin</p>
                    <h1>Dossier #{case['id']} - {e(case['full_name'])}</h1>
                    <p class="lede">{e(case['email'])}</p>
                    <div class="hero-actions">{render_status_badge(case['status'])}</div>
                </div>
                <div class="hero-actions">
                    <a class="button button-light" href="/admin">Retour admin</a>
                    <a class="button" href="/cases/{case['id']}">Voir cote patient</a>
                </div>
            </section>

            <section class="grid cols-2">
                <article class="panel">
                    <p class="eyebrow">Contenu transmis</p>
                    <h2>Informations du patient</h2>
                    <dl class="detail-list">
                        <div><dt>Type</dt><dd>{e(case['request_type'])}</dd></div>
                        <div><dt>Age</dt><dd>{e(case['age'])}</dd></div>
                        <div><dt>Sexe</dt><dd>{e(case['sex'])}</dd></div>
                        <div><dt>Contexte</dt><dd>{text_block(case['context'])}</dd></div>
                        <div><dt>Symptomes</dt><dd>{text_block(case['symptoms'])}</dd></div>
                        <div><dt>Commentaire</dt><dd>{text_block(case['comment'])}</dd></div>
                    </dl>
                    <h3 class="subheading">Fichiers joints</h3>
                    <ul class="file-list">{files_html}</ul>
                </article>

                <article class="panel">
                    <p class="eyebrow">Reponse medicale</p>
                    <h2>Mettre a jour le dossier</h2>
                    {error_html}
                    <form method="post" class="form-grid">
                        <input type="hidden" name="csrf_token" value="{e(self.session['csrf_token'])}">
                        <label>
                            Statut
                            <select name="status" required>
                                <option value="submitted" {'selected' if case['status'] == 'submitted' else ''}>Dossier recu</option>
                                <option value="reviewing" {'selected' if case['status'] == 'reviewing' else ''}>Analyse en cours</option>
                                <option value="answered" {'selected' if case['status'] == 'answered' else ''}>Compte rendu disponible</option>
                                <option value="closed" {'selected' if case['status'] == 'closed' else ''}>Dossier cloture</option>
                            </select>
                        </label>
                        <label>
                            Interpretation ecrite
                            <textarea name="interpretation" rows="12" placeholder="Renseignez ici la synthese medicale a remettre au patient.">{e(case['interpretation'] or '')}</textarea>
                        </label>
                        <button class="button" type="submit">Enregistrer la reponse</button>
                    </form>
                </article>
            </section>
        </main>
        """
        self.send_html(page_layout(title=f"Admin dossier {case['id']}", body=body, user=self.user, session=self.session, notice=notice))

    def serve_uploaded_file(self, path: str):
        if not self.require_auth():
            return
        try:
            file_id = int(path.rstrip("/").split("/")[-1])
        except ValueError:
            self.send_error_page(404, "Fichier introuvable", "Identifiant de fichier invalide.")
            return

        with db() as conn:
            row = conn.execute(
                """
                SELECT cf.*, c.user_id
                FROM case_files cf
                JOIN cases c ON c.id = cf.case_id
                WHERE cf.id = ?
                """,
                (file_id,),
            ).fetchone()
        if not row:
            self.send_error_page(404, "Fichier introuvable", "Ce document n'existe pas.")
            return
        if row["user_id"] != self.user["id"] and self.user["role"] != "admin":
            self.send_error_page(403, "Acces refuse", "Vous n'avez pas acces a ce document.")
            return

        target = UPLOAD_DIR / row["stored_name"]
        if not target.exists():
            self.send_error_page(404, "Fichier manquant", "Le fichier n'est plus disponible pour le moment.")
            return

        content_type = row["mime_type"] or mimetypes.guess_type(row["original_name"])[0] or "application/octet-stream"
        disposition = f"attachment; filename*=UTF-8''{quote(row['original_name'])}"
        self.send_bytes(
            target.read_bytes(),
            content_type=content_type,
            extra_headers=[("Content-Disposition", disposition)],
        )

    def handle_signup(self):
        form = self.parse_simple_form()
        if not self.require_csrf(form):
            return

        full_name = form.get("full_name", "").strip()
        email = form.get("email", "").strip().lower()
        password = form.get("password", "")
        password_confirm = form.get("password_confirm", "")
        next_path = safe_next(form.get("next"))

        if not full_name or not email:
            self.render_signup("", "Merci de remplir votre nom et votre email.", form)
            return
        if password != password_confirm:
            self.render_signup("", "Les deux mots de passe ne correspondent pas.", form)
            return
        if not password_strength_ok(password):
            self.render_signup("", "Choisissez un mot de passe d'au moins 8 caracteres avec un chiffre.", form)
            return

        try:
            with db() as conn:
                existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
                if existing:
                    self.render_signup("", "Un compte existe deja avec cette adresse email.", form)
                    return
                salt, password_hash = hash_password(password)
                cursor = conn.execute(
                    """
                    INSERT INTO users (
                        full_name,
                        email,
                        password_salt,
                        password_hash,
                        role,
                        subscription_expires_at,
                        single_request_credits,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, 'patient', NULL, 0, ?)
                    """,
                    (full_name, email, salt, password_hash, iso(now_utc())),
                )
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            self.render_signup("", "Impossible de creer ce compte pour le moment.", form)
            return

        self.attach_user_to_session(user_id)
        self.redirect(with_notice(next_path, "Compte cree avec succes."))

    def handle_login(self):
        form = self.parse_simple_form()
        if not self.require_csrf(form):
            return
        email = form.get("email", "").strip().lower()
        password = form.get("password", "")
        next_path = safe_next(form.get("next"))

        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not verify_password(password, user["password_salt"], user["password_hash"]):
            self.render_login("", "Email ou mot de passe incorrect.", {"email": email})
            return

        self.attach_user_to_session(user["id"])
        self.redirect(with_notice(next_path, "Connexion reussie."))

    def handle_logout(self):
        form = self.parse_simple_form()
        if not self.require_csrf(form):
            return
        old_session_id = self.session["id"] if self.session else None
        if old_session_id:
            with db() as conn:
                conn.execute("DELETE FROM sessions WHERE id = ?", (old_session_id,))
        self.clear_session_cookie()
        self.redirect(with_notice("/", "Vous etes maintenant deconnecte."))

    def handle_checkout(self):
        if not self.require_auth():
            return
        form = self.parse_simple_form()
        if not self.require_csrf(form):
            return

        plan_code = form.get("plan_code", "")
        if plan_code not in PLANS:
            self.redirect(with_notice("/checkout", "Le plan selectionne est invalide."))
            return
        if form.get("consent") != "yes":
            self.redirect(with_notice(f"/checkout?plan={plan_code}", "Merci de confirmer les conditions avant de finaliser votre commande."))
            return

        plan = PLANS[plan_code]
        reference = f"BIOT-{secrets.token_hex(4).upper()}"
        now = now_utc()

        with db() as conn:
            conn.execute(
                """
                INSERT INTO payments (
                    user_id,
                    plan_code,
                    plan_label,
                    amount_cents,
                    status,
                    fake_reference,
                    created_at
                )
                VALUES (?, ?, ?, ?, 'confirmed', ?, ?)
                """,
                (
                    self.user["id"],
                    plan_code,
                    plan["label"],
                    plan["amount_cents"],
                    reference,
                    iso(now),
                ),
            )

            current_user = conn.execute("SELECT * FROM users WHERE id = ?", (self.user["id"],)).fetchone()
            if plan_code == "subscription":
                current_expiry = parse_iso(current_user["subscription_expires_at"])
                base_date = current_expiry if current_expiry and current_expiry > now else now
                new_expiry = iso(base_date + timedelta(days=30))
                conn.execute(
                    "UPDATE users SET subscription_expires_at = ? WHERE id = ?",
                    (new_expiry, self.user["id"]),
                )
            else:
                conn.execute(
                    "UPDATE users SET single_request_credits = single_request_credits + 1 WHERE id = ?",
                    (self.user["id"],),
                )

        self.user = fetch_user(self.user["id"])
        self.redirect(with_notice("/dashboard", f"Paiement confirme ({reference})."))

    def handle_new_request(self):
        if not self.require_auth():
            return
        form = self.parse_multipart_form()
        csrf_token = form.getfirst("csrf_token", "")
        if not self.require_csrf({"csrf_token": csrf_token}):
            return

        values = {
            "age": form.getfirst("age", "").strip(),
            "sex": form.getfirst("sex", "").strip(),
            "context": form.getfirst("context", "").strip(),
            "symptoms": form.getfirst("symptoms", "").strip(),
            "comment": form.getfirst("comment", "").strip(),
            "patient_email_copy": form.getfirst("patient_email_copy", "").strip(),
        }

        if not has_submission_access(self.user):
            self.redirect(with_notice("/checkout?plan=single", "Choisissez une formule avant d'envoyer une nouvelle demande."))
            return
        if not values["age"] or not values["sex"]:
            self.render_new_request("", "Merci de renseigner au moins l'age et le sexe.", values)
            return

        file_items = form["analysis_files"] if "analysis_files" in form else []
        if not isinstance(file_items, list):
            file_items = [file_items]

        uploaded_files = [item for item in file_items if getattr(item, "filename", "")]
        if not uploaded_files:
            self.render_new_request("", "Merci d'ajouter au moins un fichier d'analyse.", values)
            return

        saved_files: list[Path] = []
        now = iso(now_utc())
        request_type = "Abonnement" if subscription_active(self.user) else "Analyse unique"

        try:
            with db() as conn:
                latest_user = conn.execute("SELECT * FROM users WHERE id = ?", (self.user["id"],)).fetchone()
                using_subscription = subscription_active(latest_user)
                if not using_subscription and latest_user["single_request_credits"] < 1:
                    self.render_new_request("", "Votre formule n'est plus active. Merci d'en choisir une nouvelle.", values)
                    return

                cursor = conn.execute(
                    """
                    INSERT INTO cases (
                        user_id,
                        request_type,
                        status,
                        age,
                        sex,
                        context,
                        symptoms,
                        comment,
                        patient_email_copy,
                        interpretation,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, 'submitted', ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        self.user["id"],
                        request_type,
                        values["age"],
                        values["sex"],
                        values["context"],
                        values["symptoms"],
                        values["comment"],
                        1 if values["patient_email_copy"] == "yes" else 0,
                        now,
                        now,
                    ),
                )
                case_id = cursor.lastrowid

                for item in uploaded_files:
                    data = item.file.read(MAX_FILE_SIZE + 1)
                    if len(data) > MAX_FILE_SIZE:
                        raise ValueError(f"Le fichier {item.filename} depasse 8 MB.")
                    extension = Path(item.filename).suffix
                    stored_name = f"{secrets.token_hex(16)}{extension}"
                    target = UPLOAD_DIR / stored_name
                    with target.open("wb") as file_handle:
                        file_handle.write(data)
                    saved_files.append(target)

                    conn.execute(
                        """
                        INSERT INTO case_files (
                            case_id,
                            original_name,
                            stored_name,
                            mime_type,
                            size_bytes,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            case_id,
                            Path(item.filename).name,
                            stored_name,
                            item.type,
                            len(data),
                            now,
                        ),
                    )

                if not using_subscription:
                    conn.execute(
                        "UPDATE users SET single_request_credits = single_request_credits - 1 WHERE id = ?",
                        (self.user["id"],),
                    )
        except ValueError as exc:
            for target in saved_files:
                target.unlink(missing_ok=True)
            self.render_new_request("", str(exc), values)
            return
        except Exception:
            for target in saved_files:
                target.unlink(missing_ok=True)
            raise

        self.user = fetch_user(self.user["id"])
        self.redirect(with_notice(f"/cases/{case_id}", "Votre demande a bien ete envoyee."))

    def handle_admin_case_update(self, path: str):
        if not self.require_admin():
            return
        try:
            case_id = int(path.rstrip("/").split("/")[-1])
        except ValueError:
            self.send_error_page(404, "Dossier introuvable", "Le numero de dossier demande est invalide.")
            return

        form = self.parse_simple_form()
        if not self.require_csrf(form):
            return

        status = form.get("status", "")
        interpretation = form.get("interpretation", "").strip()
        if status not in STATUS_LABELS:
            self.render_admin_case(path, "", "Merci de choisir un statut valide.")
            return
        if status in {"answered", "closed"} and not interpretation:
            self.render_admin_case(path, "", "Une interpretation est requise pour clore ou repondre au dossier.")
            return

        with db() as conn:
            conn.execute(
                """
                UPDATE cases
                SET status = ?, interpretation = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, interpretation, iso(now_utc()), case_id),
            )

        self.redirect(with_notice(f"/admin/cases/{case_id}", "Le dossier a ete mis a jour."))


def run():
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", APP_PORT), BioptimHandler)
    print(f"Bioptim disponible sur http://0.0.0.0:{APP_PORT}")
    print("Compte admin de demo : admin@bioptim.local / DemoAdmin123!")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArret du serveur Bioptim.")
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
