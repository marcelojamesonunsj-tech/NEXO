from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session, flash,
    render_template_string, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =========================
# Config
# =========================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOADS_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "nexo_rrhh.db"

APP_NAME = "NEXO RRHH"
SECRET_KEY = os.environ.get("NEXO_SECRET_KEY", "CAMBIAME-EN-PROD-UNA-CLAVE-LARGA")

ALLOWED_EXT = {".xlsx", ".xls"}

ROLES = ("SUPERADMIN", "ADMIN", "RRHH", "LECTOR")

# =========================
# App
# =========================
app = Flask(__name__)
app.secret_key = SECRET_KEY

def get_conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def init_db() -> None:
    with get_conn() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            pass_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('SUPERADMIN','ADMIN','RRHH','LECTOR')),
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            uploaded_by INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
            notes TEXT,
            FOREIGN KEY(uploaded_by) REFERENCES users(id)
        );
        """)
        # SUPERADMIN por defecto
        row = conn.execute("SELECT COUNT(*) AS c FROM users;").fetchone()
        if row["c"] == 0:
            conn.execute("""
                INSERT INTO users (username, pass_hash, role)
                VALUES (?, ?, ?)
            """, ("admin", generate_password_hash("admin123"), "SUPERADMIN"))

init_db()

# =========================
# Auth helpers
# =========================
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    with get_conn() as conn:
        u = conn.execute("SELECT * FROM users WHERE id=? AND is_active=1", (uid,)).fetchone()
    return u

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def require_roles(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u or u["role"] not in roles:
                flash("No tenés permisos para entrar ahí.", "error")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapper
    return deco

# =========================
# UI (Win11-ish)
# =========================
BASE_HTML = r"""
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{ title }}</title>
  <style>
    :root{
      --bg: #f6f7fb;
      --card: rgba(255,255,255,0.7);
      --text: #0f172a;
      --muted: rgba(15,23,42,0.65);
      --border: rgba(15,23,42,0.12);
      --primary: #2563eb;
      --danger: #ef4444;
      --shadow: 0 14px 40px rgba(15,23,42,0.10);
      --radius: 18px;
    }
    [data-theme="dark"]{
      --bg: #0b1220;
      --card: rgba(17,24,39,0.72);
      --text: #e5e7eb;
      --muted: rgba(229,231,235,0.68);
      --border: rgba(229,231,235,0.14);
      --primary: #60a5fa;
      --danger: #fb7185;
      --shadow: 0 14px 40px rgba(0,0,0,0.35);
    }
    *{ box-sizing: border-box; }
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(1200px 600px at 10% 0%, rgba(37,99,235,0.18), transparent 60%),
                  radial-gradient(1200px 600px at 90% 10%, rgba(99,102,241,0.16), transparent 60%),
                  var(--bg);
      color: var(--text);
      min-height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      padding: 28px;
    }
    .shell{ width: min(1040px, 100%); }
    .topbar{
      display:flex; align-items:center; justify-content:space-between;
      margin-bottom: 16px;
    }
    .brand{
      display:flex; gap:12px; align-items:center;
    }
    .logo{
      width:44px; height:44px; border-radius: 14px;
      background: linear-gradient(135deg, rgba(37,99,235,0.95), rgba(99,102,241,0.9));
      box-shadow: var(--shadow);
    }
    .brand h1{ font-size: 18px; margin:0; }
    .brand p{ margin:0; color: var(--muted); font-size: 13px; }
    .btn{
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.35);
      color: var(--text);
      padding: 10px 12px;
      border-radius: 12px;
      cursor: pointer;
      transition: 120ms ease;
      backdrop-filter: blur(10px);
    }
    [data-theme="dark"] .btn{ background: rgba(17,24,39,0.35); }
    .btn:hover{ transform: translateY(-1px); }
    .btn.primary{
      background: linear-gradient(135deg, rgba(37,99,235,0.95), rgba(99,102,241,0.9));
      border: none; color: white;
    }
    .btn.danger{
      background: rgba(239,68,68,0.10);
      border: 1px solid rgba(239,68,68,0.25);
      color: var(--danger);
    }
    .card{
      border: 1px solid var(--border);
      background: var(--card);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 18px;
      backdrop-filter: blur(14px);
    }
    .grid{
      display:grid; gap: 14px;
      grid-template-columns: 1.2fr 0.8fr;
    }
    @media (max-width: 920px){
      .grid{ grid-template-columns: 1fr; }
    }
    .muted{ color: var(--muted); }
    .row{ display:flex; gap: 10px; flex-wrap: wrap; align-items:center; }
    input, select{
      width: 100%;
      padding: 12px 12px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.35);
      color: var(--text);
      outline: none;
    }
    [data-theme="dark"] input, [data-theme="dark"] select{ background: rgba(17,24,39,0.35); }
    label{ font-size: 13px; color: var(--muted); display:block; margin-bottom: 6px; }
    .field{ margin-bottom: 12px; }
    .flash{
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.30);
      margin-bottom: 12px;
    }
    .flash.error{ border-color: rgba(239,68,68,0.25); background: rgba(239,68,68,0.10); }
    .flash.ok{ border-color: rgba(34,197,94,0.25); background: rgba(34,197,94,0.10); }
    table{ width:100%; border-collapse: collapse; font-size: 14px; }
    th, td{
      padding: 10px 10px;
      border-bottom: 1px solid var(--border);
      text-align:left;
    }
    th{ color: var(--muted); font-weight: 600; }
    a{ color: inherit; }
    .pill{
      padding: 6px 10px; border-radius: 999px; font-size: 12px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.25);
    }
    [data-theme="dark"] .pill{ background: rgba(17,24,39,0.25); }
    .right{ text-align:right; }
  </style>
</head>
<body data-theme="{{ theme }}">
  <div class="shell">
    <div class="topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>{{ title }}</h1>
          <p class="muted">{{ subtitle }}</p>
        </div>
      </div>
      <div class="row">
        {% if user %}
          <span class="pill">{{ user['username'] }} · {{ user['role'] }}</span>
          <a class="btn" href="{{ url_for('dashboard') }}">Panel</a>
          <a class="btn" href="{{ url_for('logout') }}">Salir</a>
        {% endif %}
        <form method="post" action="{{ url_for('toggle_theme') }}">
          <button class="btn" type="submit">Modo: {{ "Oscuro" if theme=="dark" else "Claro" }}</button>
        </form>
      </div>
    </div>

    {% for c, m in flashes %}
      <div class="flash {{ c }}">{{ m }}</div>
    {% endfor %}

    {{ body | safe }}
  </div>
</body>
</html>
"""

def render_page(body_html: str, title: str, subtitle: str):
    u = current_user()
    theme = session.get("theme", "light")
    flashes = []
    for cat, msg in list(get_flashed()):
        flashes.append((cat, msg))
    return render_template_string(
        BASE_HTML,
        body=body_html,
        title=title,
        subtitle=subtitle,
        user=u,
        theme=theme,
        flashes=flashes,
    )

def get_flashed():
    # Flask guarda flashes internamente; esta función permite leerlos sin duplicar lógica
    # Usamos get_flashed_messages con categorías.
    from flask import get_flashed_messages
    return get_flashed_messages(with_categories=True)

# =========================
# Routes
# =========================
@app.post("/toggle-theme")
def toggle_theme():
    session["theme"] = "dark" if session.get("theme", "light") == "light" else "light"
    ref = request.headers.get("Referer") or url_for("dashboard")
    return redirect(ref)

@app.get("/")
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.get("/login")
def login():
    body = """
    <div class="card" style="max-width:520px; margin: 0 auto;">
      <h2 style="margin:0 0 6px 0;">Iniciar sesión</h2>
      <p class="muted" style="margin-top:0;">Entrás al sistema local. Sin internet. En red.</p>
      <form method="post" action="/login">
        <div class="field">
          <label>Usuario</label>
          <input name="username" autocomplete="username" required />
        </div>
        <div class="field">
          <label>Contraseña</label>
          <input name="password" type="password" autocomplete="current-password" required />
        </div>
        <div class="row" style="justify-content:space-between;">
          <button class="btn primary" type="submit">Entrar</button>
          <span class="muted">Default: <b>admin / admin123</b></span>
        </div>
      </form>
    </div>
    """
    return render_page(body, APP_NAME, "Login")

@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "")
    with get_conn() as conn:
        u = conn.execute(
            "SELECT * FROM users WHERE username=? AND is_active=1",
            (username,),
        ).fetchone()
    if not u or not check_password_hash(u["pass_hash"], password):
        flash("Usuario o contraseña incorrectos.", "error")
        return redirect(url_for("login"))
    session["uid"] = int(u["id"])
    flash("Listo, entraste.", "ok")
    return redirect(url_for("dashboard"))

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/dashboard")
@login_required
def dashboard():
    u = current_user()
    with get_conn() as conn:
        uploads = conn.execute("""
            SELECT up.*, us.username AS uploader
            FROM uploads up
            JOIN users us ON us.id = up.uploaded_by
            ORDER BY up.id DESC
            LIMIT 20
        """).fetchall()

    rows = ""
    for r in uploads:
        rows += f"""
        <tr>
          <td>{r['id']}</td>
          <td>{r['original_name']}</td>
          <td class="muted">{r['uploaded_at']}</td>
          <td class="muted">{r['uploader']}</td>
          <td class="right"><a class="btn" href="/uploads/{r['stored_name']}">Descargar</a></td>
        </tr>
        """

    admin_block = ""
    if u["role"] in ("SUPERADMIN", "ADMIN"):
        admin_block = """
        <div class="card">
          <h3 style="margin:0 0 8px 0;">Administración</h3>
          <p class="muted" style="margin-top:0;">Usuarios, roles, permisos, reset de contraseña.</p>
          <div class="row">
            <a class="btn" href="/users">Gestionar usuarios</a>
          </div>
        </div>
        """

    body = f"""
    <div class="grid">
      <div class="card">
        <h2 style="margin:0 0 6px 0;">Panel</h2>
        <p class="muted" style="margin-top:0;">
          Subí el Excel de marcaciones. Después lo procesamos para calcular horas, faltas, extras, etc.
        </p>

        <form method="post" action="/upload" enctype="multipart/form-data">
          <div class="field">
            <label>Archivo Excel (.xls / .xlsx)</label>
            <input type="file" name="file" accept=".xls,.xlsx" required />
          </div>
          <div class="field">
            <label>Notas (opcional)</label>
            <input name="notes" placeholder="Enero 2026 - marcaciones reloj principal" />
          </div>
          <button class="btn primary" type="submit">Subir Excel</button>
        </form>

        <hr style="border:none; border-top:1px solid var(--border); margin:16px 0;" />

        <h3 style="margin:0 0 8px 0;">Últimos archivos</h3>
        <table>
          <thead>
            <tr>
              <th>ID</th><th>Archivo</th><th>Fecha</th><th>Subido por</th><th class="right">Acción</th>
            </tr>
          </thead>
          <tbody>
            {rows if rows else '<tr><td colspan="5" class="muted">Todavía no hay uploads.</td></tr>'}
          </tbody>
        </table>
      </div>

      <div style="display:flex; flex-direction:column; gap:14px;">
        {admin_block}
        <div class="card">
          <h3 style="margin:0 0 8px 0;">Próximo paso</h3>
          <p class="muted" style="margin-top:0;">
            Cuando me pases 1 Excel “viejo” y 1 “nuevo”, armamos el parser automático y el motor de cálculo.
          </p>
          <div class="row">
            <span class="pill">Sin internet</span>
            <span class="pill">En red</span>
            <span class="pill">Modo oscuro</span>
          </div>
        </div>
      </div>
    </div>
    """
    return render_page(body, APP_NAME, "Sistema local RRHH")

@app.post("/upload")
@login_required
def upload():
    u = current_user()
    f = request.files.get("file")
    if not f or not f.filename:
        flash("No seleccionaste ningún archivo.", "error")
        return redirect(url_for("dashboard"))

    ext = Path(f.filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        flash("Formato no soportado. Subí .xls o .xlsx", "error")
        return redirect(url_for("dashboard"))

    original = f.filename
    safe = secure_filename(original)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stored = f"{stamp}__{safe}"
    path = UPLOADS_DIR / stored
    f.save(path)

    notes = (request.form.get("notes") or "").strip()

    with get_conn() as conn:
        conn.execute("""
            INSERT INTO uploads (original_name, stored_name, uploaded_by, notes)
            VALUES (?, ?, ?, ?)
        """, (original, stored, int(u["id"]), notes))

    flash("Excel subido OK.", "ok")
    return redirect(url_for("dashboard"))

@app.get("/uploads/<name>")
@login_required
def download_upload(name: str):
    # Descarga del archivo subido
    return send_from_directory(UPLOADS_DIR, name, as_attachment=True)

@app.get("/users")
@login_required
@require_roles("SUPERADMIN", "ADMIN")
def users():
    with get_conn() as conn:
        rows = conn.execute("SELECT id, username, role, is_active, created_at FROM users ORDER BY id").fetchall()

    trs = ""
    for r in rows:
        status = "Activo" if r["is_active"] else "Inactivo"
        trs += f"""
        <tr>
          <td>{r['id']}</td>
          <td>{r['username']}</td>
          <td><span class="pill">{r['role']}</span></td>
          <td class="muted">{status}</td>
          <td class="muted">{r['created_at']}</td>
        </tr>
        """

    body = f"""
    <div class="card">
      <h2 style="margin:0 0 6px 0;">Usuarios</h2>
      <p class="muted" style="margin-top:0;">En el próximo paso agregamos: alta/edición/baja y reset de contraseña.</p>
      <div class="row" style="margin-bottom:10px;">
        <a class="btn" href="/dashboard">Volver</a>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th><th>Usuario</th><th>Rol</th><th>Estado</th><th>Creado</th>
          </tr>
        </thead>
        <tbody>
          {trs}
        </tbody>
      </table>
    </div>
    """
    return render_page(body, APP_NAME, "Administración de usuarios")

# =========================
# Main
# =========================
if __name__ == "__main__":
    # Para red local: host="0.0.0.0" expone a la LAN
    # En Windows puede saltar el firewall: permitir Python.
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
