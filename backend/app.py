import os
import json
import subprocess
import smtplib
import hashlib
import secrets
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, abort, Response
from flask_cors import CORS
from flask_socketio import SocketIO, emit, disconnect
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

load_dotenv()

app = Flask(__name__, static_folder='../frontend', template_folder='../frontend')
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))
app.permanent_session_lifetime = timedelta(hours=24)
app.config['SESSION_COOKIE_PATH'] = '/'

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

ADMIN_PIN   = os.environ.get('ADMIN_PIN', '1234')
SMTP_HOST   = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT   = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER   = os.environ.get('SMTP_USER', '')
SMTP_PASS   = os.environ.get('SMTP_PASS', '')
APP_URL     = os.environ.get('APP_URL', 'https://mgrattenberg.duckdns.org/voiceai')
REPOS_BASE  = os.environ.get('REPOS_BASE', '/repos')
USERS_FILE  = os.environ.get('USERS_FILE', '/data/users.json')

serializer = URLSafeTimedSerializer(app.secret_key)


# ── Nutzerverwaltung (JSON-Datei) ─────────────────────────────────────────────

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

def get_user(email):
    return load_users().get(email.lower())

def upsert_user(email, **kwargs):
    users = load_users()
    email = email.lower()
    if email not in users:
        users[email] = {'email': email, 'name': '', 'status': 'eingeladen',
                        'role': 'user', 'repos': [],
                        'created': datetime.utcnow().isoformat(), 'last_login': None}
    users[email].update(kwargs)
    save_users(users)
    return users[email]

def delete_user(email):
    users = load_users()
    users.pop(email.lower(), None)
    save_users(users)


# ── Auth Decorators ───────────────────────────────────────────────────────────

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            if request.is_json:
                abort(401)
            return redirect(APP_URL + '/login')
        email = session.get('email', '')
        user = get_user(email) if email else None
        if user and user.get('status') == 'gesperrt':
            session.clear()
            return redirect(APP_URL + '/login?err=gesperrt')
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return redirect(APP_URL + '/admin/login')
        return f(*args, **kwargs)
    return decorated


# ── Email ─────────────────────────────────────────────────────────────────────

def send_invite_email(to_email, name, token):
    link = f"{APP_URL}/auth?token={token}"
    greeting = f"Hallo {name}!" if name else "Hallo!"
    body = f"""{greeting}

Du wurdest zu VoiceAI eingeladen.

Klicke auf den folgenden Link um dich anzumelden (gültig 24 Stunden):

{link}
"""
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = 'VoiceAI Einladung'
    msg['From'] = SMTP_USER
    msg['To'] = to_email
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)


# ── Passwort-Hilfsfunktionen ──────────────────────────────────────────────────

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 260000)
    return salt + ':' + h.hex()

def verify_password(password, stored):
    try:
        salt, _ = stored.split(':', 1)
        return hash_password(password, salt) == stored
    except Exception:
        return False


# ── Login / Auth Routen ───────────────────────────────────────────────────────

LOGIN_HTML = '''<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VoiceAI</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f0f0f;color:#e0e0e0;font-family:sans-serif;display:flex;
align-items:center;justify-content:center;height:100dvh}
.box{background:#1a1a1a;border:1px solid #333;border-radius:16px;padding:32px;
max-width:360px;width:90%;text-align:center}
h2{margin-bottom:8px;font-size:22px}
p{color:#888;font-size:14px;margin-bottom:20px}
input{width:100%;background:#2a2a2a;border:1px solid #444;color:#e0e0e0;
border-radius:8px;padding:10px 14px;font-size:15px;margin-bottom:12px;outline:none}
input:focus{border-color:#2563eb}
button{width:100%;background:#2563eb;color:white;border:none;border-radius:8px;
padding:12px;font-size:15px;cursor:pointer;margin-bottom:8px}
.err{color:#f87171;font-size:13px;margin-bottom:12px}
#pw-row{display:none}
</style></head><body>
<div class="box">
  <h2>&#127908; VoiceAI</h2>
  <p id="subtitle">Email eingeben</p>
  <div id="err" class="err"></div>
  <input type="email" id="email" placeholder="Email-Adresse" autofocus>
  <div id="pw-row">
    <input type="password" id="password" placeholder="Passwort">
    <button onclick="doLogin()">Anmelden</button>
  </div>
  <div id="nopw-row">
    <button onclick="checkEmail()">Weiter</button>
  </div>
</div>
<script>
const base = window.location.pathname.replace(/[/]login$/, '');
let step = 'email';
document.getElementById('email').addEventListener('keydown', e => { if(e.key==='Enter') checkEmail(); });
document.getElementById('password').addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); });
async function checkEmail() {
  const email = document.getElementById('email').value.trim();
  const err = document.getElementById('err');
  if (!email) return;
  const r = await fetch(base + '/api/check-email', {method:'POST',
    headers:{'Content-Type':'application/json'}, body:JSON.stringify({email})});
  const d = await r.json();
  if (!r.ok) { err.textContent = d.error || 'Kein Zugang.'; return; }
  err.textContent = '';
  document.getElementById('email').readOnly = true;
  document.getElementById('nopw-row').style.display = 'none';
  document.getElementById('pw-row').style.display = 'block';
  if (d.need_set) {
    document.getElementById('subtitle').textContent = 'Passwort festlegen';
    document.getElementById('password').placeholder = 'Neues Passwort wählen (mind. 6 Zeichen)';
  } else {
    document.getElementById('subtitle').textContent = 'Passwort eingeben';
    document.getElementById('password').focus();
  }
  step = d.need_set ? 'set' : 'login';
}
async function doLogin() {
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const err = document.getElementById('err');
  if (!password) return;
  const url = step === 'set' ? base + '/api/set-password' : base + '/api/login';
  const r = await fetch(url, {method:'POST',
    headers:{'Content-Type':'application/json'}, body:JSON.stringify({email, password})});
  const d = await r.json();
  if (!r.ok) { err.textContent = d.error || 'Fehler'; return; }
  window.location.href = d.redirect || base + '/';
}
</script></body></html>'''


@app.route('/login')
def login():
    return LOGIN_HTML


@app.route('/api/check-email', methods=['POST'])
def check_email():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'error': 'Ungültige Email'}), 400
    user = get_user(email)
    if not user:
        return jsonify({'error': 'Kein Zugang. Bitte beim Administrator anfragen.'}), 403
    if user.get('status') == 'gesperrt':
        return jsonify({'error': 'Dein Zugang wurde gesperrt.'}), 403
    need_set = not user.get('password_hash')
    return jsonify({'ok': True, 'need_set': need_set})


@app.route('/api/set-password', methods=['POST'])
def set_password():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    user = get_user(email)
    if not user or user.get('status') == 'gesperrt':
        return jsonify({'error': 'Kein Zugang'}), 403
    if user.get('password_hash'):
        return jsonify({'error': 'Passwort bereits gesetzt'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Passwort muss mindestens 6 Zeichen haben'}), 400
    upsert_user(email, password_hash=hash_password(password),
                status='aktiv', last_login=datetime.utcnow().isoformat())
    _do_login_session(email)
    return jsonify({'ok': True, 'redirect': APP_URL + '/'})


@app.route('/api/login', methods=['POST'])
def do_login():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    user = get_user(email)
    if not user or user.get('status') == 'gesperrt':
        return jsonify({'error': 'Kein Zugang'}), 403
    if not user.get('password_hash'):
        return jsonify({'error': 'Noch kein Passwort gesetzt'}), 400
    if not verify_password(password, user['password_hash']):
        return jsonify({'error': 'Falsches Passwort'}), 401
    upsert_user(email, status='aktiv', last_login=datetime.utcnow().isoformat())
    _do_login_session(email)
    return jsonify({'ok': True, 'redirect': APP_URL + '/'})


def _do_login_session(email):
    user = get_user(email)
    session.permanent = True
    session['authenticated'] = True
    session['email'] = email
    session['role'] = user.get('role', 'user')
    session['repos'] = user.get('repos', [])


@app.route('/logout')
def logout():
    session.clear()
    return redirect(APP_URL + '/login')


# ── Admin Routen ──────────────────────────────────────────────────────────────

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    err = ''
    if request.method == 'POST':
        pin = request.form.get('pin', '')
        if pin == ADMIN_PIN:
            session['admin'] = True
            return redirect(APP_URL + '/admin')
        err = 'Falscher PIN'
    return f'''<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0f0f0f;color:#e0e0e0;font-family:sans-serif;display:flex;
align-items:center;justify-content:center;height:100dvh}}
.box{{background:#1a1a1a;border:1px solid #333;border-radius:16px;padding:32px;
max-width:320px;width:90%;text-align:center}}
h2{{margin-bottom:20px}}
input{{width:100%;background:#2a2a2a;border:1px solid #444;color:#e0e0e0;
border-radius:8px;padding:10px;font-size:18px;text-align:center;
margin-bottom:12px;outline:none;letter-spacing:4px}}
button{{width:100%;background:#7c3aed;color:white;border:none;border-radius:8px;
padding:12px;font-size:15px;cursor:pointer}}
.err{{color:#f87171;font-size:13px;margin-bottom:12px}}
</style></head><body>
<div class="box">
  <h2>🔐 Admin</h2>
  {"<p class='err'>" + err + "</p>" if err else ""}
  <form method="post">
    <input type="password" name="pin" placeholder="PIN" autofocus>
    <button type="submit">Anmelden</button>
  </form>
</div></body></html>'''


@app.route('/admin')
@require_admin
def admin():
    users = load_users()
    rows = ''
    for u in sorted(users.values(), key=lambda x: x.get('created', '')):
        status = u.get('status', '')
        status_badge = {
            'eingeladen': '<span style="color:#fb923c">eingeladen</span>',
            'aktiv':      '<span style="color:#4ade80">aktiv</span>',
            'gesperrt':   '<span style="color:#f87171">gesperrt</span>',
        }.get(status, status)
        last = u.get('last_login', '')
        last_str = last[:16].replace('T', ' ') if last else '—'
        sperr_btn = ''
        if status != 'gesperrt':
            sperr_btn = f'<button class="btn-warn" onclick="action(\'{u["email"]}\',\'sperren\')">Sperren</button>'
        else:
            sperr_btn = f'<button class="btn-ok" onclick="action(\'{u["email"]}\',\'entsperren\')">Entsperren</button>'
        role = u.get('role', 'user')
        role_badge = {'user': '<span style="color:#60a5fa">user</span>',
                      'developer': '<span style="color:#a78bfa">developer</span>',
                      'admin': '<span style="color:#f59e0b">admin</span>'}.get(role, role)
        repos_str = ', '.join(u.get('repos', [])) or '—'
        rows += f'''<tr data-email="{u['email']}">
          <td>{u.get("name","")}</td>
          <td>{u["email"]}</td>
          <td>{status_badge}</td>
          <td>{role_badge}</td>
          <td style="font-size:12px;color:#888">{repos_str}</td>
          <td>{last_str}</td>
          <td style="display:flex;gap:6px;flex-wrap:wrap">
            <button class="btn-blue" onclick="action('{u["email"]}','pw_reset')">PW Reset</button>
            <button class="btn-purple" onclick="editRole('{u["email"]}','{role}','{",".join(u.get("repos",[]))}')">Rolle</button>
            {sperr_btn}
            <button class="btn-red" onclick="action('{u["email"]}','loeschen')">Löschen</button>
          </td>
        </tr>'''

    return f'''<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VoiceAI Admin</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0f0f0f;color:#e0e0e0;font-family:sans-serif;padding:24px}}
h2{{margin-bottom:20px;font-size:20px}}
.card{{background:#1a1a1a;border:1px solid #333;border-radius:12px;padding:20px;margin-bottom:20px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th{{text-align:left;padding:8px 10px;color:#888;border-bottom:1px solid #333}}
td{{padding:8px 10px;border-bottom:1px solid #222;vertical-align:middle}}
button{{border:none;border-radius:6px;padding:5px 10px;font-size:12px;cursor:pointer}}
.btn-blue{{background:#2563eb;color:white}}
.btn-warn{{background:#d97706;color:white}}
.btn-ok{{background:#166534;color:white}}
.btn-red{{background:#7f1d1d;color:#fca5a5}}
.btn-purple{{background:#7c3aed;color:white}}
.add-form{{display:flex;gap:8px;flex-wrap:wrap}}
.add-form input{{background:#2a2a2a;border:1px solid #444;color:#e0e0e0;
border-radius:8px;padding:8px 12px;font-size:14px;outline:none;flex:1;min-width:140px}}
.add-form button{{background:#7c3aed;color:white;padding:8px 16px;font-size:14px}}
#msg{{margin-top:10px;font-size:13px;color:#4ade80}}
</style></head><body>
<h2>🎤 VoiceAI – Nutzerverwaltung</h2>

<div class="card">
  <h3 style="margin-bottom:14px;font-size:16px">Person hinzufügen</h3>
  <div class="add-form">
    <input type="text" id="new-name" placeholder="Name">
    <input type="email" id="new-email" placeholder="Email">
    <button onclick="addUser()">Hinzufügen & Einladen</button>
  </div>
  <div id="msg"></div>
</div>

<div class="card">
  <table>
    <thead><tr><th>Name</th><th>Email</th><th>Status</th><th>Rolle</th><th>Repos</th><th>Letzter Login</th><th>Aktionen</th></tr></thead>
    <tbody id="tbody">{rows}</tbody>
  </table>
</div>

<script>
async function addUser() {{
  const name = document.getElementById('new-name').value.trim();
  const email = document.getElementById('new-email').value.trim();
  const msg = document.getElementById('msg');
  if (!email) return;
  const base = window.location.pathname.replace(/[/]admin.*$/, '');
  const r = await fetch(base + '/admin/users', {{method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{name, email, invite: true}})}});
  const d = await r.json();
  msg.textContent = r.ok ? '✓ ' + d.msg : '⚠️ ' + d.error;
  if (r.ok) setTimeout(() => location.reload(), 1000);
}}

async function action(email, act) {{
  if (act === 'loeschen' && !confirm('Wirklich löschen?')) return;
  const base = window.location.pathname.replace(/[/]admin.*$/, '');
  const r = await fetch(base + '/admin/users/' + encodeURIComponent(email) + '/' + act, {{method:'POST'}});
  const d = await r.json();
  if (r.ok) location.reload();
  else alert(d.error);
}}

function editRole(email, currentRole, currentRepos) {{
  const existing = document.getElementById('role-edit-row');
  if (existing) existing.remove();
  const rows = document.querySelectorAll('#tbody tr');
  let targetRow = null;
  rows.forEach(function(r) {{ if (r.dataset.email === email) targetRow = r; }});
  if (!targetRow) return;
  const td = document.createElement('td');
  td.colSpan = 7;
  td.style.cssText = 'background:#1a1a2e;padding:12px';
  const div = document.createElement('div');
  div.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap';
  const sel = document.createElement('select');
  sel.id = 'role-select';
  sel.style.cssText = 'background:#2a2a2a;color:#e0e0e0;border:1px solid #444;border-radius:6px;padding:6px 10px';
  [['user','user – nur Chat'],['developer','developer – Chat + Agent'],['admin','admin – alles']].forEach(function(o) {{
    const opt = document.createElement('option');
    opt.value = o[0]; opt.textContent = o[1];
    if (o[0] === currentRole) opt.selected = true;
    sel.appendChild(opt);
  }});
  const inp = document.createElement('input');
  inp.id = 'role-repos'; inp.value = currentRepos;
  inp.placeholder = 'z.B. agrobetrieb,gemeinschaft';
  inp.style.cssText = 'background:#2a2a2a;color:#e0e0e0;border:1px solid #444;border-radius:6px;padding:6px 10px;flex:1;min-width:200px';
  const saveBtn = document.createElement('button');
  saveBtn.textContent = 'Speichern';
  saveBtn.style.cssText = 'background:#7c3aed;color:white;border:none;border-radius:6px;padding:6px 14px;cursor:pointer';
  saveBtn.onclick = function() {{ saveRole(email); }};
  const cancelBtn = document.createElement('button');
  cancelBtn.textContent = 'Abbrechen';
  cancelBtn.style.cssText = 'background:#333;color:#e0e0e0;border:none;border-radius:6px;padding:6px 14px;cursor:pointer';
  cancelBtn.onclick = function() {{ document.getElementById('role-edit-row').remove(); }};
  const lbl1 = document.createElement('span'); lbl1.textContent = 'Rolle:'; lbl1.style.fontSize = '13px';
  const lbl2 = document.createElement('span'); lbl2.textContent = 'Repos (leer = alle):'; lbl2.style.fontSize = '13px';
  div.appendChild(lbl1); div.appendChild(sel); div.appendChild(lbl2);
  div.appendChild(inp); div.appendChild(saveBtn); div.appendChild(cancelBtn);
  td.appendChild(div);
  const editRow = document.createElement('tr');
  editRow.id = 'role-edit-row';
  editRow.appendChild(td);
  targetRow.after(editRow);
}}

async function saveRole(email) {{
  const role = document.getElementById('role-select').value;
  const reposStr = document.getElementById('role-repos').value;
  const repos = reposStr.split(',').map(r => r.trim()).filter(r => r);
  const base = window.location.pathname.replace(/[/]admin.*$/, '');
  const r = await fetch(base + '/admin/users/' + encodeURIComponent(email) + '/rolle', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{role, repos}})
  }});
  const d = await r.json();
  if (d.ok) location.reload();
  else alert(d.error);
}}
</script></body></html>'''


@app.route('/admin/users', methods=['POST'])
@require_admin
def admin_add_user():
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    do_invite = data.get('invite', False)
    if not email or '@' not in email:
        return jsonify({'error': 'Ungültige Email'}), 400
    if get_user(email):
        return jsonify({'error': 'Email bereits vorhanden'}), 400
    upsert_user(email, name=name, status='eingeladen')
    msg = f'{name or email} hinzugefügt'
    if do_invite and SMTP_USER and SMTP_PASS:
        try:
            token = serializer.dumps(email, salt='invite')
            send_invite_email(email, name, token)
            msg += ' und Einladung gesendet'
        except Exception as e:
            msg += f' (Email-Fehler: {e})'
    return jsonify({'msg': msg})


@app.route('/admin/users/<email>/<action>', methods=['POST'])
@require_admin
def admin_user_action(email, action):
    email = email.lower()
    user = get_user(email)
    if not user:
        return jsonify({'error': 'Nicht gefunden'}), 404
    if action == 'pw_reset':
        # Passwort-Hash löschen → User muss beim nächsten Login neues Passwort setzen
        upsert_user(email, password_hash=None)
        return jsonify({'ok': True, 'msg': f'Passwort für {email} zurückgesetzt. User muss beim nächsten Login ein neues Passwort setzen.'})
    elif action == 'sperren':
        upsert_user(email, status='gesperrt')
        return jsonify({'ok': True})
    elif action == 'entsperren':
        upsert_user(email, status='aktiv')
        return jsonify({'ok': True})
    elif action == 'loeschen':
        delete_user(email)
        return jsonify({'ok': True})
    elif action == 'rolle':
        data = request.get_json() or {}
        role = data.get('role', 'user')
        repos = data.get('repos', [])
        if role not in ('user', 'developer', 'admin'):
            return jsonify({'error': 'Ungültige Rolle'}), 400
        upsert_user(email, role=role, repos=repos)
        return jsonify({'ok': True})
    return jsonify({'error': 'Unbekannte Aktion'}), 400


# ── App Routen ────────────────────────────────────────────────────────────────

@app.route('/')
@require_auth
def index():
    return app.send_static_file('index.html')


@app.route('/api/me')
@require_auth
def me():
    return jsonify({
        'role': session.get('role', 'user'),
        'repos': session.get('repos', []),
        'email': session.get('email', ''),
        'helpdesk_mode': session.get('helpdesk_mode', False),
        'helpdesk_repo': session.get('helpdesk_repo', None),
    })


@app.route('/api/helpdesk-mode', methods=['POST'])
@require_auth
def toggle_helpdesk_mode():
    """Nur für Admin/Developer: Helpdesk-Modus + Repo in der Session setzen."""
    role = session.get('role', 'user')
    if role == 'user':
        return jsonify({'error': 'Nicht erlaubt'}), 403
    enabled = request.json.get('enabled', False)
    repo = request.json.get('repo', None)  # Repo-Pfad oder None
    session['helpdesk_mode'] = bool(enabled)
    session['helpdesk_repo'] = repo if enabled else None
    return jsonify({'helpdesk_mode': session['helpdesk_mode'], 'helpdesk_repo': session['helpdesk_repo']})


@app.route('/api/helpdesk-repos')
@require_auth
def helpdesk_repos():
    """Listet alle Repos mit .voiceai.md auf."""
    repos = find_repos_with_voiceai()
    # Füge docs/-Fallback hinzu falls vorhanden
    if os.path.exists(DOCS_BASE) and any(f.endswith('.md') for f in os.listdir(DOCS_BASE)):
        repos.insert(0, {'repo': '(lokale Docs)', 'path': None})
    return jsonify(repos)


@app.route('/api/models')
@require_auth
def models():
    available = []
    if os.environ.get('ANTHROPIC_API_KEY'):
        available += [
            {'id': 'claude-sonnet-4-6', 'name': 'Claude Sonnet 4.6', 'provider': 'anthropic'},
            {'id': 'claude-haiku-4-5-20251001', 'name': 'Claude Haiku 4.5', 'provider': 'anthropic'},
        ]
    if os.environ.get('MISTRAL_API_KEY'):
        available += [
            {'id': 'mistral-large-latest', 'name': 'Mistral Large', 'provider': 'mistral'},
            {'id': 'mistral-small-latest', 'name': 'Mistral Small', 'provider': 'mistral'},
        ]
    return jsonify(available)


# ── Agent Tools ───────────────────────────────────────────────────────────────

AGENT_TOOLS = [
    {
        "name": "list_repos",
        "description": "Listet alle verfügbaren Repositories auf.",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "read_file",
        "description": "Liest den Inhalt einer Datei in einem Repository.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "Repository-Name"},
                "path": {"type": "string", "description": "Dateipfad relativ zum Repo-Root"}
            },
            "required": ["repo", "path"]
        }
    },
    {
        "name": "list_files",
        "description": "Listet Dateien in einem Verzeichnis eines Repositories.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "Repository-Name"},
                "path": {"type": "string", "description": "Verzeichnispfad (leer = Root)", "default": ""}
            },
            "required": ["repo"]
        }
    },
    {
        "name": "git_status",
        "description": "Zeigt den git status eines Repositories.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "Repository-Name"}
            },
            "required": ["repo"]
        }
    },
    {
        "name": "git_log",
        "description": "Zeigt die letzten Commits eines Repositories.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "Repository-Name"},
                "n": {"type": "integer", "description": "Anzahl Commits", "default": 10}
            },
            "required": ["repo"]
        }
    },
    {
        "name": "git_diff",
        "description": "Zeigt Änderungen (diff) in einem Repository.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "Repository-Name"},
                "path": {"type": "string", "description": "Optionaler Dateipfad", "default": ""}
            },
            "required": ["repo"]
        }
    },
]


def _safe_repo_path(repo, path='', allowed_repos=None):
    if allowed_repos and not any(a.lower() in repo.lower() for a in allowed_repos):
        raise ValueError(f"Kein Zugriff auf Repository: {repo}")
    base = os.path.realpath(REPOS_BASE)
    repo_path = os.path.realpath(os.path.join(base, repo))
    if not repo_path.startswith(base):
        raise ValueError(f"Ungültiges Repository: {repo}")
    if path:
        full = os.path.realpath(os.path.join(repo_path, path))
        if not full.startswith(repo_path):
            raise ValueError(f"Ungültiger Pfad: {path}")
        return full
    return repo_path


def run_tool(name, inputs, allowed_repos=None):
    try:
        if name == "list_repos":
            if not os.path.exists(REPOS_BASE):
                return f"Repos-Verzeichnis nicht gefunden: {REPOS_BASE}"
            repos = [d for d in os.listdir(REPOS_BASE)
                     if os.path.isdir(os.path.join(REPOS_BASE, d)) and not d.startswith('.')]
            if allowed_repos:
                repos = [r for r in repos if any(a.lower() in r.lower() for a in allowed_repos)]
            return "Verfügbare Repos:\n" + "\n".join(repos) if repos else "Keine Repos gefunden."
        elif name == "read_file":
            path = _safe_repo_path(inputs['repo'], inputs['path'])
            if not os.path.isfile(path):
                return f"Datei nicht gefunden: {inputs['path']}"
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            if len(content) > 8000:
                content = content[:8000] + "\n... [gekürzt]"
            return content
        elif name == "list_files":
            path = _safe_repo_path(inputs['repo'], inputs.get('path', ''))
            if not os.path.isdir(path):
                return f"Verzeichnis nicht gefunden: {inputs.get('path', '')}"
            items = []
            for item in sorted(os.listdir(path)):
                if item.startswith('.'):
                    continue
                full = os.path.join(path, item)
                items.append(("📁 " if os.path.isdir(full) else "📄 ") + item)
            return "\n".join(items) if items else "Leer."
        elif name == "git_status":
            repo_path = _safe_repo_path(inputs['repo'])
            r = subprocess.run(['git', 'status', '--short'],
                               cwd=repo_path, capture_output=True, text=True, timeout=10)
            return r.stdout or "Keine Änderungen."
        elif name == "git_log":
            repo_path = _safe_repo_path(inputs['repo'])
            r = subprocess.run(['git', 'log', f'-{inputs.get("n", 10)}', '--oneline'],
                               cwd=repo_path, capture_output=True, text=True, timeout=10)
            return r.stdout or "Keine Commits."
        elif name == "git_diff":
            repo_path = _safe_repo_path(inputs['repo'])
            cmd = ['git', 'diff'] + ([inputs['path']] if inputs.get('path') else [])
            r = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, timeout=10)
            output = r.stdout
            if len(output) > 6000:
                output = output[:6000] + "\n... [gekürzt]"
            return output or "Keine Änderungen."
        return f"Unbekanntes Tool: {name}"
    except Exception as e:
        return f"Fehler: {str(e)}"


AGENT_SYSTEMS = {
    'developer': """Du bist ein Entwicklungsassistent mit Zugriff auf Code-Repositories.
Du kannst Dateien lesen, Git-Status prüfen und Fragen über den Code beantworten.

Wenn du Code-Änderungen vorschlägst, verwende immer dieses Format:

DATEI: pfad/zur/datei.py
ZEILE: 42 (oder "nach Zeile 42" / "ersetze Zeilen 10-15")
CODE:
```python
# hier der vollständige neue Code
```
ERKLÄRUNG: Was diese Änderung bewirkt.

Bei Sprachausgabe: Fasse zuerst kurz zusammen was zu tun ist (1-2 Sätze),
dann folgt der Code-Block. Keine langen Erklärungen vor dem Code.
Antworte immer auf Deutsch.""",

    'user': None,  # wird dynamisch aus Docs geladen
}


def run_agent_anthropic(messages, model, system, allowed_repos):
    import anthropic
    client = anthropic.Anthropic(api_key=os.environ.get('ANTHROPIC_API_KEY', ''))
    while True:
        response = client.messages.create(
            model=model, max_tokens=4096,
            system=system, tools=AGENT_TOOLS, messages=messages,
        )
        if response.stop_reason == 'end_turn':
            for block in response.content:
                if hasattr(block, 'text'):
                    return block.text
            return "Keine Antwort."
        elif response.stop_reason == 'tool_use':
            tool_results = []
            for block in response.content:
                if block.type == 'tool_use':
                    result = run_tool(block.name, block.input, allowed_repos=allowed_repos)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result
                    })
            messages = messages + [
                {"role": "assistant", "content": response.content},
                {"role": "user", "content": tool_results}
            ]
        else:
            return "Unerwarteter Stop-Grund: " + response.stop_reason


# Mistral Tool-Format konvertieren
MISTRAL_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t["description"],
            "parameters": t["input_schema"]
        }
    } for t in AGENT_TOOLS
]


def run_agent_mistral(messages, model, system, allowed_repos):
    import json as _json
    from mistralai import Mistral
    client = Mistral(api_key=os.environ.get('MISTRAL_API_KEY', ''))
    # System-Prompt als erstes Message
    mistral_messages = [{"role": "system", "content": system}] + messages
    while True:
        response = client.chat.complete(
            model=model,
            messages=mistral_messages,
            tools=MISTRAL_TOOLS,
            tool_choice="auto",
        )
        msg = response.choices[0].message
        finish = response.choices[0].finish_reason
        if finish == 'tool_calls' and msg.tool_calls:
            mistral_messages.append({"role": "assistant", "content": msg.content or "", "tool_calls": msg.tool_calls})
            for tc in msg.tool_calls:
                try:
                    inputs = _json.loads(tc.function.arguments)
                except Exception:
                    inputs = {}
                result = run_tool(tc.function.name, inputs, allowed_repos=allowed_repos)
                mistral_messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result
                })
        else:
            return msg.content or "Keine Antwort."


DOCS_BASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs')

VOICEAI_FILENAME = '.voiceai.md'

def find_repos_with_voiceai():
    """Gibt alle Repos zurück die eine .voiceai.md im Root haben."""
    result = []
    if not os.path.exists(REPOS_BASE):
        return result
    for top in sorted(os.listdir(REPOS_BASE)):
        top_path = os.path.join(REPOS_BASE, top)
        if not os.path.isdir(top_path):
            continue
        # Direkt im top-level (z.B. /repos/home/agrobetrieb)
        vf = os.path.join(top_path, VOICEAI_FILENAME)
        if os.path.isfile(vf):
            result.append({'repo': top, 'path': top_path})
        # Eine Ebene tiefer (z.B. /repos/docker/agrobetrieb)
        for sub in sorted(os.listdir(top_path)):
            sub_path = os.path.join(top_path, sub)
            if os.path.isdir(sub_path):
                vf2 = os.path.join(sub_path, VOICEAI_FILENAME)
                if os.path.isfile(vf2):
                    result.append({'repo': f"{top}/{sub}", 'path': sub_path})
    return result

def load_voiceai_md(repo_path):
    """Liest .voiceai.md aus einem Repo-Pfad."""
    vf = os.path.join(repo_path, VOICEAI_FILENAME)
    try:
        with open(vf, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return None

def load_docs():
    """Lädt alle Markdown-Dateien aus dem docs/ Ordner (Fallback)."""
    docs = []
    if os.path.exists(DOCS_BASE):
        for f in sorted(os.listdir(DOCS_BASE)):
            if f.endswith('.md'):
                try:
                    with open(os.path.join(DOCS_BASE, f), 'r', encoding='utf-8') as fh:
                        docs.append(fh.read())
                except Exception:
                    pass
    return '\n\n---\n\n'.join(docs)

def build_user_system(repo_path=None):
    """Baut den Helpdesk-System-Prompt.
    Wenn repo_path gesetzt: .voiceai.md aus dem Repo laden.
    Fallback: docs/-Ordner.
    """
    context = None
    app_name = "diese Software"

    if repo_path:
        context = load_voiceai_md(repo_path)

    if not context:
        context = load_docs()

    base = f"""Du bist ein freundlicher Helpdesk-Assistent für {app_name}.
Du hilfst Anwendern bei Fragen zur Bedienung. Erkläre Schritt für Schritt.
Antworte auf Deutsch, verständlich und ohne technischen Jargon.
Beziehe dich auf die folgende Dokumentation:\n\n"""
    return base + context if context else base + "(Keine Dokumentation vorhanden)"


def run_agent(messages, model='claude-sonnet-4-6', provider='anthropic', role='developer', allowed_repos=None, repo_path=None):
    if role == 'user':
        system = build_user_system(repo_path=repo_path)
    else:
        system = AGENT_SYSTEMS.get(role, AGENT_SYSTEMS['developer'])
    if provider == 'mistral':
        return run_agent_mistral(messages, model, system, allowed_repos)
    else:
        return run_agent_anthropic(messages, model, system, allowed_repos)


# ── Socket.IO ─────────────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    if not session.get('authenticated'):
        disconnect()
        return False


@socketio.on('chat')
def handle_chat(data):
    messages = data.get('messages', [])
    model_id = data.get('model', 'claude-sonnet-4-6')
    provider = data.get('provider', 'anthropic')
    role = session.get('role', 'user')
    helpdesk_mode = session.get('helpdesk_mode', False)
    helpdesk_repo = session.get('helpdesk_repo', None)
    ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
    MISTRAL_API_KEY = os.environ.get('MISTRAL_API_KEY', '')
    # Helpdesk-System-Prompt: immer für user-Rolle, für andere nur wenn Modus aktiv
    use_helpdesk = (role == 'user') or helpdesk_mode
    system_prompt = build_user_system(repo_path=helpdesk_repo) if use_helpdesk else None
    try:
        if provider == 'anthropic':
            if not ANTHROPIC_API_KEY:
                emit('error', {'message': 'Anthropic API-Key nicht konfiguriert'})
                return
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            kwargs = {'model': model_id, 'max_tokens': 2048, 'messages': messages}
            if system_prompt:
                kwargs['system'] = system_prompt
            response = client.messages.create(**kwargs)
            text = response.content[0].text
        elif provider == 'mistral':
            if not MISTRAL_API_KEY:
                emit('error', {'message': 'Mistral API-Key nicht konfiguriert'})
                return
            from mistralai import Mistral
            client = Mistral(api_key=MISTRAL_API_KEY)
            msgs = messages
            if system_prompt:
                msgs = [{'role': 'system', 'content': system_prompt}] + list(messages)
            response = client.chat.complete(model=model_id, messages=msgs)
            text = response.choices[0].message.content
        else:
            emit('error', {'message': f'Unbekannter Provider: {provider}'})
            return
        emit('response', {'text': text, 'model': model_id})
    except Exception as e:
        emit('error', {'message': str(e)})


@socketio.on('agent')
def handle_agent(data):
    messages = data.get('messages', [])
    model_id = data.get('model', 'claude-sonnet-4-6')
    provider = data.get('provider', 'anthropic')
    role = session.get('role', 'user')
    allowed_repos = session.get('repos', []) or None
    if role == 'user':
        allowed_repos = []
    if provider == 'anthropic' and not os.environ.get('ANTHROPIC_API_KEY'):
        emit('error', {'message': 'Agent benötigt Anthropic API-Key'})
        return
    if provider == 'mistral' and not os.environ.get('MISTRAL_API_KEY'):
        emit('error', {'message': 'Mistral API-Key nicht konfiguriert'})
        return
    try:
        emit('agent_status', {'text': '🔍 Agent denkt...'})
        text = run_agent(messages, model_id, provider=provider, role=role, allowed_repos=allowed_repos)
        emit('response', {'text': text, 'model': model_id + ' (Agent)'})
    except Exception as e:
        emit('error', {'message': str(e)})


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
