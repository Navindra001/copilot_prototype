"""Story Pilot prototype server (Flask).

Run:   python app.py
Env:   PORT (default 3000), CLINIC_CODE (default clinic-invite)
"""
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import threading
import time

from flask import Flask, Response, jsonify, request, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE, "data.json")
PORT = int(os.environ.get("PORT", 3000))
CLINIC_CODE = os.environ.get("CLINIC_CODE", "clinic-invite")
COLLS = ["families", "status", "clinical", "claims", "closed"]
SESSION_SECONDS = 30 * 86400

app = Flask(__name__)
lock = threading.RLock()

# ---------- storage ----------
try:
    with open(DATA_FILE, encoding="utf-8") as fh:
        db = json.load(fh)
except (OSError, ValueError):
    db = {}
for name in COLLS + ["users", "sessions"]:
    db.setdefault(name, {})

_save_timer = None


def save():
    """Write data.json shortly after the last change."""
    global _save_timer
    def write():
        with lock, open(DATA_FILE, "w", encoding="utf-8") as fh:
            json.dump(db, fh)
    if _save_timer:
        _save_timer.cancel()
    _save_timer = threading.Timer(0.15, write)
    _save_timer.daemon = True
    _save_timer.start()


# ---------- accounts ----------
def hash_pw(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=64).hex()


def public_user(u):
    return {"id": u["id"], "name": u["name"], "email": u["email"], "role": u["role"]}


def find_by_email(email):
    return next((u for u in db["users"].values() if u["email"] == email), None)


fails = {}  # login throttle per email


def too_many(email):
    f = fails.get(email)
    return bool(f and f["n"] >= 5 and time.time() - f["t"] < 300)


def note_fail(email):
    f = fails.get(email)
    if not f or time.time() - f["t"] >= 300:
        f = {"n": 0, "t": time.time()}
    f["n"] += 1
    f["t"] = time.time()
    fails[email] = f


def new_session(uid):
    token = secrets.token_hex(24)
    db["sessions"][token] = {"uid": uid, "at": time.time()}
    save()
    return token


def current_auth():
    token = request.headers.get("x-token") or request.args.get("token") or ""
    s = db["sessions"].get(token)
    if not s or time.time() - s["at"] > SESSION_SECONDS:
        return None
    user = db["users"].get(s["uid"])
    return (user, token) if user else None


def err(message, code):
    return jsonify({"error": message}), code


# ---------- live updates (server-sent events) ----------
clients = []  # list of (queue, user)


def view_for(user):
    """Families see only their own record. Clinical notes are clinic-only."""
    out = {c: db[c] for c in COLLS}
    if user["role"] != "clinician":
        out["clinical"] = {}
        out["families"] = {user["id"]: db["families"][user["id"]]} if user["id"] in db["families"] else {}
    return out


def push():
    for q, user in list(clients):
        q.put(json.dumps(view_for(user)))


# ---------- routes ----------
@app.get("/")
def index():
    return send_from_directory(BASE, "index.html")


@app.get("/api/ping")
def ping():
    return jsonify(ok=True)


@app.post("/api/signup")
def signup():
    b = request.get_json(silent=True) or {}
    name = str(b.get("name", "")).strip()
    email = str(b.get("email", "")).strip().lower()
    pw = str(b.get("password", ""))
    role = "clinician" if b.get("role") == "clinician" else "parent"
    if not 2 <= len(name) <= 60:
        return err("Enter your name.", 400)
    if not re.match(r"^\S+@\S+\.\S+$", email):
        return err("Enter a valid email address.", 400)
    if len(pw) < 8:
        return err("Use at least 8 characters for your password.", 400)
    if role == "clinician" and str(b.get("code", "")) != CLINIC_CODE:
        return err("That clinic invite code is not right.", 403)
    with lock:
        if find_by_email(email):
            return err("An account with that email already exists. Log in instead.", 409)
        uid = "u" + secrets.token_hex(8)
        salt = secrets.token_hex(16)
        db["users"][uid] = {"id": uid, "name": name, "email": email, "role": role,
                            "salt": salt, "hash": hash_pw(pw, salt), "created": time.time()}
        return jsonify(user=public_user(db["users"][uid]), token=new_session(uid))


@app.post("/api/login")
def login():
    b = request.get_json(silent=True) or {}
    email = str(b.get("email", "")).strip().lower()
    if too_many(email):
        return err("Too many attempts. Try again in a few minutes.", 429)
    u = find_by_email(email)
    ok = bool(u) and hmac.compare_digest(hash_pw(str(b.get("password", "")), u["salt"]), u["hash"])
    if not ok:
        note_fail(email)
        return err("Email or password is not right.", 401)
    fails.pop(email, None)
    with lock:
        return jsonify(user=public_user(u), token=new_session(u["id"]))


@app.get("/api/me")
def me():
    a = current_auth()
    return jsonify(user=public_user(a[0])) if a else err("Please log in.", 401)


@app.post("/api/logout")
def logout():
    a = current_auth()
    if not a:
        return err("Please log in.", 401)
    with lock:
        db["sessions"].pop(a[1], None)
        save()
    return jsonify(ok=True)


@app.get("/api/events")
def events():
    a = current_auth()
    if not a:
        return err("Please log in.", 401)
    user = a[0]
    q = queue.Queue()
    entry = (q, user)
    clients.append(entry)

    def stream():
        try:
            yield f"data: {json.dumps(view_for(user))}\n\n"
            while True:
                try:
                    yield f"data: {q.get(timeout=25)}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        finally:
            if entry in clients:
                clients.remove(entry)

    return Response(stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/doc/<coll>/<path:doc_id>", methods=["PUT", "DELETE"])
def doc(coll, doc_id):
    a = current_auth()
    if not a:
        return err("Please log in.", 401)
    user = a[0]
    if coll not in COLLS:
        return err("Not found.", 404)
    allowed = (user["role"] == "clinician"
               or (coll == "families" and doc_id == user["id"])
               or coll == "claims")
    if not allowed:
        return err("You do not have permission to change this.", 403)
    with lock:
        if request.method == "PUT":
            body = request.get_json(silent=True)
            if not isinstance(body, dict):
                return err("Bad request.", 400)
            db[coll][doc_id] = body
        else:
            db[coll].pop(doc_id, None)
        save()
        push()
    return jsonify(ok=True)


@app.post("/api/claim/<path:slot>")
def claim(slot):
    a = current_auth()
    if not a:
        return err("Please log in.", 401)
    user = a[0]
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return err("Bad request.", 400)
    body["uid"] = user["id"]
    with lock:
        cur = db["claims"].get(slot)
        if cur:  # a claim is stale if its booking was cancelled or declined
            fam = db["families"].get(cur.get("uid"), {})
            bk = (fam.get("bookings") or {}).get(cur.get("bid"))
            st = db["status"].get(cur.get("bid"))
            if bk and not bk.get("cancelled") and not (st and st.get("status") == "declined"):
                return err("Taken.", 409)
        db["claims"][slot] = body
        save()
        push()
    return jsonify(ok=True)


if __name__ == "__main__":
    print(f"Story Pilot running on http://localhost:{PORT}")
    print(f"Clinician invite code: {CLINIC_CODE}")
    app.run(host="0.0.0.0", port=PORT, threaded=True, debug=False)
