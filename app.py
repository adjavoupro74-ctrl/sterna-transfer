from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_wtf.csrf import CSRFProtect
import sqlite3
import time
from datetime import datetime
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash
from datetime import timedelta
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email
from flask import jsonify, abort
from flask import jsonify
import pandas as pd
from flask import send_file
import io
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors
from flask import request

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Connexion')

class ContactForm(FlaskForm):
    nom = StringField("Nom", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Envoyer")

class CSRFOnlyForm(FlaskForm):
    pass

import logging


# =========================
# CONFIGURATION
# =========================
app = Flask(__name__)
app.config["WTF_CSRF_ENABLED"] = False
app.config["DEBUG"] = True

import os
app.secret_key = os.environ.get("SECRET_KEY", "change_me_in_production")

# =========================
# LOGS DE SÉCURITÉ
# =========================
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False  # True uniquement si HTTPS
)

# Expiration automatique de session (15 minutes)
app.permanent_session_lifetime = timedelta(minutes=15)

DB_NAME = "contact_messages.db"

ADMIN_SESSION_DURATION = 900  # 15 minutes (en secondes)

# =========================
# PROTECTION ANTI-BRUTEFORCE
# =========================
MAX_LOGIN_ATTEMPTS = 5
login_attempts = {}

# =========================
# ADMIN SECURISÉ
# =========================
ADMIN_EMAIL = "admin@sternatransfer.com"

ADMIN_PASSWORD_HASH = "scrypt:32768:8:1$2BB2IkIbsiNnvFtT$f94ecb4ebbfcde8ba2d8336450ec2577127f8bf6d490b398dffba38360e64ffb412d21708522d9f8ee182b5c6b08004ffb92325da4ff3a7195dc5bbb08539528"

ADMIN_ALLOWED_IPS = ["127.0.0.1"]  # localhost (ajoute la tienne plus tard)

FAILED_LOGINS = {}
MAX_ATTEMPTS = 3
BLOCK_TIME = 300  # secondes (5 minutes)
PENDING_DELETIONS = {}  # en mémoire (simple et suffisant)

# -------------------------
# CONFIG EMAIL (GMAIL)
# -------------------------
app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
    MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD")
)
mail = Mail(app)

# =========================
# INIT DB
# =========================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            date TEXT NOT NULL,
            lu INTEGER DEFAULT 0,
            deleted INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()
    print("✅ Base de données prête")

init_db()

conn = sqlite3.connect(DB_NAME)
c = conn.cursor()

try:
    c.execute("ALTER TABLE messages ADD COLUMN deleted INTEGER DEFAULT 0")
    print("✅ Colonne 'deleted' ajoutée")
except:
    print("ℹ️ Colonne déjà existante")

conn.commit()
conn.close()

# =========================
# ROUTES PUBLIQUES
# =========================
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/services")
def services():
    return render_template("services.html")

@app.route("/transfer")
def transfer():
    return render_template("transfer.html")

# =========================
# CONTACT
# =========================
from flask_mail import Message

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        try:
            nom = request.form.get("nom")
            email = request.form.get("email")
            message = request.form.get("message")

            # 💾 Sauvegarde DB
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute(
                "INSERT INTO messages (nom, email, message, date) VALUES (?, ?, ?, datetime('now'))",
                (nom, email, message)
            )
            conn.commit()
            conn.close()

            print("📧 Tentative envoi email...")

            try:
                msg = Message(
                    subject="Nouveau message",
                    sender=app.config['MAIL_USERNAME'],
                    recipients=["adjavoupro74@gmail.com"]
                )
                msg.body = f"""
Nom: {nom}
Email: {email}
Message:
{message}
                """

                mail.send(msg)
                print("✅ Email envoyé")

            except Exception as mail_error:
                print("❌ ERREUR EMAIL:", mail_error)

            return "Message envoyé avec succès ✅"

        except Exception as e:
            return "Erreur serveur: " + str(e)

    return render_template("contact.html")

# =========================
# AUTHENTIFICATION ADMIN
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():  # Vérifie automatiquement CSRF
        email = form.email.data
        password = form.password.data

        ip = request.remote_addr
        now = datetime.now().timestamp()

        # ⛔ Anti-bruteforce
        if ip in FAILED_LOGINS:
            attempts, last_time = FAILED_LOGINS[ip]
            if attempts >= MAX_ATTEMPTS and now - last_time < BLOCK_TIME:
                logging.warning(f"IP BLOQUÉE | ip={ip}")
                return "Trop de tentatives. Réessayez plus tard.", 403
        # 🌍 IP autorisée
        if ip not in ADMIN_ALLOWED_IPS:
            return "Accès refusé (IP)", 403

        # 🔐 Vérification identifiants
        if email == ADMIN_EMAIL and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.permanent = True
            session["admin"] = True
            session["login_time"] = datetime.now().timestamp()
            FAILED_LOGINS.pop(ip, None)
            logging.info(f"LOGIN OK | email={email} | ip={ip}")
            return redirect(url_for("admin"))

        # ❌ Échec login
        FAILED_LOGINS[ip] = (FAILED_LOGINS.get(ip, (0, now))[0] + 1, now)
        logging.warning(f"LOGIN FAIL | email={email} | ip={ip}")
        return "❌ Identifiants incorrects"

    # GET ou formulaire invalide
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    session.clear()
    logging.info(f"ADMIN LOGOUT | ip={request.remote_addr}")
    return redirect(url_for("login"))

# =========================
# ADMIN (PAGINATION)
# =========================
@app.route("/admin")
def admin():
    if not session.get("admin"):
        logging.info(f"ADMIN ACCESS | ip={request.remote_addr}")
        return redirect(url_for("login"))

    login_time = session.get("login_time")

    if not login_time:
        session.clear()
        return redirect(url_for("login"))

    elapsed = datetime.now().timestamp() - login_time

    if elapsed > ADMIN_SESSION_DURATION:
        session.clear()
        return redirect(url_for("login"))
    
    page = request.args.get("page", 1, type=int)
    per_page = 5
    offset = (page - 1) * per_page

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # 📊 Stats
    c.execute("SELECT COUNT(*) FROM messages")
    total_messages = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM messages WHERE lu = 1")
    read_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM messages WHERE lu = 0")
    unread_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM messages WHERE deleted = 1")
    trash_count = c.fetchone()[0]

    # ✅ Total messages
    c.execute("SELECT COUNT(*) FROM messages")
    row = c.fetchone()
    total_messages = row[0] if row else 0

    # 🔴 Messages non lus
    c.execute("SELECT COUNT(*) FROM messages WHERE lu = 0")
    row = c.fetchone()
    unread_count = row[0] if row else 0

    # 🗑 Messages supprimés
    c.execute("SELECT COUNT(*) FROM messages WHERE deleted = 1")
    trash_count = c.fetchone()[0]

    # 📩 Messages paginés (non lus en haut)
    c.execute("""
        SELECT id, nom, email, message, date, lu
        FROM messages
        WHERE deleted = 0
        ORDER BY lu ASC, id DESC
        LIMIT ? OFFSET ?
    """, (per_page, offset))

    total_pages = (total_messages + per_page - 1) // per_page

    form = CSRFOnlyForm()
    # lus
    c.execute("SELECT COUNT(*) FROM messages WHERE lu = 1")
    read_count = c.fetchone()[0]

    # supprimés (si tu as une colonne deleted)
    c.execute("SELECT COUNT(*) FROM messages WHERE deleted = 1")
    trash_count = c.fetchone()[0]

    messages = c.fetchall()
    conn.close()

    return render_template(
        "admin.html",
        messages=messages,
        page=page,
        total_pages=total_pages,
        unread_count=unread_count,
        read_count=trash_count,
        trash_count=trash_count,
        form=form   # 👈 OBLIGATOIRE
    )

# =========================
# ACTION ADMIN (SUPPRIMER / MARQUER LU)
# =========================
@app.route("/admin/delete/<int:msg_id>", methods=["POST"])
def delete_message(msg_id):
    if not session.get("admin"):
        abort(403)

    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        abort(400)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin"))

@app.route("/admin/read/<int:msg_id>", methods=["POST"])
def mark_as_read(msg_id):
    if not session.get("admin"):
        return jsonify(success=False), 403

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("UPDATE messages SET lu = 1 WHERE id = ?", (msg_id,))
    conn.commit()

    # compteur messages non lus
    c.execute("SELECT COUNT(*) FROM messages WHERE lu = 0")
    unread_count = c.fetchone()[0]

    conn.close()

    return jsonify(success=True, unread_count=unread_count)

@app.route("/admin/read-ajax/<int:msg_id>", methods=["POST"])
def delete_message_ajax(msg_id):
    if not session.get("admin"):
        abort(403)

    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        abort(400)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # suppression du message
    c.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    conn.commit()

    # recalcul message non lus
    c.execute("SELECT COUNT(*) FROM messages WHERE lu = 0")
    unread_count = c.fetchone()[0]

    conn.close()

    return jsonify({
        "success": True,
        "unread_count": unread_count
    })

@app.route("/admin/delete-pending/<int:msg_id>", methods=["POST"])
def delete_pending(msg_id):
    if not session.get("admin"):
        abort(403)

    PENDING_DELETIONS[msg_id] = time.time()
    return {"success": True}

@app.route("/admin/delete-confirm/<int:msg_id>", methods=["POST"])
def delete_confirm(msg_id):
    if not session.get("admin"):
        abort(403)

    if msg_id not in PENDING_DELETIONS:
        abort(400)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE messages SET deleted = 1 WHERE id = ?", (msg_id,))
    conn.commit()
    conn.close()

    PENDING_DELETIONS.pop(msg_id, None)
    return {"success": True}

@app.route("/admin/trash")
def admin_trash():
    if not session.get("admin"):
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        SELECT id, nom, email, message, date
        FROM messages
        WHERE deleted = 1
        ORDER BY id DESC
    """)

    messages = c.fetchall()
    conn.close()

    return render_template("admin_trash.html", messages=messages)

@app.route("/admin/restore/<int:msg_id>", methods=["POST"])
def restore_message(msg_id):
    if not session.get("admin"):
        abort(403)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE messages SET deleted = 0 WHERE id = ?", (msg_id,))
    conn.commit()

    # recalcul compteur corbeille
    c.execute("SELECT COUNT(*) FROM messages WHERE deleted = 1")
    trash_count = c.fetchone()[0]

    conn.close()

    return jsonify(success=True, trash_count=trash_count)

@app.route("/admin/delete-permanent/<int:msg_id>", methods=["POST"])
def delete_permanent(msg_id):
    if not session.get("admin"):
        abort(403)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_trash"))

@app.route("/admin/trash/empty", methods=["POST"])
def empty_trash():
    if not session.get("admin"):
        abort(403)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM messages WHERE deleted = 1")
    conn.commit()
    conn.close()

    flash("🧹 Corbeille vidée avec succès", "success")
    return redirect(url_for("trash"))

@app.route("/admin/trash/clear", methods=["POST"])
def clear_trash():
    if not session.get("admin"):
        abort(403)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # supprimer définitivement
    c.execute("DELETE FROM messages WHERE deleted = 1")
    conn.commit()
    conn.close()

    return jsonify(success=True)

@app.route("/admin/export/excel")
def export_excel():
    if not session.get("admin"):
        abort(403)

    conn = sqlite3.connect(DB_NAME)

    df = pd.read_sql_query(
        "SELECT id, nom, email, message, date, lu FROM messages WHERE deleted = 0",
        conn
    )

    conn.close()

    # convertir lu → texte
    df["lu"] = df["lu"].apply(lambda x: "Lu" if x == 1 else "Non lu")

    output = io.BytesIO()
    df.to_excel(output, index=False, engine="openpyxl")
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="messages.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

@app.route("/admin/export/pdf")
def export_pdf():
    if not session.get("admin"):
        abort(403)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("SELECT nom, email, message, date, lu FROM messages WHERE deleted = 0")
    data = c.fetchall()
    conn.close()

    # préparation données
    table_data = [["Nom", "Email", "Message", "Date", "Statut"]]

    for row in data:
        statut = "Lu" if row[4] == 1 else "Non lu"
        table_data.append([row[0], row[1], row[2], row[3], statut])

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(buffer)
    table = Table(table_data)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.black)
    ]))

    doc.build([table])

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="messages.pdf",
        mimetype="application/pdf"
    )

# =========================
# LANCEMENT
# =========================
if __name__ == "__main__":
    app.run(debug=True)
