
from flask import Flask, render_template, request
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import secrets
import os
import re
from contextlib import closing
import psycopg2
from psycopg2 import sql

app = Flask(__name__)

dbHost = os.environ.get("DB_HOST", "localhost")
dbPort = int(os.environ.get("DB_PORT", "5432"))

tempName = re.compile(r"^temp_[0-9a-f]{8}$")
tier = "db_read_only"

#Internal helper method to check environment variable
def _env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Set the {name} environment variable first.")
    return value
#Connect to database
def _db_conn():
    return psycopg2.connect(host=dbHost, port=dbPort, dbname="accessdb",
                            user="broker_web", password=_env("BROKER_WEB_PW"))

def get_engineer_hash(username):
    """Return the stored password hash for an active engineer, else None."""
    with closing(_db_conn()) as conn, conn, conn.cursor() as cur:
        cur.execute("SELECT password_hash FROM broker.engineers "
                    "WHERE username = %s AND active", (username,))
        row = cur.fetchone()
    return row[0] if row else None


# Generate temporary username and password
def generate_credentials():
    # "temp" + the code generates a 4 random bytes and then turns them into hex to make 8 characters to append to that "temp" section
    username = "temp_" + secrets.token_hex(4)
    # Generates a 24 byte random string of characters that is encoded in URL safe Base64 that is 32 characters long
    password = secrets.token_urlsafe(24)

    return username, password

#Craetes database login and logs grant
def create_database_access(username, password, engineer, reason, duration, expires):
    if not tempName.match(username):
        return False
 
    try:
        with closing(_db_conn()) as conn, conn.cursor() as cur:
            who = sql.Identifier(username)
            # VALID UNTIL only accepts a plain string, so send the time as text
            # (UTC). PostgreSQL itself then refuses new logins past this time,
            # even if nothing else (this app, a cleanup job, etc.) is running.
            until = expires.astimezone(timezone.utc).isoformat()
            cur.execute(sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} VALID UNTIL {} "
                "CONNECTION LIMIT 2 NOSUPERUSER NOCREATEDB NOCREATEROLE"
            ).format(who, sql.Literal(password), sql.Literal(until)))
            cur.execute(sql.SQL("GRANT {} TO {}")
                       .format(sql.Identifier(tier), who))
            cur.execute(sql.SQL("ALTER ROLE {} SET statement_timeout = '30s'")
                       .format(who))
            conn.commit()
    except Exception:
        return False
 
    try:
        with closing(_db_conn()) as conn, conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO broker.access_grants "
                "(engineer_id, temp_username, reason, duration_min, expires_at) "
                "SELECT id, %s, %s, %s, %s FROM broker.engineers "
                "WHERE username = %s AND active",
                (username, reason, duration, expires, engineer))
            if cur.rowcount != 1:
                raise RuntimeError("engineer not found or inactive")
    except Exception:
        _drop_login_quietly(username)
        return False
 
    return True

def _drop_login_quietly(username):
    try:
        with closing(_db_conn()) as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (username,))
            if cur.fetchone() is None:
                return
            who = sql.Identifier(username)
            cur.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(who))
            cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                       "WHERE usename = %s", (username,))
            cur.execute(sql.SQL("DROP ROLE {}").format(who))
            conn.commit()
    except Exception:
        pass


# Display HTML page
@app.route("/")
def index():
    return render_template("index.html")


# Process access request
@app.route("/request-access", methods=["POST"])
def request_access():

    engineer = request.form.get("username", "")
    password = request.form.get("password", "")
    reason = request.form.get("reason", "").strip()

    # Check engineer login (broker.engineers table in accessdb)
    stored_hash = get_engineer_hash(engineer)
 
    if stored_hash is None or not check_password_hash(stored_hash, password):
        return "Invalid login.", 401

    # Check reason and duration
    if not reason:
        return "Reason for access is required.", 400

    # Some input sanitization for the duration so the time cannot be < 15 or > 60 minutes
    try:
        duration = int(request.form.get("duration", "0"))
    except ValueError:
        return "Invalid duration.", 400

    if duration not in (15, 30, 60):
        return "Invalid duration.", 400

    # Generate credentials and expiration
    username, temp_password = generate_credentials()
    expires = datetime.now(timezone.utc) + timedelta(minutes=duration)

    # Send to database function
    success = create_database_access(
        username, temp_password, engineer, reason, duration,expires
    )

    if not success:
        return "Database access failed.", 500



    # I have no idea what this does, it was in the template I made, def need to find a new solution to display a different HTML page with the creds.

    # Display generated credentials
    return f"""
    <h2>Temporary Credentials (Demo)</h2>

    <p><b>Engineer:</b> {escape(engineer)}</p>
    <p><b>Username:</b> {escape(username)}</p>
    <p><b>Password:</b> {escape(temp_password)}</p>
    <p><b>Expires:</b> {expires.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

    <p>No real database account has been created yet.</p>

    <a href="/">Return to Request Page</a>
    """


if __name__ == "__main__":
    app.run(debug=True)
