
from flask import Flask, render_template, request
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import secrets

app = Flask(__name__)

# Temporary engineer login for testing we can remove this later after hooking up to ur database
engineers = {
    "engineer01": generate_password_hash("TestPassword123!")
}


# Generate temporary username and password
def generate_credentials():
    # "temp" + the code generates a 4 random bytes and then turns them into hex to make 8 characters to append to that "temp" section
    username = "temp_" + secrets.token_hex(4)
    # Generates a 24 byte random string of characters that is encoded in URL safe Base64 that is 32 characters long
    password = secrets.token_urlsafe(24)

    return username, password


# Placeholder for the database code
def create_database_access(username, password, engineer, reason, expires):

    print("Engineer:", engineer)
    print("Temporary Username:", username)
    print("Reason:", reason)
    print("Expires:", expires)

    # Send information to database section
    return True


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

    # Check engineer login
    if engineer not in engineers:
        return "Invalid login.", 401

    if not check_password_hash(engineers[engineer], password):
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
        username, temp_password, engineer, reason, expires
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
