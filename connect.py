import os
import datetime
import requests
from flask import Flask, redirect, request, session, render_template
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "sjfkdj38yechijneoaw"
app.permanent_session_lifetime = timedelta(minutes=10)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Only for local testing

CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = [
    "https://www.googleapis.com/auth/fitness.activity.read",
    "https://www.googleapis.com/auth/fitness.heart_rate.read",
    "https://www.googleapis.com/auth/fitness.sleep.read"
]
REDIRECT_URI = "http://localhost:5000/callback"  # ✅ Matches your updated client_secret.json

@app.route("/")
def index():
    return '<a href="/authorize">📲 Connect Google Fit</a>'

@app.route("/authorize")
def authorize():
    session.permanent = True
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    state = session.get("state") or request.args.get("state")
    if not state:
        return "⚠️ Session expired or state missing. <a href='/authorize'>Try again</a>."

    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
            state=state
        )
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        session["credentials"] = credentials_to_dict(credentials)
        return redirect("/dashboard")
    except Exception as e:
        return f"OAuth Error: {e}. <a href='/'>Try again</a>"

@app.route("/dashboard")
def dashboard():
    if "credentials" not in session:
        return redirect("/")

    creds = Credentials(**session["credentials"])

    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        session["credentials"] = credentials_to_dict(creds)

    headers = {"Authorization": f"Bearer {creds.token}"}
    now = datetime.datetime.now()
    start = int((now - datetime.timedelta(days=1)).timestamp() * 1000)
    end = int(now.timestamp() * 1000)

    def fetch_total(data_type):
        try:
            res = requests.post(
                "https://www.googleapis.com/fitness/v1/users/me/dataset:aggregate",
                headers=headers,
                json={
                    "aggregateBy": [{"dataTypeName": data_type}],
                    "bucketByTime": {"durationMillis": 86400000},
                    "startTimeMillis": start,
                    "endTimeMillis": end
                }
            ).json()
            points = res.get("bucket", [])[0].get("dataset", [])[0].get("point", [])
            return sum(v.get("fpVal", v.get("intVal", 0)) for p in points for v in p.get("value", []))
        except Exception as e:
            print(f"[ERROR] {data_type}: {e}")
            return 0

    def fetch_average(data_type):
        try:
            res = requests.post(
                "https://www.googleapis.com/fitness/v1/users/me/dataset:aggregate",
                headers=headers,
                json={
                    "aggregateBy": [{"dataTypeName": data_type}],
                    "bucketByTime": {"durationMillis": 86400000},
                    "startTimeMillis": start,
                    "endTimeMillis": end
                }
            ).json()
            points = res.get("bucket", [])[0].get("dataset", [])[0].get("point", [])
            values = [v.get("fpVal", 0) for p in points for v in p.get("value", [])]
            return round(sum(values) / len(values), 1) if values else 0
        except Exception as e:
            print(f"[ERROR] {data_type}: {e}")
            return 0

    def fetch_sleep_duration():
        try:
            res = requests.post(
                "https://www.googleapis.com/fitness/v1/users/me/dataset:aggregate",
                headers=headers,
                json={
                    "aggregateBy": [{"dataTypeName": "com.google.sleep.segment"}],
                    "bucketByTime": {"durationMillis": 86400000},
                    "startTimeMillis": start,
                    "endTimeMillis": end
                }
            ).json()
            total_ms = 0
            for bucket in res.get("bucket", []):
                for dataset in bucket.get("dataset", []):
                    for point in dataset.get("point", []):
                        if point["value"][0].get("intVal") == 1:
                            start_ns = int(point["startTimeNanos"])
                            end_ns = int(point["endTimeNanos"])
                            total_ms += (end_ns - start_ns) / 1e6
            return round(total_ms / 3600000, 2)
        except Exception as e:
            print(f"[ERROR] sleep.segment: {e}")
            return 0

    # Final metrics
    steps = fetch_total("com.google.step_count.delta")
    calories = fetch_total("com.google.calories.expended")
    heart_rate = fetch_average("com.google.heart_rate.bpm")
    sleep_hours = fetch_sleep_duration()

    return render_template("dashboard.html",
                           steps=int(steps),
                           calories=round(calories, 2),
                           heart_rate=heart_rate,
                           sleep_minutes=round(sleep_hours * 60))

def credentials_to_dict(credentials):
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes
    }

if __name__ == "__main__":
    app.run(debug=True)
