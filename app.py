import os
import requests

from flask import Flask, session, abort, redirect, request
from pip._vendor import cachecontrol
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from google.oauth2 import id_token
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET"]
GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
client_secrets_file = "client_secret.json"

# Bypass OAuth requirement for HTTPS
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email", 
        "openid"
    ],
    redirect_uri="http://localhost:5000/callback"
)

def login_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            abort(401) # Unauthorized
        else:
            return function()
    return wrapper

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session["state"] == request.args["state"]:
        abort(500) # State does not match

    credentials = flow.credentials
    request_session = requests.session()
    # Not sure how significant this next line is
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    
    session["google_id"] = id_info["sub"]
    session["name"] = id_info["name"]
    return redirect("/protected_area")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    return "Hello World! <a href='/login'><button>Login</button></a>"

# Decorators are evaluated from bottom to top
@app.route("/protected_area")
@login_required
def protected_area():
    return "Protected! <a href='/logout'><button>Logout</button></a>"

if __name__ == "__main__":
    app.run(debug=True)