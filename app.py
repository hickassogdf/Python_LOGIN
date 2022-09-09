import pathlib
from flask import Flask, session, abort, redirect, request
from google_auth_oauthlib.flow import Flow
import os
import requests_oauthlib
import requests
import cachecontrol
import google.auth.transport.requests
from google.oauth2 import id_token

app = Flask(__name__)
app.secret_key = "loginapp.com"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "1065778933497-mddeifli8thhoc1q0cqk1lnj3pgcl24f.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback" 
    )



def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else: 
            return function()
    return wrapper 

#define url /login 
@app.route("/login")
#login
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

#receive the data from google endpoint
@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)
    credentials = flow.credentials
    request_session = request.session()
    cached_session = cachecontrol.Cachecontrol(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    return id_info



#clear local session
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    return "Hello World  <a href='/login'><button>Login</button></a>"

#protected area to show only if the user is logged 
@app.route("/protected_area")
@login_is_required
def protected_area():
    return "Protected <a href='/logout'><button>Logout</button></a>"



if __name__ == '__main__':
    app.run(debug=True)





