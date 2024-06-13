from dash import Dash, html, dcc, Input, Output, State
import dash_bootstrap_components as dbc
import boto3
from botocore.exceptions import ClientError
import os
import time
import logging
from secrets import token_urlsafe
from urllib.parse import parse_qs
from flask import Flask
import random
import json
from dotenv import load_dotenv

load_dotenv()

# Initialize the Dash application
server = Flask(__name__)
app = Dash(__name__, server=server, external_stylesheets=[dbc.themes.BOOTSTRAP])

app.title = "Simple Authentication Example"


def load_user_db():
    with open("users_db.json", "r") as f:
        return json.load(f)


def save_user_db(users_db):
    with open("users_db.json", "w") as f:
        json.dump(users_db, f)


def hash_secret(secret):
    # Dummy hash function (use a proper hashing function in production)
    return secret[::-1]


def save_token(email):
    token = token_urlsafe(16)
    users_db = load_user_db()
    users_db[email]["tokens"].append(
        {"token": hash_secret(token), "expiration": time.time() + 31536000}
    )
    save_user_db(users_db)
    return token


def authenticate(token):
    hashed_token = hash_secret(token)
    users_db = load_user_db()
    for email, data in users_db.items():
        for t in data["tokens"]:
            if t["token"] == hashed_token and t["expiration"] > time.time():
                return email, data["name"]
    return None, None


def send_magic_link(email, login_code):
    ses_client = boto3.client("ses", region_name=os.getenv("AWS_REGION"))
    sender = os.getenv("AWS_SES_SENDER_EMAIL")
    subject = "Your Login Code"
    body_html = f"""
    <html>
        <body>
            <center>
                <h1>Your Login Code</h1>
                <p>Please use this code to log in:</p>
                <p>{login_code}</p>
                <p>Alternatively, you can click this link to log in: 
                    <a href='http://localhost:8050/?login_code={login_code}'>Log In</a>
                </p>
            </center>
        </body>
    </html>
    """
    try:
        response = ses_client.send_email(
            Destination={"ToAddresses": [email]},
            Message={
                "Body": {"Html": {"Charset": "UTF-8", "Data": body_html}},
                "Subject": {"Charset": "UTF-8", "Data": subject},
            },
            Source=sender,
        )
        logging.info(f"Email sent! Message ID: {response['MessageId']}")
        return "A login code has been sent to your email. Please enter the code below or click the link in the email."
    except ClientError as e:
        logging.error(f"Failed to send email: {e}")
        return "Failed to send email."


def get_login_code_from_url(search):
    if not search:
        return None

    query_params = parse_qs(search.lstrip("?"))
    return query_params.get("login_code", [None])[0]


# Layout
app.layout = html.Div(
    [
        dcc.Location(id="url", refresh=False),
        dbc.Navbar(
            dbc.Container(
                [
                    dbc.NavbarBrand("Simple Authentication Example", className="ml-2"),
                    dbc.NavbarToggler(id="navbar-toggler"),
                    dbc.Collapse(
                        dbc.Nav(
                            [
                                dbc.NavItem(
                                    dbc.NavLink(
                                        "Settings", id="settings-btn", className="ml-2"
                                    )
                                ),
                                dbc.NavItem(
                                    dbc.NavLink(id="user-display", className="ml-2")
                                ),
                                dbc.NavItem(
                                    dbc.NavLink(
                                        "Logout", id="logout-btn", className="ml-2"
                                    )
                                ),
                            ],
                            navbar=True,
                        ),
                        id="navbar-collapse",
                        navbar=True,
                    ),
                ]
            ),
            color="dark",
            dark=True,
        ),
        dbc.Container(
            [
                dbc.Row(
                    dbc.Col(
                        [
                            html.Div(
                                id="login-form",
                                children=[
                                    html.Div(
                                        id="email-form",
                                        children=[
                                            dbc.Input(
                                                id="email-input",
                                                placeholder="Enter your email",
                                                type="email",
                                                className="mb-2",
                                            ),
                                            dbc.Button(
                                                "Send Login Code",
                                                id="send-link-btn",
                                                n_clicks=0,
                                                className="mb-2",
                                            ),
                                        ],
                                    ),
                                    html.Div(
                                        id="code-form",
                                        style={"display": "none"},
                                        children=[
                                            html.Div(
                                                id="email-status",
                                                className="text-center",
                                            ),
                                            dbc.Input(
                                                id="login-code-input",
                                                placeholder="Enter login code",
                                                type="text",
                                                className="mb-2",
                                            ),
                                            dbc.Button(
                                                "Login",
                                                id="login-btn",
                                                n_clicks=0,
                                                className="mb-2",
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            html.Div(id="login-status", className="text-center"),
                        ],
                        className="d-flex flex-column align-items-center justify-content-center",
                    )
                ),
            ]
        ),
        dcc.Store(id="authenticated", storage_type="local"),
    ]
)


# Callbacks
@app.callback(
    [
        Output("email-status", "children"),
        Output("email-form", "style"),
        Output("code-form", "style"),
    ],
    [Input("send-link-btn", "n_clicks")],
    [State("email-input", "value")],
)
def handle_send_link(n_clicks, email):
    if n_clicks > 0 and email:
        login_code = "".join(random.choices("0123456789", k=6))
        users_db = load_user_db()
        if email in users_db:
            users_db[email].setdefault("login_codes", []).append(
                {
                    "hash": hash_secret(login_code),
                    "expiration": int(time.time()) + 300,  # 5 minutes expiration
                }
            )
            save_user_db(users_db)
            return (
                send_magic_link(email, login_code),
                {"display": "none"},
                {"display": "block"},
            )
        return (
            "Email not found in the database.",
            {"display": "block"},
            {"display": "none"},
        )
    return "", {"display": "block"}, {"display": "none"}


@app.callback(
    Output("login-status", "children"),
    Output("authenticated", "data"),
    [Input("login-btn", "n_clicks"), Input("url", "search")],
    [State("login-code-input", "value")],
)
def handle_login(n_clicks, search, login_code_input):
    login_code = login_code_input or get_login_code_from_url(search)
    if login_code:
        users_db = load_user_db()
        for email, data in users_db.items():
            for code in data.get("login_codes", []):
                if (
                    code["hash"] == hash_secret(login_code)
                    and code["expiration"] > time.time()
                ):
                    data["login_codes"].remove(code)
                    save_user_db(users_db)
                    token = save_token(email)
                    return f"Welcome, {data['name']}!", {
                        "email": email,
                        "name": data["name"],
                        "token": token,
                    }
        return "Invalid or expired login code.", None
    return "", None


@app.callback(Output("user-display", "children"), Input("authenticated", "data"))
def update_user_display(authenticated):
    if authenticated:
        return f"Hello, {authenticated['name']}"
    return ""


@app.callback(
    Output("navbar-collapse", "is_open"),
    [Input("navbar-toggler", "n_clicks")],
    [State("navbar-collapse", "is_open")],
)
def toggle_navbar(n_clicks, is_open):
    if n_clicks:
        return not is_open
    return is_open


@app.callback(Output("url", "href"), Input("logout-btn", "n_clicks"))
def logout(n_clicks):
    if n_clicks:
        return "/?logout=true"
    return "/"


if __name__ == "__main__":
    app.run_server(debug=True)
