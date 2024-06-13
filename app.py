from dash import Dash, html, dcc, Input, Output, State, ALL, ctx
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
app = Dash(
    __name__,
    server=server,
    external_stylesheets=[dbc.themes.BOOTSTRAP],
    prevent_initial_callbacks="initial_duplicate",
)

app.title = "Simple Authentication Example"


def load_user_db():
    try:
        with open("users_db.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        os.exit("users_db.json not found. Please create the file.")


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
        {"hash": hash_secret(token), "expiration": time.time() + 31536000}
    )
    save_user_db(users_db)
    return token


def authenticate(login_code=None, web_app_token=None):
    data = load_user_db()

    if login_code:
        login_code_hash = hash_secret(login_code)
        for email, user_data in data.items():
            for code in user_data.get("login_codes", []):
                if code["hash"] == login_code_hash and code["expiration"] > int(
                    time.time()
                ):
                    user_data["login_codes"].remove(code)
                    save_user_db(data)
                    return {
                        "email": email,
                        "name": user_data["name"],
                    }

    if web_app_token:
        hashed_token = hash_secret(web_app_token)
        for email, user_data in data.items():
            for token in user_data.get("tokens", []):
                if token["hash"] == hashed_token and token["expiration"] > int(
                    time.time()
                ):
                    return {
                        "email": email,
                        "name": user_data["name"],
                    }

    return False


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


def random_index():
    return random.randint(0, 999999)


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
                    [
                        dbc.Col(
                            id={"type": "toggle-element", "index": random_index()},
                            className="show-logged-out d-none",
                            children=[
                                html.H2("Welcome! Please log in."),
                            ],
                        ),
                        dbc.Col(
                            id={"type": "toggle-element", "index": random_index()},
                            className="show-logged-in d-none",
                            children=[
                                html.H2("Welcome back! You are logged in."),
                            ],
                        ),
                    ]
                ),
                dbc.Row(
                    id={"type": "toggle-element", "index": random_index()},
                    className="show-logged-out d-none",
                    children=dbc.Col(
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
                            html.Div(id="login-status"),
                        ],
                        className="d-flex flex-column align-items-center justify-content-center",
                    ),
                ),
            ]
        ),
        dcc.Store(id="authenticated", storage_type="local"),
        dcc.Store(id="dash_app_context", storage_type="local"),
        dcc.Input(id="page-load-trigger", type="hidden", value="trigger"),
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
    [
        Output("authenticated", "data", allow_duplicate=True),
        Output("dash_app_context", "data", allow_duplicate=True),
    ],
    [
        Input("url", "search"),
        Input("login-code-input", "value"),
        Input("dash_app_context", "data"),
    ],
)
def handle_login(search, login_code_input, dash_app_context):
    # todo: only trigger login_code check if it's the right length
    login_code_from_url = parse_qs(search.lstrip("?")).get("login_code", [None])[0]
    login_code_entered = login_code_input
    login_code = login_code_entered or login_code_from_url
    web_app_token = dash_app_context.get("web_app_token") if dash_app_context else None

    if user := authenticate(login_code=login_code, web_app_token=web_app_token):
        return (
            True,
            {
                "web_app_token": web_app_token or save_token(user["email"]),
                "user": user,
            },
        )
    else:
        return (
            False,
            {"web_app_token": None},
        )


# handle logout
@app.callback(
    [
        Output("authenticated", "data"),
        Output("dash_app_context", "data"),
        Output("email-form", "style", allow_duplicate=True),
        Output("code-form", "style", allow_duplicate=True),
    ],
    [Input("logout-btn", "n_clicks")],
    prevent_initial_call=True,
)
def handle_logout(n_clicks):
    return False, {"web_app_token": None}, {"display": "block"}, {"display": "none"}


@app.callback(
    Output("user-display", "children"),
    Input("authenticated", "data"),
    State("dash_app_context", "data"),
)
def update_user_display(authenticated, dash_app_context):
    if authenticated:
        return f"Hello, {dash_app_context['user']['name']}"
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


# Callback to show/hide elements based on login state using pattern-matching
@app.callback(
    Output({"type": "toggle-element", "index": ALL}, "className"),
    [Input("authenticated", "data"), Input("page-load-trigger", "value")],
    [
        State({"type": "toggle-element", "index": ALL}, "id"),
        State({"type": "toggle-element", "index": ALL}, "className"),
    ],
)
def update_element_visibility(authenticated, trigger, ids, current_classes):
    updated_classes = []
    for i, element_id in enumerate(ids):
        if (
            current_classes[i] is None
        ):  # this shouldn't happen because the element should have a class defining whether it should be shown or hidden
            current_classes[i] = ""

        class_to_add = None

        # update the class list based on the login state and display class
        if "show-logged-in" in current_classes[i]:
            if authenticated:
                # remove d-none from the class list
                current_classes[i] = current_classes[i].replace("d-none", "")
            else:
                class_to_add = "d-none"

        elif "show-logged-out" in current_classes[i]:
            if not authenticated:
                # remove d-none from the class list
                current_classes[i] = current_classes[i].replace("d-none", "")
            else:
                class_to_add = "d-none"

        else:
            updated_classes.append(current_classes[i])
            continue

        if class_to_add and class_to_add not in current_classes[i]:
            updated_classes.append(current_classes[i] + " " + class_to_add)
        else:
            updated_classes.append(current_classes[i])

    return updated_classes


if __name__ == "__main__":
    app.run_server(debug=True)
