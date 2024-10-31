"""Python Flask WebApp Auth0 integration example
"""

import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
import requests
from flask import Flask, redirect, render_template, session, url_for, request, jsonify


from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for

def update_user_metadata(user_id, metadata):
    url = f'https://{env.get("AUTH0_DOMAIN")}/api/v2/users/{user_id}'
    
    headers = {
        'Authorization': f'Bearer {["access_token"]}',
        'Content-Type': 'application/json'
    }

    data = {
        "user_metadata": metadata
    }

    # Realiza la solicitud PATCH a la API
    response = requests.patch(url, json=data, headers=headers)

    # Log del contenido de la respuesta para diagnóstico
    print("Respuesta")
    print({user_id})
    app.logger.info(f"Respuesta de la API: {response.status_code}, {response.text}")
    if response.status_code == 200:
        return response.json()
    else:
        app.logger.error(f'Error en la actualización: {session["user"]["access_token"]}')  # Línea corregida
        raise Exception(f"Error en la actualización: {response.status_code}, {response.text}")

     
   


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")


oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email read:current_user update:current_user_metadata",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
     authorize_params={
        "audience": f'https://{env.get("AUTH0_DOMAIN")}/api/v2/'
    }
)


# Controllers API
@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    # Obtén el token de acceso
    token = oauth.auth0.authorize_access_token()
    
    # Guarda la información del token en la sesión
    session["user"] = token
    
    # Llama a la API para obtener información del usuario
    userinfo_url = f'https://{env.get("AUTH0_DOMAIN")}/userinfo'
    headers = {'Authorization': f'Bearer {session["user"]["access_token"]}',
    'Content-Type': 'application/json'}
    userinfo_response = requests.get(userinfo_url, headers=headers)
    
    # Asegúrate de que la respuesta sea exitosa
    if userinfo_response.status_code == 200:
        userinfo = userinfo_response.json()
        app.logger.info(f"Información del usuario: {userinfo}")  # Imprimir para verificar
        session["user"] ["sub"] = userinfo.get("sub")  # Almacena 'sub' en la sesión
        session["user"]["userinfo"] = userinfo
    else:
        app.logger.error(f"Error obteniendo información del usuario: {userinfo_response.text}")

    return redirect("/")

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route("/update-metadata", methods=["POST"])
def update_metadata():
    if "user" not in session:
        return redirect(url_for("login"))

    # Imprimir la sesión para verificar su contenido
    app.logger.info(f"Contenido de la sesión: {session}")

    try:
        data = request.json
        if not data:
            return jsonify({"success": False, "error": "No metadata provided"}), 400
        
        # Aquí es donde puede fallar
        user_id =session["user"]["userinfo"]["sub"] 
        metadata = data

        app.logger.info(f"user id: {user_id}")
        result = update_user_metadata(user_id, metadata)
        
        return jsonify({"success": True, "data": result}), 200
    except KeyError as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({"success": False, "error": f"KeyError: {str(e)}"}), 400
    except Exception as e:
        app.logger.error(f"Error con la metadata: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))
