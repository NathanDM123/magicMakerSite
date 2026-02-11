from flask import Flask, render_template, redirect, url_for, session, request, abort
import os
import pymongo
import bcrypt
from bson.objectid import ObjectId
from bson.errors import InvalidId
from dotenv import load_dotenv
import re
from datetime import datetime, timedelta, timezone
import time
import secrets
from mail_utils import send_verification_email

load_dotenv()

app = Flask(__name__)
app.secret_key = "6af3255620cb90e9bc3c0dc05bbe80481482f9d85af8feff" # mieux -> os.urandom(24) (en prod, en dev pas besoin)

mongo_uri = os.getenv("MONGO_URI")
client = pymongo.MongoClient(mongo_uri)
db = client['db'] 

db_utils = db.utilisateurs
db_pendingu = db.pending_users

EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)

def is_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

def get_username(id):
    if not id:
        return None
    
    try:
        user = db_utils.find_one({"_id": ObjectId(id)}, {"username": 1})
        return user['username'] if user else None
    except(InvalidId, TypeError):
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/test')
def test():
    return render_template('test.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if 'util' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        user = request.form['user']
        pswd = request.form['password']
        mail = request.form['email']

        if db_utils.find_one({'username': user}):
            return render_template('register.html', erreur="Nom d'utilisateur déjà pris")
        
        if db_utils.find_one({'email': mail}):
            return render_template('register.html', erreur="Email deja utilisée")
        
        if len(pswd) < 8 or not any(c.isdigit() for c in pswd):
            return render_template('register.html', erreur="Le mot de passe doit contenir au moins 8 caracteres dont minimum 1 chiffre")
        
        if not pswd == request.form['confirm_password']:
            return render_template("register.html", erreur="Les mots de passe ne correspondent pas")
        
        if not is_email(mail):
            return render_template('register.html', erreur="C'est pas un email ca 🤦‍♂️")
        
        pswd_hash = bcrypt.hashpw(pswd.encode('utf-8'), bcrypt.gensalt())

        code = f"{secrets.randbelow(1_000_000):06d}"

        db_pendingu.delete_many({"email": mail})

        db_pendingu.insert_one({
            "email": mail,
            "user": user,
            "password": pswd_hash,
            "code": code,
            "essais": 0,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
        })

        send_verification_email(mail, code)

        session['pending_user'] = mail
        return redirect(url_for('verify_email'))
    else:
        return render_template('register.html')    
    
@app.route("/login", methods=['GET', 'POST'])
def login():
    if 'util' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        user = request.form['user']
        pswd = request.form['password']

        user_found = db_utils.find_one({'username': user})

        if not user_found or not bcrypt.checkpw(pswd.encode('utf-8'), user_found['password']):
            return render_template("login.html", erreur="Identifiants incorrects")
        
        session['util'] = str(user_found['_id'])
        return redirect(url_for('index'))
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/verify_email", methods=['GET', 'POST'])
def verify_email():
    mail = session.get('pending_user')
    if not mail:
        return redirect(url_for('register'))
    
    pending_user = db_pendingu.find_one({"email": mail})
    if not pending_user:
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        code_input = request.form['code']

        if datetime.now(timezone.utc) > pending_user['expires_at'].replace(tzinfo=timezone.utc):
            db_pendingu.delete_one({"_id": pending_user["_id"]})
            return render_template("register.html", erreur="Code expiré")

        if pending_user['essais'] >= 5:
            db_pendingu.delete_one({"_id": pending_user["_id"]})
            return render_template("verify_mail.html", erreur="Trop de tentative, recommence l'inscription")
        
        if code_input != pending_user['code']:
            db_pendingu.update_one(
                {"_id": pending_user["_id"]},
                {"$inc": {"essais": 1}}
            )
            return render_template("verify_mail.html", erreur="Code incorrect")
        
        result = db_utils.insert_one({
            "username": pending_user['user'],
            "password": pending_user['password'],
            "email": pending_user['email'],
            "role": "user"
        })

        db_pendingu.delete_one({"_id": pending_user["_id"]})
        session.pop('pending_user', None)
        session['util'] = str(result.inserted_id)

        return redirect(url_for('index'))
    else:
        return render_template("verify_mail.html")
    #apres 1H30 ca fonctionne...
    

app.run(host="127.0.0.1", port=81) # A CHANGER EN PROD PAS DE 127.0.0.1!!! -> 0.0.0.0 en prod