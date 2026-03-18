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
from werkzeug.utils import secure_filename

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

load_dotenv()

app = Flask(__name__)
app.secret_key = "6af3255620cb90e9bc3c0dc05bbe80481482f9d85af8feff" # mieux -> os.urandom(24) (en prod, en dev pas besoin)

mongo_uri = os.getenv("MONGO_URI")
client = pymongo.MongoClient(mongo_uri)
db = client['db'] 

db_utils = db.utilisateurs
db_pendingu = db.pending_users
db_posts = db.posts
db_categories = db.categories
db_comments = db.comments

EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

if db_categories.count_documents({}) == 0:
    db_categories.insert_many([
        {"nom": "Général"},
        {"nom": "Technologie"},
        {"nom": "Jeux Vidéo"},
        {"nom": "Humour"}
    ])

def is_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

def slugify(text):
    text = text.lower()
    text = re.sub(r'\s+', '-', text) 
    return re.sub(r'[^\w\-]', '', text)

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
        
        if not mail == "test123@e" and not is_email(mail):
            return render_template('register.html', erreur="C'est pas un email ca 🤦‍♂️")
        
        pswd_hash = bcrypt.hashpw(pswd.encode('utf-8'), bcrypt.gensalt())

        if mail == "test123@e":
            result = db_utils.insert_one({
                "username": user,
                "password": pswd_hash,
                "email": "no_mail",
                "role": "user"
            })

            session['util'] = str(result.inserted_id)
            return redirect(url_for('index'))

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
        session['username'] = user_found['username']
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
    
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'util' not in session:
        return redirect(url_for('login'))

    categories = list(db_categories.find().sort("nom", 1))

    if request.method == 'POST':
        titre = request.form.get('titre', '').strip()
        description = request.form.get('description', '').strip()
        categorie_id = request.form.get('categorie')
        nouvelle_cat = request.form.get('nouvelle_categorie', '').strip()
        file = request.files.get('image')

        if not titre or len(titre) < 5 or len(titre) > 100:
            return render_template('create_post.html', categories=categories, erreur="Le titre doit faire entre 5 et 100 caractères.")
        
        if not description or len(description) > 5000:
            return render_template('create_post.html', categories=categories, erreur="Description trop longue ou vide.")

        final_cat = ""
        if categorie_id == "new" and nouvelle_cat:
            if not db_categories.find_one({"nom": nouvelle_cat}):
                db_categories.insert_one({"nom": nouvelle_cat})
            final_cat = nouvelle_cat
        else:
            cat_doc = db_categories.find_one({"_id": ObjectId(categorie_id)})
            final_cat = cat_doc['nom'] if cat_doc else "Général"

        image_filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{int(time.time())}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_filename = filename

        db_posts.insert_one({
            "titre": titre,
            "description": description,
            "categorie": final_cat,
            "image": image_filename,
            "auteur_id": ObjectId(session['util']),
            "auteur_name": get_username(session['util']),
            "created_at": datetime.now(timezone.utc)
        })

        return redirect(url_for('index'))

    return render_template('create_post.html', categories=categories)



@app.route('/<categorie>/<post_id>')
def view_post(categorie, post_id):
    try:
        post = db_posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            abort(404)
        
        comments = list(db_comments.find({"post_id": ObjectId(post_id)}).sort("created_at", -1))
        
        return render_template('view_post.html', post=post, comments=comments)
    except (InvalidId, TypeError):
        abort(404)

@app.route('/categories')
def categories():
    categories = list(db_categories.find())
    for categorie in categories:
        categorie['count'] = db_posts.count_documents({'categorie': categorie['nom']})
    return render_template('categories.html', categories=categories)

@app.route('/c/<categorie>')
def view_categorie(categorie):
    cat = db_categories.find_one({'nom': categorie})
    if not cat:
        abort(404)
    posts = list(db_posts.find({'categorie': categorie}).sort('created_at', -1))
    return render_template('categorie.html', categorie=categorie, posts=posts)
    

@app.route('/comment/<post_id>', methods=['POST'])
def add_comment(post_id):
    if 'util' not in session:
        return redirect(url_for('login'))

    contenu = request.form.get('commentaire', '').strip()
    
    if not contenu or len(contenu) > 1000:
        return redirect(request.referrer)

    post = db_posts.find_one({"_id": ObjectId(post_id)})
    if not post:
        abort(404)

    db_comments.insert_one({
        "post_id": ObjectId(post_id),
        "auteur_id": ObjectId(session['util']),
        "auteur_name": get_username(session['util']),
        "contenu": contenu,
        "created_at": datetime.now(timezone.utc)
    })

    return redirect(request.referrer)
    

app.run(host="127.0.0.1", port=81) # A CHANGER EN PROD PAS DE 127.0.0.1!!! -> 0.0.0.0 en prod