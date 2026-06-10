from flask import Flask, render_template, redirect, url_for, session, request, abort, flash
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

load_dotenv()

app = Flask(__name__)
app.secret_key = "6af3255620cb90e9bc3c0dc05bbe80481482f9d85af8feff" # en prod -> os.urandom(24)

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

#######################################
############### HELPERS ###############
#######################################

def allowed_file(file):
    if not '.' in file:
        return False
    
    parts = file.rsplit('.', 1)
    extension = parts[1].lower()

    if extension in ALLOWED_EXTENSIONS:
        return True
    else:
        return False
    
def is_email(email):
    if EMAIL_REGEX.match(email):
        return True
    else:
        return False
    
def get_username(id):
    if not id:
        return None
    
    try:
        user = db_utils.find_one({"_id": ObjectId(id)}, {"username": 1})
        if not user:
            return None
        else:
            return user['username']
    except (InvalidId, TypeError):
        return None
    
def is_admin(id):
    if not id:
        return False
    
    try:
        user = db_utils.find_one({'_id': ObjectId(id)})
    except (InvalidId, TypeError):
        return False

    if not user:
        return False
    
    role = user.get('role', 'user')
    return role in ['admin', 'superadmin']

def build_admin_user_card(user):
    username = user.get('username') or user.get('nom') or user.get('user') or 'Utilisateur'
    email = user.get('email')

    if email in [None, '', 'no_mail']:
        email = None

    muted_until = user.get('muted_until')
    muted_until_display = None
    if isinstance(muted_until, datetime):
        muted_until_display = muted_until.strftime('%d/%m/%Y %H:%M')

    role = user.get('role', 'user')

    return {
        'id': str(user.get('_id', '')),
        '_id': str(user.get('_id', '')),
        'nom': username,
        'email': email,
        'is_admin': role in ['admin', 'superadmin'],
        'banned': bool(user.get('banned', False)),
        'muted': bool(user.get('muted', False)),
        'first_name': user.get('first_name', ''),
        'last_name': user.get('last_name', ''),
        'ban_reason': user.get('ban_reason', ''),
        'muted_until_display': muted_until_display
    }

#####################################
############### INDEX ###############
#####################################

@app.route('/')
def index():
    return render_template('index.html')

#########################################
############### CONNEXION ###############
#########################################

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
                "role": "user",
                "favoris": []
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

        if user_found.get('banned'):
            reason = user_found.get('ban_reason')
            message = "Ce compte est banni."
            if reason:
                message += f" Raison : {reason}"
            return render_template("login.html", erreur=message)

        if 'favoris' not in user_found:
            db_utils.update_one({'_id': user_found['_id']}, {'$set': {'favoris': []}})
        
        session['util'] = str(user_found['_id'])
        return redirect(url_for('index'))
    else:
        return render_template("login.html")
    
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

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
            "role": "user",
            "favoris": []
        })

        db_pendingu.delete_one({"_id": pending_user["_id"]})
        session.pop('pending_user', None)
        session['util'] = str(result.inserted_id)

        return redirect(url_for('index'))
    else:
        return render_template("verify_mail.html")
    
#####################################
############### POSTS ###############
#####################################

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

        est_en_favori = False
        is_user_admin = False
        if session.get('util'):
            utilisateur = db_utils.find_one({'_id': ObjectId(session['util'])}, {'favoris': 1})
            favoris = utilisateur.get('favoris', []) if utilisateur else []
            est_en_favori = any(str(f) == post_id for f in favoris)
            is_user_admin = is_admin(session['util'])
        
        comments = list(db_comments.find({"post_id": ObjectId(post_id)}).sort("created_at", -1))
        
        return render_template('view_post.html', post=post, comments=comments, est_en_favori=est_en_favori, is_user_admin=is_user_admin)
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




@app.route('/favori/<id>', methods=['POST'])
def toggle_favori(id):
    if not session.get('util'):
        return redirect(url_for('login'))

    try:
        annonce_id = ObjectId(id)
        utilisateur_id = ObjectId(session['util'])

        if not db_posts.find_one({'_id': annonce_id}):
            abort(404)

        utilisateur = db_utils.find_one({'_id': utilisateur_id}, {'favoris': 1})
        if not utilisateur:
            return redirect(url_for('login'))

        favoris = utilisateur.get('favoris', [])
        deja_favori = any(str(f) == id for f in favoris)

        if deja_favori:
            db_utils.update_one({'_id': utilisateur_id}, {'$pull': {'favoris': annonce_id}})
        else:
            db_utils.update_one({'_id': utilisateur_id}, {'$addToSet': {'favoris': annonce_id}})

        post = db_posts.find_one({'_id': annonce_id})
        if post:
            return redirect(request.referrer or url_for('view_post', categorie=post['categorie'], post_id=id))

        return redirect(request.referrer or url_for('index'))
    except (InvalidId, TypeError):
        abort(404)

######################################
############### FAVORIS ##############
######################################

# Page des favoris de l'utilisateur connecté
@app.route('/mes-favoris')
def mes_favoris():
    if not session.get('util'):
        return redirect(url_for('login'))

    try:
        utilisateur = db_utils.find_one({'_id': ObjectId(session['util'])}, {'favoris': 1})
        if not utilisateur:
            return redirect(url_for('login'))

        ids_favoris_raw = utilisateur.get('favoris', [])
        ids_favoris = []
        for fav_id in ids_favoris_raw:
            if isinstance(fav_id, ObjectId):
                ids_favoris.append(fav_id)
            else:
                try:
                    ids_favoris.append(ObjectId(str(fav_id)))
                except InvalidId:
                    continue

        posts_favoris = list(db_posts.find({'_id': {'$in': ids_favoris}}).sort('created_at', -1))

        return render_template('mes_favoris.html', posts=posts_favoris)
    except (InvalidId, TypeError):
        abort(404)


######################################
############### PROFIL ###############
######################################

def is_superadmin(id):
    if not id:
        return False
    try:
        user = db_utils.find_one({'_id': ObjectId(id)})
    except (InvalidId, TypeError):
        return False

    if not user:
        return False

    return user.get('role') == 'superadmin'


def build_profile_stats(user_id):
    return {
        'posts_count': db_posts.count_documents({'auteur_id': user_id}),
        'comments_count': db_comments.count_documents({'auteur_id': user_id}),
        'categories_count': len(db_posts.distinct('categorie', {'auteur_id': user_id}))
    }


@app.route('/profil', methods=['GET'])
def profil():
    if 'util' not in session:
        return redirect(url_for('login'))

    try:
        user = db_utils.find_one({'_id': ObjectId(session['util'])})
    except (InvalidId, TypeError):
        return redirect(url_for('login'))

    if not user:
        session.pop('util', None)
        return redirect(url_for('login'))

    stats = build_profile_stats(user['_id'])
    recent_posts = list(db_posts.find({'auteur_id': user['_id']}).sort('created_at', -1).limit(5))
    recent_comments = list(db_comments.find({'auteur_id': user['_id']}).sort('created_at', -1).limit(5))

    return render_template('profil.html', user=user, stats=stats, recent_posts=recent_posts, recent_comments=recent_comments)


@app.route('/profil/update-info', methods=['POST'])
def update_profile_info():
    if 'util' not in session:
        return redirect(url_for('login'))

    try:
        user_id = ObjectId(session['util'])
    except (InvalidId, TypeError):
        return redirect(url_for('login'))

    user = db_utils.find_one({'_id': user_id})
    if not user:
        return redirect(url_for('login'))

    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()

    if not username:
        flash("Le pseudo ne peut pas être vide.", "error")
        return redirect(url_for('profil'))

    if username != user.get('username') and db_utils.find_one({'username': username}):
        flash("Ce pseudo est déjà pris.", "error")
        return redirect(url_for('profil'))

    if email:
        if not is_email(email):
            flash("L'adresse email est invalide.", "error")
            return redirect(url_for('profil'))

        if db_utils.find_one({'email': email, '_id': {'$ne': user_id}}):
            flash("Cet email est déjà utilisé.", "error")
            return redirect(url_for('profil'))
    else:
        email = None

    db_utils.update_one({'_id': user_id}, {'$set': {'username': username, 'email': email}})
    flash("Informations de profil mises à jour.", "success")
    return redirect(url_for('profil'))


@app.route('/profil/change-password', methods=['POST'])
def change_password():
    if 'util' not in session:
        return redirect(url_for('login'))

    try:
        user_id = ObjectId(session['util'])
    except (InvalidId, TypeError):
        return redirect(url_for('login'))

    user = db_utils.find_one({'_id': user_id})
    if not user:
        return redirect(url_for('login'))

    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
        flash("Mot de passe actuel incorrect.", "error")
        return redirect(url_for('profil'))

    if new_password != confirm_password:
        flash("Les nouveaux mots de passe ne correspondent pas.", "error")
        return redirect(url_for('profil'))

    if len(new_password) < 8 or not any(c.isdigit() for c in new_password):
        flash("Le mot de passe doit faire au moins 8 caractères et contenir au moins un chiffre.", "error")
        return redirect(url_for('profil'))

    password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    db_utils.update_one({'_id': user_id}, {'$set': {'password': password_hash}})
    flash("Mot de passe mis à jour avec succès.", "success")
    return redirect(url_for('profil'))


@app.route('/profil/delete-account', methods=['POST'])
def delete_account():
    if 'util' not in session:
        return redirect(url_for('login'))

    if request.form.get('confirm_delete', '') != 'SUPPRIMER':
        flash("Confirmez la suppression en écrivant SUPPRIMER.", "error")
        return redirect(url_for('profil'))

    try:
        user_id = ObjectId(session['util'])
    except (InvalidId, TypeError):
        return redirect(url_for('login'))

    db_utils.delete_one({'_id': user_id})
    session.clear()
    flash("Votre compte a bien été supprimé.", "success")
    return redirect(url_for('index'))


#####################################
############### ADMIN ###############
#####################################

@app.route('/admin')
def admin_index():
    if 'util' not in session or not is_admin(session['util']):
        return abort(403)

    current_user = db_utils.find_one({'_id': ObjectId(session['util'])}, {'username': 1, 'role': 1}) or {}

    q = request.args.get('q', '').strip()
    mode = request.args.get('mode', 'pseudo').strip().lower()
    message = request.args.get('message', '')
    erreur = request.args.get('erreur', '')

    mongo_query = {}
    if q:
        regex = {'$regex': re.escape(q), '$options': 'i'}

        if mode == 'email':
            mongo_query = {'email': regex}
        elif mode == 'name':
            mongo_query = {
                '$or': [
                    {'first_name': regex},
                    {'last_name': regex},
                    {'username': regex},
                    {'nom': regex}
                ]
            }
        else:
            mode = 'pseudo'
            mongo_query = {
                '$or': [
                    {'username': regex},
                    {'nom': regex}
                ]
            }

    limit = 20 if not q else 100
    raw_users = list(db_utils.find(mongo_query).sort('_id', -1).limit(limit))
    users = [build_admin_user_card(user) for user in raw_users]

    return render_template(
        'admin/admin_index.html',
        nom=current_user.get('username', 'Admin'),
        is_superadmin=current_user.get('role') in ['admin', 'superadmin'],
        q=q,
        mode=mode,
        users=users,
        message=message,
        erreur=erreur
    )

@app.route('/admin/create-user', methods=['POST'])
def admin_create_user():
    if 'util' not in session or not is_admin(session['util']):
        return abort(403)

    username = request.form.get('nom', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    make_admin = request.form.get('is_admin') == 'on'

    if not username:
        return redirect(url_for('admin_index', erreur="Le pseudo est obligatoire."))

    if len(password) < 8 or not any(c.isdigit() for c in password):
        return redirect(url_for('admin_index', erreur="Le mot de passe doit contenir au moins 8 caractères et 1 chiffre."))

    if db_utils.find_one({'username': username}):
        return redirect(url_for('admin_index', erreur="Ce pseudo existe déjà."))

    if email:
        if not is_email(email):
            return redirect(url_for('admin_index', erreur="L'adresse email est invalide."))

        if db_utils.find_one({'email': email}):
            return redirect(url_for('admin_index', erreur="Cet email est déjà utilisé."))
    else:
        email = None

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    db_utils.insert_one({
        'username': username,
        'password': password_hash,
        'email': email,
        'role': 'admin' if make_admin else 'user',
        'favoris': [],
        'banned': False,
        'muted': False,
        'created_at': datetime.now(timezone.utc)
    })

    return redirect(url_for('admin_index', message=f"Le compte {username} a bien été créé."))

@app.route('/admin/posts', methods=['GET', 'POST'])
def admin_posts():
    if 'util' not in session or not is_admin(session['util']):
        return abort(403)

    q = request.args.get('q', '').strip()
    message = request.args.get('message', '')
    erreur = request.args.get('erreur', '')

    mongo_query = {}
    if q:
        regex = {'$regex': re.escape(q), '$options': 'i'}
        mongo_query = {
            '$or': [
                {'titre': regex},
                {'description': regex},
                {'categorie': regex},
                {'auteur_name': regex}
            ]
        }

    limit = 50 if not q else 200
    posts = list(db_posts.find(mongo_query).sort('created_at', -1).limit(limit))

    return render_template(
        'admin/admin_posts.html',
        posts=posts,
        q=q,
        message=message,
        erreur=erreur
    )


@app.route('/comment/<comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    if 'util' not in session:
        return redirect(url_for('login'))

    try:
        comment_id = ObjectId(comment_id)
    except (InvalidId, TypeError):
        abort(404)

    comment = db_comments.find_one({'_id': comment_id})
    if not comment:
        abort(404)

    current_user_id = ObjectId(session['util'])
    current_user = db_utils.find_one({'_id': current_user_id})

    if comment['auteur_id'] != current_user_id and not is_admin(session['util']):
        abort(403)

    db_comments.delete_one({'_id': comment_id})
    flash("Commentaire supprimé.", "success")
    return redirect(request.referrer or url_for('index'))


@app.route('/admin/comments', methods=['GET', 'POST'])
def admin_comments():
    if 'util' not in session or not is_admin(session['util']):
        return abort(403)

    q = request.args.get('q', '').strip()
    message = request.args.get('message', '')
    erreur = request.args.get('erreur', '')

    mongo_query = {}
    if q:
        regex = {'$regex': re.escape(q), '$options': 'i'}
        mongo_query = {
            '$or': [
                {'contenu': regex},
                {'auteur_name': regex}
            ]
        }

    limit = 50 if not q else 200
    comments = list(db_comments.find(mongo_query).sort('created_at', -1).limit(limit))

    for comment in comments:
        post = db_posts.find_one({'_id': comment['post_id']}, {'titre': 1})
        comment['post_titre'] = post['titre'] if post else 'Post supprimé'

    return render_template(
        'admin/admin_comments.html',
        comments=comments,
        q=q,
        message=message,
        erreur=erreur
    )


@app.route('/admin/comment/<comment_id>/delete', methods=['POST'])
def admin_delete_comment(comment_id):
    if 'util' not in session or not is_admin(session['util']):
        return abort(403)

    try:
        comment_id = ObjectId(comment_id)
    except (InvalidId, TypeError):
        abort(404)

    comment = db_comments.find_one({'_id': comment_id})
    if not comment:
        abort(404)

    db_comments.delete_one({'_id': comment_id})
    flash("Commentaire supprimé.", "success")
    return redirect(url_for('admin_comments'))


@app.route('/admin/post/<post_id>', methods=['GET', 'POST'])
def admin_post_detail(post_id):
    if 'util' not in session or not is_admin(session['util']):
        return abort(403)

    try:
        target_id = ObjectId(post_id)
    except (InvalidId, TypeError):
        return abort(404)

    post = db_posts.find_one({'_id': target_id})
    if not post:
        return abort(404)

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'update_post':
            titre = request.form.get('titre', '').strip()
            description = request.form.get('description', '').strip()
            categorie = request.form.get('categorie', '').strip()
            nouvelle_categorie = request.form.get('nouvelle_categorie', '').strip()

            if not titre or len(titre) < 5 or len(titre) > 100:
                flash("Le titre doit faire entre 5 et 100 caractères.", "error")
                return redirect(url_for('admin_post_detail', post_id=post_id))

            if not description or len(description) > 5000:
                flash("La description ne peut pas être vide et doit faire moins de 5000 caractères.", "error")
                return redirect(url_for('admin_post_detail', post_id=post_id))

            final_cat = categorie
            if categorie == 'new' and nouvelle_categorie:
                if not db_categories.find_one({'nom': nouvelle_categorie}):
                    db_categories.insert_one({'nom': nouvelle_categorie})
                final_cat = nouvelle_categorie
            elif categorie not in [c['nom'] for c in db_categories.find()]:
                final_cat = categorie or post.get('categorie', 'Général')

            db_posts.update_one(
                {'_id': target_id},
                {'$set': {
                    'titre': titre,
                    'description': description,
                    'categorie': final_cat
                }}
            )
            flash("Post mis à jour.", "success")
            return redirect(url_for('admin_post_detail', post_id=post_id))

        if action == 'delete_post':
            db_posts.delete_one({'_id': target_id})
            db_comments.delete_many({'post_id': target_id})
            db_utils.update_many({'favoris': target_id}, {'$pull': {'favoris': target_id}})
            flash("Post supprimé.", "success")
            return redirect(url_for('admin_posts'))

        flash("Action inconnue.", "error")
        return redirect(url_for('admin_post_detail', post_id=post_id))

    categories = list(db_categories.find().sort('nom', 1))
    post_comments = list(db_comments.find({'post_id': target_id}).sort('created_at', -1))
    return render_template(
        'admin/admin_post_detail.html',
        post=post,
        comments=post_comments,
        categories=categories,
        post_id=str(post['_id'])
    )


@app.route('/admin/user/<user_id>', methods=['GET', 'POST'])
def admin_user_detail(user_id):
    if 'util' not in session or not is_admin(session['util']):
        return abort(403)

    try:
        target_id = ObjectId(user_id)
    except (InvalidId, TypeError):
        return abort(404)

    current_user = db_utils.find_one({'_id': ObjectId(session['util'])})
    target_user = db_utils.find_one({'_id': target_id})
    if not target_user:
        return abort(404)

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'update_info':
            new_username = request.form.get('username', '').strip()
            new_email = request.form.get('email', '').strip()
            new_role = request.form.get('role', target_user.get('role', 'user')).strip()

            if not new_username:
                flash("Le pseudo ne peut pas être vide.", "error")
                return redirect(url_for('admin_user_detail', user_id=user_id))

            if new_username != target_user.get('username') and db_utils.find_one({'username': new_username, '_id': {'$ne': target_id}}):
                flash("Ce pseudo est déjà pris.", "error")
                return redirect(url_for('admin_user_detail', user_id=user_id))

            if new_email:
                if not is_email(new_email):
                    flash("L'adresse email est invalide.", "error")
                    return redirect(url_for('admin_user_detail', user_id=user_id))
                if db_utils.find_one({'email': new_email, '_id': {'$ne': target_id}}):
                    flash("Cet email est déjà utilisé.", "error")
                    return redirect(url_for('admin_user_detail', user_id=user_id))
            else:
                new_email = None

            update_fields = {'username': new_username, 'email': new_email}
            if current_user.get('role') == 'superadmin':
                update_fields['role'] = new_role if new_role in ['user', 'admin', 'superadmin'] else target_user.get('role', 'user')

            db_utils.update_one({'_id': target_id}, {'$set': update_fields})
            flash("Informations utilisateur mises à jour.", "success")
            return redirect(url_for('admin_user_detail', user_id=user_id))

        if action == 'change_password':
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')

            if new_password != confirm_password:
                flash("Les mots de passe ne correspondent pas.", "error")
                return redirect(url_for('admin_user_detail', user_id=user_id))

            if len(new_password) < 8 or not any(c.isdigit() for c in new_password):
                flash("Le mot de passe doit faire au moins 8 caractères et contenir au moins un chiffre.", "error")
                return redirect(url_for('admin_user_detail', user_id=user_id))

            password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            db_utils.update_one({'_id': target_id}, {'$set': {'password': password_hash}})
            flash("Mot de passe utilisateur mis à jour.", "success")
            return redirect(url_for('admin_user_detail', user_id=user_id))

        if action == 'toggle_ban':
            if target_user.get('role') == 'superadmin' and current_user.get('role') != 'superadmin':
                return abort(403)

            if request.form.get('ban_action') == 'ban':
                ban_reason = request.form.get('ban_reason', '').strip() or 'Aucune raison précisée'
                db_utils.update_one({'_id': target_id}, {'$set': {'banned': True, 'ban_reason': ban_reason}})
                flash("Utilisateur banni.", "success")
            else:
                db_utils.update_one({'_id': target_id}, {'$set': {'banned': False, 'ban_reason': ''}})
                flash("Utilisateur débanni.", "success")
            return redirect(url_for('admin_user_detail', user_id=user_id))

        if action == 'delete_account':
            if target_user.get('role') == 'superadmin' and current_user.get('role') != 'superadmin':
                return abort(403)

            db_utils.delete_one({'_id': target_id})
            if str(target_id) == str(current_user.get('_id')):
                session.clear()
                flash("Votre compte a été supprimé.", "success")
                return redirect(url_for('index'))

            flash("Le compte a été supprimé.", "success")
            return redirect(url_for('admin_index'))

        flash("Action inconnue.", "error")
        return redirect(url_for('admin_user_detail', user_id=user_id))

    stats = build_profile_stats(target_user['_id'])
    recent_posts = list(db_posts.find({'auteur_id': target_user['_id']}).sort('created_at', -1).limit(5))
    recent_comments = list(db_comments.find({'auteur_id': target_user['_id']}).sort('created_at', -1).limit(5))

    return render_template(
        'admin/admin_user_detail.html',
        current_user=current_user,
        user=target_user,
        user_id=str(target_user['_id']),
        stats=stats,
        recent_posts=recent_posts,
        recent_comments=recent_comments,
        can_edit_role=current_user.get('role') == 'superadmin'
    )


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=81) # A CHANGER EN PROD PAS DE 127.0.0.1!!! -> 0.0.0.0 en prod