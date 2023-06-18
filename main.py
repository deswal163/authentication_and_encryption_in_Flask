import sqlalchemy.exc
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import pathlib

app = Flask(__name__)

path_for_db = pathlib.Path(__file__).parent.resolve()
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:////{path_for_db}/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.app_context().push()
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


#Line below only required once, when creating DB.


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)



@app.route('/', methods=["GET", "POST"])
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        user = User()
        user.name = request.form['name']
        user.email = request.form['email']
        user.password = generate_password_hash(
            password=request.form['password'],
            method="pbkdf2:sha256",
            salt_length=8
        )

        db.session.add(user)
        try:
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            return redirect(url_for('login', msg=flash("That email already exist. Please login!", "error")))
        login_user(user, remember=True)
        return redirect(url_for('secrets'))

    return render_template("register.html")


@app.route('/login', methods=["POST", "GET"])
def login(msg=""):
    if request.method == "POST":
        user_email = request.form['email']
        entered_password = request.form['password']

        user = User.query.filter_by(email=user_email).first()
        if user is None:
            return redirect(url_for("login", msg=flash("That email doesn't exist.\nPlease login again !", "error")))
        if check_password_hash(user.password, entered_password):
            # user.is_authenticated = True
            login_user(user, remember=True)
            return redirect(url_for('secrets'))
        else:
            return redirect(url_for("login", msg=flash("Entered password is incorrect.", "error")))

    return render_template("login.html", msg=msg)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", user=current_user, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(
        f'{path_for_db}/static/files', 'cheat_sheet.pdf'
    )


if __name__ == "__main__":
    app.run(debug=True)
