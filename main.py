import datetime
import flask
from flask import Flask, render_template, redirect, url_for, flash, abort, Response
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///new_blogs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)



##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    parent = relationship("User", back_populates="children")
    child = relationship("Comment", back_populates="third_parent")


class User(UserMixin, db.Model):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    children = relationship("BlogPost", back_populates="parent")
    child = relationship("Comment", back_populates="second_parent")


    
class Comment(UserMixin, db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    second_parent_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    second_parent = relationship("User", back_populates="child")
    third_parent_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    third_parent = relationship("BlogPost", back_populates="child")


# with app.app_context():
#     db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/', methods=['GET', 'POST'])
def get_all_posts():
    posts = User().children
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    new_user = User(
        email=form.email.data,
        password=generate_password_hash(str(form.password.data), method='pbkdf2:sha256', salt_length=8),
        name=form.name.data
    )
    user = User.query.filter_by(email=form.email.data).first()
    if form.validate_on_submit():
        if user:
            error = "You've already registered that email. Log in instead!"
            return render_template('login.html', form=LoginForm(), error=error)
        login_user(new_user)
        db.session.add(new_user)
        db.session.commit()
        return render_template('index.html', logged_in=current_user.is_authenticated)
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    password = form.password.data
    user = User.query.filter_by(email=form.email.data).first()
    if form.validate_on_submit():
        if not user:
            error = "Oops! You've entered the wrong email. Please try again."
            return render_template("login.html", form=form, error=error)
        elif not check_password_hash(user.password, password):
            error = "Oops! You've entered the wrong password. Please try again."
            return render_template("login.html", form=form, error=error)
        else:
            logged_in = True
            posts = BlogPost.query.all()
            return render_template('index.html', all_posts=posts, logged_in=logged_in, id=user.id)
    return render_template("login.html", form=form)


@app.route('/')
def logout():
    logged_in = False
    posts = BlogPost.query.all()
    return render_template('index.html', all_posts=posts, logged_in=logged_in)


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        user = current_user
        print(user)
        if user:
            return function(*args, **kwargs)
        else:
            abort(403)
    return wrapper_function


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    name = User.query.all()[0]
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=name.name,
            date=datetime.datetime.now(),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    comment = CommentForm()
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
