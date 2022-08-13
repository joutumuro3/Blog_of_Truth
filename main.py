from flask import Flask, render_template, redirect, url_for, flash, request, g, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base
import os
from dotenv import load_dotenv, find_dotenv


app = Flask(__name__)


app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY_1")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)



##CONFIGURE TABLES

class Blog_User(UserMixin,db.Model):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment",back_populates="comment_author")
    posts = relationship("BlogPost", back_populates='author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    author= relationship("Blog_User", back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship('Comment', back_populates='parent_post')

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    comment_author = relationship('Blog_User',back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates='comments')
    text = db.Column(db.String(250), nullable=False)

db.create_all()



def admin_only(f):
    @wraps(f)
    def wrapper_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            abort(403)
            # return redirect(url_for('get_all_posts'))
        # return f(*args, **kwargs)
        return f(*args, **kwargs)
    return wrapper_function


@login_manager.user_loader
def load_user(user_id):
    return Blog_User.query.get(user_id)

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST','GET'])
def register():
    reg_form = RegisterForm()
    if reg_form.validate_on_submit():
        if Blog_User.query.filter_by(email=request.form['email']).first() is not None:
            flash("You've already signed up with that email! Log in instead please.")
            return redirect(url_for('login'))
        user_registered = Blog_User(email=request.form['email'],
                                    password=generate_password_hash(request.form['password']),
                                    name=request.form['name'])
        db.session.add_all([user_registered])
        db.session.commit()
        login_user(user_registered)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=reg_form)


@app.route('/login', methods = ['POST','GET'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user_try = Blog_User.query.filter_by(email=request.form['email']).first()
        if user_try is None:
            flash("This email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user_try.password, request.form['password']):
            flash("Incorrect password, please try again.")
            return redirect(url_for('login'))
        if user_try is not None and check_password_hash(user_try.password, request.form['password']):
            login_user(user_try)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form= login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST','GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    gravatar = Gravatar(app,
                        size=100,
                        rating='g',
                        default='retro',
                        force_default=False,
                        force_lower=False,
                        use_ssl=False,
                        base_url=None)
    if comment_form.validate_on_submit():
        if not current_user.is_anonymous:
            new_comment = Comment(comment_author=current_user,
                                  parent_post=requested_post,
                                  text=request.form['comment_text']
                                  )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("Log in first to be able to comment")
            return redirect(url_for('login'))

    return render_template("post.html", post=requested_post, form=comment_form, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST','GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

# @app.route('/abort')
# def abortit():
#     abort(403)
#     return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
