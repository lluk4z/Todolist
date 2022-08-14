from crypt import methods
import email
from email.policy import default
from enum import unique
import imp
from unicodedata import name
from flask import Flask, request
from flask import render_template
from flask import redirect
from flask import url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    
    email = StringField(validators=[
                           InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "Email"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')
    
    def validate_email(self, email):
        existing_email = User.query.filter_by(
            username=email.data).first()
        if existing_email:
            raise ValidationError(
                'That email already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text)
    content = db.Column(db.Text)
    done = db.Column(db.Boolean, default=False)
    priority = db.Column(db.Text, default='Baixa')

    def __init__(self, name, content, priority):
        self.name = name
        self.content = content
        self.done = False
        self.priority = priority

    def __repr__(self):
        return '<Name %s> <Content %s>' % self.name % self.content


db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/list')
def tasks_list():
    tasks = Task.query.all()
    return render_template('list.html', tasks=tasks)

@app.route('/membros')
def member_list():
    members = User.query.all()
    return render_template('membros.html', members=members)

@app.route('/task', methods=['POST'])
def add_task():
    content = request.form['content']

    name = request.form['name']

    priority = request.form['priority']

    if not name:
        return 'Error'


    if not content:
        return 'Error'


    task = Task(name,content, priority)
    db.session.add(task)
    db.session.commit()
    return redirect('list')


@app.route('/delete/<int:task_id>')
def delete_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return redirect('list')

    db.session.delete(task)
    db.session.commit()
    return redirect('list')


@app.route('/done/<int:task_id>')
def resolve_task(task_id):
    task = Task.query.get(task_id)

    if not task:
        return redirect('list')
    if task.done:
        task.done = False
    else:
        task.done = True

    db.session.commit()
    return redirect('list')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    id = User(username=form.username.data)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('tasks_list'))

    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)