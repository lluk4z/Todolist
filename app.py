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

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

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

@app.route('/list')
def tasks_list():
    tasks = Task.query.all()
    return render_template('list.html', tasks=tasks)

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

if __name__ == '__main__':
    app.run(debug=True)