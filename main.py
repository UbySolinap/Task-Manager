from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from forms import RegisterForm, LoginForm, ForgotForm, ResetForm, ListForm, TaskForm
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from datetime import date
import smtplib
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")

# Connect to Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL1", 'sqlite:///task.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

Bootstrap(app)

MY_EMAIL = os.environ.get("EMAIL")
PASSWORD = os.environ.get("EMAIL_PASS")


# Databases
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    task_list = relationship("TaskList", back_populates="owner")

    def get_reset_token(self, expires_seconds=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_seconds)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


class TaskList(db.Model):
    __tablename__ = "task-lists"
    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    owner = relationship("User", back_populates="task_list")
    task_data = relationship("Task", back_populates="task_title")
    done_task = relationship("TaskDone", back_populates="task_list_data")


class Task(db.Model):
    __tablename__ = "task"
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.String(100), nullable=False)
    end_date = db.Column(db.String(100))
    task_list_id = db.Column(db.Integer, db.ForeignKey("task-lists.id"))
    task_title = relationship("TaskList", back_populates="task_data")


class TaskDone(db.Model):
    __tablename__ = "finished"
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(100), nullable=False)
    end_date = db.Column(db.String(100))
    task_list_id = db.Column(db.Integer, db.ForeignKey("task-lists.id"))
    task_list_data = relationship("TaskList", back_populates="done_task")


db.create_all()

# For Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html", current_user=current_user)


# User Section
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = request.form['email']
        name = request.form['name']
        password = generate_password_hash(request.form['password'], method="pbkdf2:sha256", salt_length=8)
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("Email already exists. Login instead")
            return redirect(url_for('login'))
        new_user = User(email=email, name=name, password=password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('task_list_page'))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email is not registered. Click Sign Up to register.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Wrong password. Please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('task_list_page'))
    return render_template("login.html", form=form, current_user=current_user)


def send_reset_email(user):
    token = user.get_reset_token()
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(user=MY_EMAIL, password=PASSWORD)
        connection.sendmail(from_addr=MY_EMAIL,
                            to_addrs=MY_EMAIL,
                            msg=f"Subject:Password Reset\n\n"
                                f"To reset your password, click on the following link:\n"
                                f"{url_for('reset_password', token=token, _external=True)}\n"
                                f"If you did not make this request then simply ignore this email.")


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    form = ForgotForm()
    if form.validate_on_submit():
        email = request.form.get('email')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("There is no account with that email. Please, register first.")
            return redirect(url_for('forgot'))
        else:
            send_reset_email(user)
            flash("An email has been sent. Follow the instructions to reset your password.", "info")
            return redirect(url_for("login"))
    return render_template("forgot.html", form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token.')
        return redirect(url_for('forgot'))
    form = ResetForm()
    if form.validate_on_submit():
        # password = generate_password_hash(request.form['password'], method="pbkdf2:sha256", salt_length=8)
        user.password = generate_password_hash(request.form['password'], method="pbkdf2:sha256", salt_length=8)
        db.session.commit()
        flash("Your password has been updated, Please log in now.")
        return redirect(url_for('login'))
    return render_template("password-reset.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


# Task Section
@app.route('/tasks-list', methods=['GET', 'POST'])
def task_list_page():
    form = ListForm()
    task_lists = db.session.query(TaskList).filter(TaskList.user_id == current_user.get_id())
    if form.validate_on_submit():
        new_task_list = TaskList(
            task_name=form.list_name.data,
            date=date.today().strftime("%B %d, %Y"),
            owner=current_user
        )
        db.session.add(new_task_list)
        db.session.commit()
        return redirect(url_for("task_list_page"))
    return render_template("task-list.html", form=form, current_user=current_user, all_tasks=task_lists)


@app.route('/tasks/<int:index>/<taskname>/', methods=["GET", "POST"])
def add_task(index, taskname):
    form = TaskForm()
    selected_task = TaskList.query.get(index)
    tasks = db.session.query(Task).filter(Task.task_list_id == index)
    finished_tasks = db.session.query(TaskDone).filter(TaskDone.task_list_id == index)

    if form.validate_on_submit():
        new_task = Task(
            task=form.task.data,
            start_date=date.today().strftime("%Y-%m-%d"),
            end_date=form.end_date.data,
            task_title=selected_task
        )
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for("add_task", index=selected_task.id, taskname=selected_task.task_name))
    return render_template("task.html", form=form, current_user=current_user, task=selected_task, tasks=tasks, finished=finished_tasks)


@app.route('/delete-list/<int:index>')
def delete_list(index):
    list_to_delete = TaskList.query.get(index)
    db.session.delete(list_to_delete)
    db.session.commit()
    return redirect(url_for('task_list_page'))


@app.route('/task-done/<int:task_index>/<int:delete_index>')
def task_done(task_index, delete_index):

    selected_task = TaskList.query.get(task_index)
    finished_task = Task.query.get(delete_index)

    # Add the finished task to the TaskDone Database
    new_finished = TaskDone(
        task=finished_task.task,
        end_date=finished_task.end_date,
        task_list_data=selected_task
    )
    db.session.add(new_finished)
    db.session.commit()

    # Remove the finished task in the Task Database
    db.session.delete(finished_task)
    db.session.commit()

    return redirect(url_for('add_task', index=selected_task.id, taskname=selected_task.task_name))


@app.route('/delete/<int:task_index>/<int:delete_index>')
def delete_task(task_index, delete_index):
    selected_task = TaskList.query.get(task_index)

    task_to_delete = TaskDone.query.get(delete_index)
    db.session.delete(task_to_delete)
    db.session.commit()

    return redirect(url_for('add_task', index=selected_task.id, taskname=selected_task.task_name))


if __name__ == "__main__":
    app.run(debug=True)