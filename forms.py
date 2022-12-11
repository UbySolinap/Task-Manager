from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateTimeLocalField
from wtforms.validators import DataRequired, Email, Optional, EqualTo
import email_validator


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class ForgotForm(FlaskForm):
    email = StringField("Please enter your email address:", validators=[DataRequired(), Email()])
    submit = SubmitField("Send Email")


class ResetForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Reset Password")


class ListForm(FlaskForm):
    list_name = StringField("Write a task list name", validators=[DataRequired()])
    submit = SubmitField("Submit")


class TaskForm(FlaskForm):
    task = StringField("Add a task:", validators=[DataRequired()])
    end_date = DateTimeLocalField("Set Deadline (Optional):", format='%Y-%m-%dT%H:%M', validators=[Optional()])
    submit = SubmitField("Add Task")