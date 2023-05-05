from flask_wtf import FlaskForm
from wtforms import TextField, SubmitField

from wtforms import validators


class Base64_Encrypt_Form(FlaskForm):
    name = TextField("Message", [validators.Required("Name required")])
    last_name = TextField("Last Name")
    submit = SubmitField("Submit")
