from flask import Flask, render_template, redirect, url_for, session, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import firestore


app = Flask(__name__)
app.config['SECRET_KEY'] = 'mojbardzosekretnyklucz'
Bootstrap(app)
db = firestore.Client()
users_database = db.collection('users')
providers_database = db.collection('providers')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])


class AddProviderForm(FlaskForm):
    providerName = SelectField('Select provider', validators=[InputRequired()])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if not session.get('logged_in'):
        if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            user = {'username': form.username.data, 'email': form.email.data, 'password': hashed_password, 'providers': []}
            users_database.add(user)
            return redirect(url_for('login'))
    else:
        return redirect(url_for('dashboard'))

    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if not session.get('logged_in'):
        if form.validate_on_submit():
            users = users_database.where('username', '==', form.username.data).get()
            for user in users:
                if check_password_hash(user.to_dict().get('password'), form.password.data):
                    session['logged_in'] = True
                    session['username'] = form.username.data
                    session['user_id'] = user.id
                    return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html', user_id=session['user_id'], name=session['username'])


@app.route('/providers', methods=['GET', 'POST'])
def providers():
    form = AddProviderForm()

    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        users_providers = users_database.document(session['user_id']).get().to_dict().get('providers')
        if isinstance(users_providers, list):
            if form.providerName.data not in users_providers:
                users_providers.append(form.providerName.data)
                users_database.document(session['user_id']).update({'providers': users_providers})
        else:
            if users_providers != form.providerName.data:
                users_providers = [users_providers]
                users_providers.append(form.providerName.data)
                users_database.document(session['user_id']).update({'providers': users_providers})

    providers_ref = providers_database.get()
    providers = []
    for provider in providers_ref:
        providers.append(provider.to_dict().get('name'))

    form.providerName.choices = [(g, g) for g in providers]

    users_providers = users_database.document(session['user_id']).get().to_dict().get('providers')

    return render_template('providers.html', form=form, users_providers=users_providers)


@app.route('/offers')
def offers():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('offers.html')


@app.route('/logout')
def logout():
    session['logged_in'] = False
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
