from flask import Flask, render_template, redirect, url_for, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import firestore


app = Flask(__name__)
app.config['SECRET_KEY'] = 'mojbardzosekretnyklucz'
Bootstrap(app)
db = firestore.Client()
users_database = db.collection('users')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    retypePassword = PasswordField('Retype password', validators=[InputRequired(), Length(min=8, max=80)])



class AddProviderForm(FlaskForm):
    # providerName = SelectField('Select provider', validators=[InputRequired()])
    providerName = StringField('Provider name', validators=[InputRequired()])
    nrCoffeeBrands = SelectField('Number of coffee brands', coerce=int, validators=[InputRequired()],
                                 choices=[(x, x) for x in range(1, 100)])
    frequency = SelectField('Frequency of delivery (for month)', coerce=int, validators=[InputRequired()],
                            choices=[(x, x) for x in range(1, 31)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if not session.get('logged_in'):
        if form.validate_on_submit():
            if form.password.data != form.retypePassword.data:
                form.password.errors.append('Passwords does not match')
                form.retypePassword.errors.append('Passwords does not match')
            else:
                hashed_password = generate_password_hash(form.password.data, method='sha256')
                user = {'username': form.username.data, 'email': form.email.data, 'password': hashed_password,
                        'providers': []}
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
            form.username.errors.append('Invalid username or password')
            form.password.errors.append('Invalid username or password')
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

    if form.validate_on_submit():
        users_providers = users_database.document(session['user_id']).get().to_dict().get('providers')
        provider = {'name': form.providerName.data, 'numberBrands': form.nrCoffeeBrands.data,
                    'frequency': form.frequency.data}
        if provider not in users_providers:
            users_providers.append(provider)
            users_database.document(session['user_id']).update({'providers': users_providers})

            return redirect(url_for('providers'))

    users_providers = users_database.document(session['user_id']).get().to_dict().get('providers')

    return render_template('providers.html', form=form, users_providers=users_providers)



@app.route('/offers')
def offers():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    users_providers = users_database.document(session['user_id']).get().to_dict().get('providers')

    return render_template('offers.html', users_providers=users_providers)


@app.route('/logout')
def logout():
    session['logged_in'] = False
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
