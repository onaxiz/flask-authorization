
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123@localhost/clear'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class Tests(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    testName = db.Column(db.String(30))
    question = db.Column(db.String(30))
    аnswer1 = db.Column(db.String(30))
    аnswer2 = db.Column(db.String(30))
    аnswer3 = db.Column(db.String(30))
    right_answer = db.Column(db.String(30))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    student_id= db.Column(db.Integer, db.ForeignKey('student.id'))



class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    patronymic = db.Column(db.String(50))
    group = db.Column(db.String(50))
    logins = db.relationship('User', backref='student',
                                    lazy='dynamic')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class StudentInfo(FlaskForm):
    first_name = StringField('first name', validators=[InputRequired(), Length(min=4, max=15)])
    last_name = StringField('last name', validators=[InputRequired(), Length(min=4, max=15)])
    patronymic = StringField('patronymic', validators=[InputRequired(), Length(min=4, max=15)])
    group = StringField('patronymic', validators=[InputRequired(), Length(min=4, max=15)])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('info'))

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/info', methods=['GET', 'POST'])
def info():
    student_form = StudentInfo()

    if student_form.validate_on_submit():
        new_student = Student(first_name=student_form.first_name.data, last_name=student_form.last_name.data, patronymic=student_form.patronymic.data, group = student_form.group.data )
        db.session.add(new_student)
        db.session.commit()

        return "ds prdfld;"

    return render_template('student_info.html', form=student_form)

if __name__ == '__main__':
    app.run(debug=True)