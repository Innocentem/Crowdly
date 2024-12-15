from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import os

app = Flask(__name__)

# Configurations
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///evently.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable=False)
    gender = db.Column(db.String(10))
    location = db.Column(db.String(100))
    hobbies = db.Column(db.String(255))
    profile_picture = db.Column(db.String(255), default='default.png')
    events = db.relationship('Event', backref='creator', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Event {self.title}>'

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')])
    location = StringField('Location', validators=[DataRequired()])
    hobbies = StringField('Hobbies')
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EventForm(FlaskForm):
    title = StringField('Event Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    category = SelectField('Category', choices=[('Party', 'Party'), ('Hookup', 'Hookup'), ('Get-Together', 'Get-Together')], validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    date = StringField('Date (YYYY-MM-DD HH:MM)', validators=[DataRequired()])
    submit = SubmitField('Create Event')

class SearchForm(FlaskForm):
    search_query = StringField('Search Events or Users', validators=[DataRequired()])
    submit = SubmitField('Search')

# Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility Function for Event Status Update
def update_event_status():
    past_events = Event.query.filter(Event.date < datetime.utcnow()).all()
    for event in past_events:
        db.session.delete(event)  # Alternatively, mark as completed
    db.session.commit()

scheduler = BackgroundScheduler()
scheduler.add_job(update_event_status, 'interval', hours=1)
scheduler.start()
#os.environ['TZ'] = 'Africa/Nairobi'

# Routes
@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(username=form.username.data, password=hashed_password, gender=form.gender.data, 
                    location=form.location.data, hobbies=form.hobbies.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to the dashboard or appropriate page
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = EventForm()
    search_form = SearchForm()
    events = Event.query.filter(Event.date > datetime.utcnow()).all()

    if form.validate_on_submit():
        event = Event(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            location=form.location.data,
            date=datetime.strptime(form.date.data, '%Y-%m-%d %H:%M'),
            creator=current_user
        )
        db.session.add(event)
        db.session.commit()
        flash('Event created successfully!', 'success')
        return redirect(url_for('dashboard'))

    if search_form.validate_on_submit() and search_form.search_query.data:
        search = search_form.search_query.data
        events = Event.query.filter(
            (Event.title.ilike(f"%{search}%")) | 
            (Event.category.ilike(f"%{search}%")) | 
            (Event.location.ilike(f"%{search}%"))
        ).all()

    return render_template('dashboard.html', form=form, search_form=search_form, events=events)

@app.route('/edit_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event.creator != current_user:
        abort(403)  # Forbidden
    form = EventForm(obj=event)
    if form.validate_on_submit():
        event.title = form.title.data
        event.description = form.description.data
        event.category = form.category.data
        event.location = form.location.data
        event.date = datetime.strptime(form.date.data, '%Y-%m-%d %H:%M')
        db.session.commit()
        flash('Event updated!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_event.html', form=form, event=event)

@app.route('/suggest_events')
@login_required
def suggest_events():
    suggested_events = Event.query.filter(
        (Event.category.ilike(f"%{current_user.hobbies}%")) &
        (Event.location.ilike(f"%{current_user.location}%")) &
        (Event.date > datetime.utcnow())
    ).all()
    return render_template('suggest_events.html', events=suggested_events)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
