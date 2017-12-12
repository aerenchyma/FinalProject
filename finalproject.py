import json
import requests
import os
from flask import Flask, request, render_template, session, redirect, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, ValidationError, SelectMultipleField
from wtforms.validators import Required, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import random
from flask_migrate import Migrate, MigrateCommand
from werkzeug import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user

api_key = '252626e355234934abc46433a0b183d5'

basedir = os.path.abspath(os.path.dirname(__file__))


app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'randomstringthatishardtoguessldkljlk'
app.static_folder = 'static'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/uniquenamefinalproject"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587 #default
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_SUBJECT_PREFIX'] = '[FINALPROJECT]'
app.config['MAIL_SENDER'] = 'Admin <jullocke364@gmail.com>'
app.config['ADMIN'] = os.environ.get('ADMIN')
app.config['HEROKU_ON'] = os.environ.get('HEROKU')


manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
mail = Mail(app)

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

def make_shell_context():
    return dict(app=app, db=db, City=City, Cuisine=Cuisine, Restaurant=Restaurant, User=User)
manager.add_command("shell", Shell(make_context=make_shell_context))

def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['MAIL_SUBJECT_PREFIX'] + subject, sender=app.config['MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)

personal_list = db.Table('personal_list', db.Column('restaurant_id', db.Integer, db.ForeignKey('restaurants.id')), db.Column('wishlist_id', db.Integer, db.ForeignKey('wishlist.id')))

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, index=True)
    email = db.Column(db.String(128), unique=True, index=True)
    #pro_pic = db.Column(db.LargeBinary, unique=True) #?? IS THIS HOW IMG SHOULD BE SAVED?
    wishlist_restaurants = db.relationship('WishListRestaurants', backref='User')
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class WishListRestaurants(db.Model):
    __tablename__ = "wishlist"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    restaurants = db.relationship('Restaurant', secondary=personal_list, backref=db.backref('wishlist', lazy='dynamic'), lazy='dynamic')

cuisine_restaurant = db.Table('cuisine_restaurant',db.Column('restuarant_id',db.Integer, db.ForeignKey('restaurants.id')),db.Column('cuisine_id',db.Integer,db.ForeignKey('cuisines.id')))

class Restaurant(db.Model):
    __tablename__ = "restaurants"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    city_id = db.Column(db.Integer, db.ForeignKey("cities.id"))
    cuisines = db.relationship('Cuisine', secondary=cuisine_restaurant,backref=db.backref('restaurants',lazy='dynamic'),lazy='dynamic')

    #def __repr__(self):
    #    return "{} | {} | Cuisine: {}".format(self.name, self.city_id, self.cuisines)

class City(db.Model):
    __tablename__ = "cities"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))

class Cuisine(db.Model):
    __tablename__ = "cuisines"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))


def get_city_code(city):
    try:
        headers = {'user-key':api_key}
        params = {'q':city}
        response = requests.get('https://developers.zomato.com/api/v2.1/cities', headers=headers, params=params)
        data = json.loads(response.text)
        for each in data['location_suggestions']:
            if each['name'].upper() == city.upper():
                return each['id']
    except:
        return None

def get_cuisine_code(cuisine, city_code):
    try:
        headers = {'user-key':api_key}
        params = {'city_id':city_code}
        response = requests.get('https://developers.zomato.com/api/v2.1/cuisines', headers=headers, params=params)
        data = json.loads(response.text)
        for each in data['cuisines']:
            if each['cuisine']['cuisine_name'].upper() == cuisine.upper():
                return str(each['cuisine']['cuisine_id'])
    except:
        return None

def get_restaurants(cuisine, city):
    try:
        city_code = get_city_code(city)
        cuisine_code = get_cuisine_code(cuisine, city_code)
        headers = {'user-key':api_key}
        params = {'user-key':api_key, 'entity_id':city_code, 'entity_type':'city', 'cuisines':cuisine_code,'count':50}
        response = requests.get('https://developers.zomato.com/api/v2.1/search', headers=headers, params=params)
        data = json.loads(response.text)
        return data['restaurants']
    except:
        return 'Trouble finding restaurant data'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    email = StringField('Email: ', validators=[Required(), Email()]) #?? VALIDATORS?!
    username = StringField('Username: ', validators=[Required()])
    file = FileField('Upload a profile picture: ')
    password = PasswordField('Password: ', validators=[Required(), EqualTo('confirm_password', message="Oops, passwords don't match!")])
    confirm_password = PasswordField('Confirm your password: ', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
    email = StringField('Email: ', validators=[Required(), Email()])
    password = PasswordField('Password: ', validators=[Required()])
    submit = SubmitField('Log In')

class RestaurantForm(FlaskForm):
    cuisine = StringField('What kind of food are you in the mood for?')
    city = StringField('What city do you want to search in?')
    submit = SubmitField('Search')

class WishListForm(FlaskForm):
    restaurant = BooleanField()
    submit = SubmitField('Add to Wish List')

def get_or_create_city(db_session, city):
    new_city = db_session.query(City).filter_by(name=city).first()
    if new_city:
        return new_city
    else:
        new_city = City(name=city)
        db_session.add(new_city)
        db_session.commit()
        return new_city

def get_or_create_cuisine(db_session, cuisine):
    new_cuisine = db_session.query(Cuisine).filter_by(name=cuisine).first()
    if new_cuisine:
        return new_cuisine
    else:
        new_cuisine = Cuisine(name=cuisine)
        db_session.add(new_cuisine)
        db_session.commit()
        return new_cuisine

def get_or_create_restaurant(db_session, restaurant_name, city_name, cuisines_list = []):
    city = get_or_create_city(db_session, city=city_name)
    #cuisine = get_or_create_cuisine(cuisine_name)
    restaurant = db_session.query(Restaurant).filter_by(name=restaurant_name, city_id=city.id).first()
    if restaurant:
        return restaurant
    else:
        restaurant = Restaurant(name=restaurant_name, city_id=city.id)
        for cuisine in cuisines_list:
            cuisine = get_or_create_cuisine(db_session, cuisine=cuisine)
            restaurant.cuisines.append(cuisine)
        db_session.add(restaurant)
        db_session.commit()
        return restaurant

def get_or_create_wishlist(db_session, restaurants=[]):
    wishlist = db_session.query(WishListRestaurants).filter_by(user_id=current_user.id).first()
    if wishlist:
        for res in restaurants:
            if res not in wishlist.restaurants:
                wishlist.restaurants.append(res)
        return wishlist
    else:
        wishlist = WishListRestaurants(user_id=current_user.id)
        for res in restaurants:
            wishlist.restaurants.append(res)
        db_session.add(wishlist)
        db_session.commit()
        return wishlist

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error404.html'), 404

@app.errorhandler(500)
def internal_server_error():
    return render_template('error505.html'), 500

@app.route('/register', methods=["GET", "POST"])
def user_registration():
    form = RegistrationForm()
    if form.validate_on_submit():
        #pro_pic_data = request.FILES[form.file.name].read() #?? QUESTION ABOUT THIS PROCESS OF SAVING FILE TO DB
        #open(os.path.join(UPLOAD_PATH, form.file.data), 'w').write(pro_pic_data)
        #form.file.data.save('static/imgs/' + filename)
        #pro_pic_path = 'static/imgs/' + filename
        # filename = secure_filename(form.file.data)
        # path = 'static/imgs' + filename
        # form.file.data.save(path)
        #pro_pic = form.file.data.read()
        # if 'file' not in request.files:
        #     print('No file')
        # else:
        #     file = request.files['file']
        #     print(file)
        # a = request.args
        # for each in a:
        #     print(a.get(each))
        #     print(a.getlist(each))

        # print(type(form.file))
        # print(type(form.file.data))
        filename = secure_filename(form.file.data.filename)
        form.file.data.save('static/imgs/' + filename)

        # filename = secure_filename(form.file.data)
        # form.file.save('static/imgs/' + filename)

        user = User(email=form.email.data, username=form.username.data, password=form.password.data) #?? ADD IN PRO PIC!
        db.session.add(user)
        db.session.commit()
        flash("Great! You're all set")
        return redirect(url_for('login'))
    return render_template('registration.html', form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
            return redirect(url_for('welcomepage'))
        flash('Something went wrong. Invalid username or password')
    return render_template('logging_in.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You're logged out!")
    return redirect(url_for('login'))

@app.route('/hidden')
def hidden():
    return render_template('hidden.html') #?? HOW TO WORK WITH LOGIN_REQUIRED

@app.route('/', methods=["GET", "POST"])
@login_required
def welcomepage():
    form = RestaurantForm()
    if form.validate_on_submit():
        cuisine = form.cuisine.data
        city = form.city.data
        session['cuisine'] = cuisine
        session['city'] = city
        restaurant_data = get_restaurants(cuisine=cuisine, city=city)
        return render_template('addrestaurants.html', data=restaurant_data)
    return render_template('welcomepage.html', form=form)

@app.route('/wishlist', methods=["POST"])
@login_required
def wishlist():
    if request.method == 'POST':
        to_add = request.form.getlist('restaurant')
        y = [get_or_create_restaurant(db.session, restaurant_name=each, city_name=session['city'], cuisines_list=[session['cuisine']]) for each in to_add]
        w = get_or_create_wishlist(db.session, restaurants=y)
        send_email(current_user.email, 'New Restaurants Added To WishList', 'mail/new_restaurant', data=to_add, city=session['city'])

    #restaurants = Restaurant.query.all()
    #res_dict = {}
    #for each in restaurants:
        # wishlist.restaurants.append(each.name) ?? SAVING TO SPECIFIC WISHLIST
    #    city_name = City.query.filter_by(id=each.city_id).first()
        # cuisine_name = Cuisine.query.filter_by(id=each.cuisines).first() #?? HOW TO SHOW TYPE OF CUISINE
    #    res_dict[each.name] = (city_name.name, 'cuisine name here')
    #num_restaurants = len(restaurants)
        q = [each.name for each in w.restaurants]
        return render_template('seewishlist.html', res_dict = q, num_restaurants=w.restaurants.count())

if __name__ == '__main__':
    db.create_all()
    manager.run()
