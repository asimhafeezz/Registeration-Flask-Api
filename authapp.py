from flask import Flask, request, jsonify, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
import uuid
from werkzeug.security import generate_password_hash , check_password_hash
import jwt
import datetime
from functools import wraps
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import logging
from validate_email import validate_email
from flask_cors import CORS

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# cors
CORS(app)

# secret key
app.config['SECRET_KEY'] = "mysecretkey"

# DataBase Configration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.Sqlite_authapp')
app.config['SQLALCHEMY_TRACKER_MODIFICATION'] = False

#Email Configuration..
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'helpforsafar@gmail.com'
app.config['MAIL_PASSWORD'] = "merasafaracc"
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# db
db = SQLAlchemy(app)

#ma
ma = Marshmallow(app)

#mail
mail = Mail(app)

#URLSerializer
url_serializer = URLSafeTimedSerializer(app.config.get('SECRET_KEY'))


# token required function
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# User class/model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(200) , unique=True)
    email = db.Column(db.String(50) , nullable=False , unique=True)
    password = db.Column(db.String(150))
    firstName= db.Column(db.String(150))
    lastName= db.Column(db.String(150))

    def __init__(self, public_id, email, password , firstName , lastName):
        self.public_id = public_id
        self.email = email
        self.password = password
        self.firstName = firstName
        self.lastName = lastName


# create database all tables
db.create_all()

# User Schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id' , 'public_id' , "email" , 'password' , 'firstName' , 'lastName')

# init schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

# add user (registration)
@app.route('/register', methods=['POST'])
def registeration():
    firstName = request.json['firstName']
    lastName = request.json['lastName']
    email = request.json['email']

    db_user = User.query.filter_by(email=email).first()
    
    if db_user:
        return jsonify({'msg':'This email already exists'})
    # else:
    #     is_valid = validate_email(email, verify=True)
    #     if not is_valid:
    #         return jsonify({"msg": "email address is not valid"})
        
    


    password = generate_password_hash(request.json['password'] , method='sha256')
    public_id = str(uuid.uuid4())
    
    new_user = User(public_id, email, password, firstName , lastName)
    
    db.session.add(new_user)
    db.session.commit()

    return user_schema.jsonify(new_user)

#  show all users
@app.route('/users', methods=['GET'])
@token_required
def show_all_users(current_user):
    users = User.query.all()
    all_users = users_schema.dump(users)
    
    return jsonify(all_users)


# get user by id (public_id)
@app.route('/user/<public_id>', methods=['GET'])
def get_user_by_id(current_user , public_id):
    user = User.query.filter_by(public_id= public_id).first()
    return user_schema.dump(user)

#login
@app.route('/login', methods=['POST'])
def login():
    entered_email = request.json['email']
    entered_password = request.json['password']

    db_user = User.query.filter_by(email=entered_email).first()

    if not db_user:
        return jsonify({'msg': 'You entered wrong email or password'})

    if db_user.email == entered_email and check_password_hash(db_user.password, entered_password):
        token = jwt.encode({'public_id': db_user.public_id , 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)} , app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8') , 'user_data' : user_schema.dump(db_user)})
    
    
    return jsonify({'msg': 'You entered wrong email or password'})


# forget Password
@app.route('/forget_password', methods=['POST'])
def change_password():
    email = request.json['email']
    db_user = User.query.filter_by(email=email).first()

    if not db_user:
        return jsonify({'errormsg': 'You email address is invalid!'})

    logging.log(logging.INFO, "User email is valid!")
    token = url_serializer.dumps(email, salt='thisisemailsalt')
    message = Message('Password Reset', sender=app.config.get('MAIL_USERNAME'),
                          recipients=[email])
    link = url_for('reset_password', token=token, _external=True)
    message.body = 'To reset your password, visit the following link '+link

    mail.send(message)

    return jsonify({'validmsg':'A password reset link has been sent!'})

@app.route('/reset_password/<token>')
def reset_password(token):
    return render_template('form.html', token=token)

@app.route('/reset_password_endpoint', methods=['POST'])
def reset_password_endpoint():
    new_password = request.form['new_password']
    token = request.form['t']

    try:
        email = url_serializer.loads(token, salt='thisisemailsalt', max_age=3600)
        db_user = User.query.filter_by(email=email).first()
        
        db_user.password = generate_password_hash(new_password , method='sha256')
        db.session.commit()
        return jsonify({'validmsg': 'Password has been successfully changed!'}), 200



    except SignatureExpired:
        return jsonify({'errormsg': 'Url has been expired! Try a new one..'})

    



if __name__ == "__main__":
    app.run(debug=True)