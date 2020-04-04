from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
import uuid
from werkzeug.security import generate_password_hash , check_password_hash

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
# DataBase Configration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.Sqlite_authapp')
app.config['SQLALCHEMY_TRACKER_MODIFICATION'] = False

# db
db = SQLAlchemy(app)

#ma
ma = Marshmallow(app)

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
    password = generate_password_hash(request.json['password'] , method='sha256')
    public_id = str(uuid.uuid4())
    
    new_user = User(public_id, email, password, firstName , lastName)
    
    db.session.add(new_user)
    db.session.commit()

    return user_schema.jsonify(new_user)

#  show all users
@app.route('/users', methods=['GET'])
def show_all_users():
    users = User.query.all()
    all_users = users_schema.dump(users)
    
    return jsonify(all_users)


# get user by id (public_id)
@app.route('/user/<public_id>', methods=['GET'])
def get_user_by_id(public_id):
    user = User.query.filter_by(public_id= public_id).first()
    return user_schema.dump(user)


@app.route('/login', methods=['POST'])
def login():
    entered_email = request.json['email']
    entered_password = request.json['password']

    db_user = User.query.filter_by(email=entered_email).first()

    if not db_user.email:
        return jsonify({'msg': 'You entered wrong email'})

    if db_user.email == entered_email and check_password_hash(db_user.password , entered_password):
        return jsonify({'msg': 'You are logged In'})
    
    
    return jsonify({'msg': 'You entered wrong email or password'})


# forget Password

if __name__ == "__main__":
    app.run(debug=True)