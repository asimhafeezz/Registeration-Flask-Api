# Registeration-Flask-Api
SignIn/SignUp Api with also forget password email service using Flask Resful services 
## Start Using Pipenv

``` bash
# Activate virtualenv
$ pipenv shell

# Install dependencies
$ pipenv install

# Run Server (http://localhost:5000)
python authapp.py
```

## Routes

* GET     /users
* GET     /user/:public_id
* POST    /register
* POST    /login
* POST    /forget_password
* POST    /reset_password/<token>
