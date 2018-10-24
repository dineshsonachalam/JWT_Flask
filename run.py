from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager


app = Flask(__name__)
api = Api(app) # created an api object



app.config['JWT_SECRET_KEY'] = 'admin'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(app)

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)


# URI: postgresql://<username>:<password>@localhost:<port_number>/<database_name>
# URI: postgresql://dinesh:admin@localhost:5432/jwt
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://dinesh:admin@localhost:5432/jwt'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'admin'

db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
    db.create_all()

import  views,models,resource

# Register apapp.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SECREi end points from resource.py
api.add_resource(resource.UserRegistration,'/registration')
api.add_resource(resource.UserLogin,'/login')
api.add_resource(resource.UserLogoutAccess,'/logout/access')
api.add_resource(resource.UserLogoutRefresh,'/logout/refresh')
api.add_resource(resource.TokenRefresh, '/token/refresh')
api.add_resource(resource.AllUsers, '/users')
api.add_resource(resource.SecretResource, '/secret')
