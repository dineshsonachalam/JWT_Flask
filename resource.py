# resource.py -> used to build api end points
from flask_restful import Resource
from parser import User_Registration_Parser
from models import UserModel,RevokedTokenModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

# flask_restful builds way to build restful api
# Each end point in rest api is called resource
# Every class that use Resource as an argument will inherit all api end points



class UserRegistration(Resource):
    def post(self):
        parser_obj = User_Registration_Parser()
        data = parser_obj.user_login_credential()
        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'. format(data['username'])}

        # adding the new user to db
        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
        )
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message':"User {} was created".format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except:
            return {'message':'something went wrong'},500

class UserLogin(Resource):
    def post(self):
        parser_obj = User_Registration_Parser()
        data = parser_obj.user_login_credential()
        current_user =  UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}

        if UserModel.verify_hash(data['password'],current_user.password):
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token':access_token,
                'refresh_token':refresh_token
            }
        else:
            return {'message': 'Wrong credentials'}



class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500



class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class TokenRefresh(Resource):
    def post(self):
        return {'message': 'Token refresh'}


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()

    def delete(self):
        return UserModel.delete_all()


class SecretResource(Resource):
    @jwt_required # @jwt_required -> creates a protected resource.
    def get(self):
        return {
            'answer': 42
        }


# Default access token, expires in 15 min
# We can reissue access token with refresh token

class TokenRefresh(Resource):
    @jwt_refresh_token_required # means you can access this path only by refresh token
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}
