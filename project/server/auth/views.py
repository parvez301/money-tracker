# project/server/auth/views.py
from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
import json
from project.server import bcrypt, db
from project.server.models import User, BlacklistToken,CategoryList,ExpenseList
from flask_cors import CORS

auth_blueprint = Blueprint('auth', __name__)

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        # get the post data
        post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            
            try:
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password')
                )
                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                print("sa")
                auth_token = user.encode_auth_token(user.id)
                print("as")
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202


class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            # fetch the user data
            user = User.query.filter_by(
                email=post_data.get('email')
            ).first()
            if user and bcrypt.check_password_hash(
                user.password, post_data.get('password')
            ):
                auth_token = user.encode_auth_token(user.id)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode()
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500

class UserAPI(MethodView):
    """
    User Resource
    """
    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                #print(user)
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401



class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class ExpenseDetailsAPI(MethodView):
    # Expense List Resource

    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        print(auth_header)
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                query = ExpenseList.query.filter_by(user_id=resp)
                return make_response(jsonify([i.serialize for i in query.all()])),200

            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401



class CategoryListAPI(MethodView):
    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                #query = CategoryList.query.filter_by(user_id=resp)
                result = CategoryList.query.with_entities(CategoryList.id, CategoryList.name).filter_by(user_id=1).all()
                '''a = []
                for i in query.all():
                    a.append(i.name)
                    print(i.name)
                print(a)''' 
                return make_response(jsonify(result)),200
                #return make_response(jsonify([i.serialize for i in query.all()])),200

            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


class GraphDataAPI(MethodView):
    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                #result = ExpenseList.query.with_entities(ExpenseList.name, ExpenseList.money_spent).filter_by(user_id=resp).all()
                #return make_response(jsonify(result)),200
                #return make_response(jsonify([i.serialize for i in query.all()])),200
                query = ExpenseList.query.filter_by(user_id=resp)
                return make_response(jsonify([i.graph_data for i in query.all()])),200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401



class AddExpenseAPI(MethodView):
    def post(self):
        # get the post data
        post_data = request.get_json()
        print(post_data.get('name'))
        print(post_data.get('money_spent'))
        print(post_data.get('category_id'))
        print(post_data.get('is_recurring'))
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        
        else:
            auth_token = ''
            
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
               
                new_expense = ExpenseList(
                        name=post_data.get('name'),
                        money_spent = post_data.get('money_spent'),
                        category_id = post_data.get('catgegory_id'),
                        user_id = resp,
                        is_recurring = post_data.get('is_recurring'),
                        created_on = 'now()'
                    )
                db.session.add(new_expense)
                db.session.commit()
                responseObject = {
                'status': 'Expense Added',
                'message': resp
                }
                return make_response(jsonify(responseObject)), 401
                responseObject = {
                'status': 'fail',
                'message': resp
                }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401

           
class AddCategoryAPI(MethodView):
    def post(self):
        print("received")
        # get the post data
        post_data = request.get_json()
        print(post_data)
        print(request.headers)
        auth_header = request.headers.get('Authorization')
        print("sd")
        print(auth_header)
        
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401, {'Access-Control-Allow-Origin': '*'}
                print(auth_token)
        else:
            auth_token = ''
        
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                print(resp)
                new_category = CategoryList(
                        name=post_data.get('name'),
                        user_id = resp,
                        created_on = 'now()'
                    )
                db.session.add(new_category)
                db.session.commit()
                responseObject = {
                'status': 'New Catgeory Successfully Added',
                'message': resp
                }
                return make_response(jsonify(responseObject)), 201, {'Access-Control-Allow-Origin': '*'}
            else:
                responseObject = {
                'status': 'fail',
                'message': resp
                }
                return make_response(jsonify(responseObject)), 401,{'Access-Control-Allow-Origin': '*'}
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401, {'Access-Control-Allow-Origin': '*'}

    def options (self):
        return {'Allow' : 'POST' }, 200, \
        { 'Access-Control-Allow-Origin': '*', \
        'Access-Control-Allow-Methods' : 'PUT,GET,POST' }
# define the API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')
expense_detail_view = ExpenseDetailsAPI.as_view('expense_detail_api')
category_list_view = CategoryListAPI.as_view('category_list_api')
add_expense_view = AddExpenseAPI.as_view('add_expense_api')
add_category_view = AddCategoryAPI.as_view('add_category_api')
graph_data_view = GraphDataAPI.as_view('graph_data_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/user/expenses',
    view_func=expense_detail_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/user/categories',
    view_func=category_list_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/user/dashboard',
    view_func=graph_data_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/user/add-expense',
    view_func=add_expense_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/user/add-category',
    view_func=add_category_view,
    methods=['POST']
)


