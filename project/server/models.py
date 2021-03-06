# project/server/models.py
import jwt
import datetime

from project.server import app, db, bcrypt


class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_name = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self,  user_name,email, password, admin=False):
        self.user_name = user_name
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.registered_on = datetime.datetime.now()
        self.admin = admin

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1, minutes=30, seconds=5),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'


class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False


class CategoryList(db.Model):
    __tablename__ = 'category_list'

    id = db.Column(db.Integer,primary_key = True, autoincrement=True)
    name = db.Column(db.String(500), autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_on = db.Column(db.DateTime, nullable=False)

    def __init__(self,name,user_id,created_on):
        self.name = name
        self.user_id = user_id
        self.created_on = datetime.datetime.now()

    @property
    def serialize(self):
        return {
            'name' : self.name,
            'id' : self.id,
            'created_on' : self.created_on,
            'user_id' : self.user_id
         }

class ExpenseList(db.Model):
    __tablename__ = 'expense_list'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(500), unique=True, nullable=False)
    money_spent = db.Column(db.Integer, nullable=False)
    #category_id = db.Column(db.Integer, db.ForeignKey('category_list.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('category_list.id'),
        nullable=False)
    category = db.relationship('CategoryList',
        backref=db.backref('expense_list', lazy=True))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_recurring = db.Column(db.Boolean,nullable=False, default=False)
    created_on = db.Column(db.DateTime, nullable=False)

    def __init__(self,name,money_spent,category_id,user_id,is_recurring,created_on):
        self.name = name
        self.money_spent = money_spent
        self.category_id = category_id
        self.user_id = user_id
        self.is_recurring = is_recurring
        self.created_on = datetime.datetime.now()

    @property
    def serialize(self):
        return {
            'money_spent' : self.money_spent,
            'category' : self.category_id,
            'created_on' : self.created_on,
            'name' : self.name,
            'is_recurring' : self.is_recurring
         }
    @property
    def graph_data(self):
        return {
            'name' : self.name,
            'value' : self.money_spent,
         }



db.create_all()