"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
import bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt

api = Blueprint('api', __name__)

@api.route('/register', methods=['POST'])
def register():
    body= request.get_json()
    hashed = bcrypt.hashpw(body['password'].encode(), bcrypt.gensalt())
    print(hashed)
    user= User(body['email'], hashed.decode())
    db.session.add(user)
    db.session.commit()
    return jsonify(user.serialize()), 200

@api.route('/login', methods=['POST'])
def login():
    body= request.get_json()
    user= User.query.filter_by(email = body['email']).one()
    if user is None : 
        return jsonify("USER IS NOT FOUND"), 404
    if bcrypt.checkpw(body['password'].encode(), user.password.encode()):
        access_token = create_access_token(identity=user.serialize())
        return jsonify({
            "token": access_token
        }), 200 
    else:
        return jsonify("PASSWORD IS NOT CORRECT"), 403

@api.route('/private', methods=['GET'])
@jwt_required()
def private():
    print(get_jwt())
    return jsonify("YOU ARE AT THE PRIVATE ROUTE"), 200

