from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
from bson import ObjectId
import string
import jwt
import datetime
from functools import wraps
import bcrypt 
from flask_cors import CORS

def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        
        bl_token = blacklist.find_one({"token" : token})
        if bl_token is not None:
            return make_response(jsonify({'message': 'Token has been cancelled'}), 401)
        return func(*args, **kwargs)
    
    return jwt_required_wrapper

def admin_required(func):
    @wraps(func)
    def admin_required_wrapper(*args, **kwargs):
        token = request.headers['x-access-token']
        data = jwt.decode(token, app.config['SECRET_KEY'])
        if data["admin"]:
            return func(*args, **kwargs)
        else:
            return make_response(jsonify({'message': 'Admin access is required'}), 401)
    return admin_required_wrapper
            
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'b00785513'

#establishing connections between webapp and mongodb
client = MongoClient("mongodb://127.0.0.1:27017")
db = client.champDB
champions = db.champions
users = db.users
blacklist = db.blacklist

#creating pagination for data within dataset
@app.route("/api/v1.0/champions", methods=["GET"])
def show_all_champions():
    page_num, page_size = 1, 10
    if request.args.get("pn"):
        page_num = int(request.args.get('pn'))
        
    if request.args.get("ps"):
        page_size = int(request.args.get('ps'))
        
    page_start = (page_size * (page_num - 1))
    
    data_to_return = []
    for champion in champions.find().skip(page_start).limit(page_size):
        champion["_id"] = str(champion["_id"])
        for review in champion["reviews"]:
            review["_id"] = str(review["_id"])
        data_to_return.append(champion)
        
    return make_response( jsonify(data_to_return), 200)

#creating GET endpoint for our REST api
@app.route("/api/v1.0/champions/<string:id>", methods = ["GET"])
def show_one_champion(id):
    #validating whetehr champion ID is valid
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(jsonify({"error" : "Invalid champion ID"}), 404)
    champion = champions.find_one({"_id": ObjectId(id)}) #finding one champion within the DB using mongodb commands
    if champion is not None: 
        champion["_id"] = str(champion["_id"]) 
        for review in champion["reviews"]: 
            review["_id"] = str(review["_id"]) 
        return make_response(jsonify( [champion] ), 200) 
    else:
        return make_response(jsonify({"error" : "Invalid champion ID"}), 404) #bad response

# #creating POST endpoint for our REST api
# @app.route("/api/v1.0/champions/", methods = ["POST"])
# @jwt_required
# def add_new_champion():
#     if len(id) != 24 or not all(c in string.hexdigits for c in id):
#         return make_response(jsonify({"error" : "Invalid champion ID"}), 404)
    
#     if "name" in request.form and "town"  in request.form and "rating" in request.form: #estalbishing data fields
#         #new_champion creates schema for adding a new champion object
#         new_champion = {
#             "name": request.form["name"],
#             "town": request.form["town"],
#             "rating": request.form["rating"],
#             "reviews": []
#         }
#         #DB command to add one new champion object
#         new_champion_id = champions.insert_one(new_champion)
#         new_champion_link = "http://127.0.0.1:5000/api/v1.0/champions/" + \
#             str(new_champion_id.inserted_id)
#         return make_response( jsonify({"url" : new_champion_link}), 201)
#     else:
#         return make_response(jsonify({"error" : "Missing form data"}), 404)
    
# @app.route("/api/v1.0/champions/<string:id>", methods = ["PUT"])
# @jwt_required
# def edit_champion(id):
#     if len(id) != 24 or not all(c in string.hexdigits for c in id):
#         return make_response(jsonify({"error" : "Invalid champion ID"}), 404)
    
#     if "name" in request.form and "town"  in request.form and "rating" in request.form:
#         result = champions.update_one(
#             #almost the same as adding a new champion except champion ID is required in order to update form data
#             {"_id": ObjectId(id) }, 
#             {
#                 "$set" : {
#                     "name" : request.form["name"],
#                     "town": request.form["town"],
#                     "rating": request.form["rating"],
#                 }
#             }
#         )
#         #if the champion ID was correct
#         if result.matched_count ==1:
#             edit_champion_link = "http://127.0.0.1:5000/api/v1.0/champions/" + id
#             return make_response( jsonify({ "url": edit_champion_link }), 200)
    
#         else:
#             return make_response(jsonify({"error" : "Invalid champion ID"}), 404)
#     else:
#         return make_response(jsonify({"error" : "Missing form data"}), 404)
    
@app.route("/api/v1.0/champions/<string:id>", methods = ["DELETE"])
@jwt_required
@admin_required
def delete_champion(id):
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(jsonify({"error" : "Invalid champion ID"}), 404)
    #DB commant to delete one object using the object ID
    result = champions.delete_one({"_id": ObjectId(id)})
    if result.deleted_count == 1:
        return make_response( jsonify({}), 204)
    else:
        return make_response(jsonify({"error" : "Invalid champion ID"}), 404)
    
@app.route("/api/v1.0/champions/<string:id>/reviews", methods = ["POST"])
def add_new_review(id):
    #new_review defines schema used for review form data
    new_review = {
        "_id": ObjectId(),
        "username" : request.form["username"],
        "comment": request.form["comment"],
        "stars": request.form["stars"]
    }
    #We need to update the buisness object with the new review so we pass the champion ID and update the review field with our new review
    champions.update_one(
        {"_id" : ObjectId(id)},
        {
            '$push' : {"reviews" : new_review}
        }
    )
    new_review_link = "http://127.0.0.1:5000/api/v1.0/champions/" + id + \
        "/reviews/" + str(new_review["_id"])
    return make_response(jsonify({"url": new_review_link}), 201)

@app.route("/api/v1.0/champions/<string:id>/reviews", methods = ["GET"])
def fetch_all_reviews(id):
    #definding our returned data (reviews) as a list
    data_to_return = []
    champion = champions.find_one(
        #we find one review via the champion ID and then project the review without its ID
        {"_id" : ObjectId(id)}, {"reviews" : 1, "_id": 0}
    )
    for review in champion["reviews"]:
        review["_id"] = str(review["_id"])
        data_to_return.append(review)
    return make_response( jsonify( data_to_return ), 200)

@app.route("/api/v1.0/champions/<string:id>/reviews/<string:review_id>", methods = ["GET"])
@jwt_required
def fetch_one_review(id, review_id):
    champion = champions.find_one(
        { "reviews._id" : ObjectId(review_id) },
        {"_id" : 0, "reviews.$" : 1}
    )
    if champion is None:
        return make_response(jsonify({"error" : "Invalid champion or Review ID"}), 404)
    else:
        champion["reviews"][0]["_id"] = str(champion["reviews"][0]["_id"])
        return make_response( jsonify(champion["reviews"][0]), 200)
    
@app.route("/api/v1.0/champions/<string:id>/reviews/<string:review_id>", methods = ["PUT"])
@jwt_required
def edit_review(id, review_id):
    #using $ positonal operator again as it poitns to the single review that matches the ID given, so we onyl update that one review
    edited_review = {
        "reviews.$.username" : request.form["username"],
        "reviews.$.comment" : request.form["comment"],
        "reviews.$.stars" : request.form["stars"]
    }
    #We update our champion object by setting the review returned by the search as the new review (edited review)
    champions.update_one(
        {"reviews._id": ObjectId(review_id)},
        {"$set": edited_review}
    )
    edit_review_url = "http://127.0.0.1:5000/api/v1.0/champions/" + id + \
        "/reviews/" + review_id
    return make_response( jsonify({"url" : edit_review_url}), 200)

@app.route("/api/v1.0/champions/<string:id>/reviews/<string:review_id>", methods = ["DELETE"])
@jwt_required
@admin_required
def delete_review(id, review_id):
    #we again update one champion using the same ID found in the url
    #to pull from reviews collection the review with the corresponding ID found in the url
    champions.update_one(
        {"_id" : ObjectId(id)},
        {"$pull" : {"reviews" : { "_id" : ObjectId(review_id) } } }
    )
    return make_response( jsonify( {} ), 204)

@app.route("/api/v1.0/login", methods = ["GET"])
def login():
    auth = request.authorization
    if auth:
        user = users.find_one({"username" : auth.username})
        if user is not None:
            if bcrypt.checkpw(bytes(auth.password, 'UTF-8'), user["password"]):      
                token = jwt.encode({
                    'user' : auth.username,
                    'admin' : user["admin"],
                    'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
                }, app.config['SECRET_KEY'])
                return make_response(jsonify({'token' : token.decode('UTF-8') }), 200)
            else:
                return make_response(jsonify({'message' : 'Bad Password'}), 401)
        else:
            return make_response(jsonify({'message' : 'Bad Username'}), 401)
        
    return make_response(jsonify({'message' : 'Authentication is required'}), 401)

@app.route("/api/v1.0/logout", methods=["GET"])
@jwt_required
def logout():
    token = request.headers['x-access-token']
    blacklist.insert_one({"token": token})
    return make_response(jsonify({'message' : 'Logout Successful!'}), 200)


if __name__ == "__main__":
    app.run(debug = True)
    
# Figure out how to validate reviews for extra marks 