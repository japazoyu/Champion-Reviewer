from pymongo import MongoClient
import bcrypt

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.champDB
users = db.users        # select the collection name

user_list = [
          { 
            "name" : "Ethan User",
            "username" : "ethanuser",  
            "password" : b"user",
            "email" : "ethanuser@user.com",
            "admin" : False
          },
          { 
            "name" : "Ethan Admin",
            "username" : "ethanadmin",  
            "password" : b"admin",
            "email" : "ethanadmin@admin.com",
            "admin" : True
          }
       ]

for new_user in user_list:
      new_user["password"] = bcrypt.hashpw(new_user["password"], bcrypt.gensalt())
      users.insert_one(new_user)
