from pymongo import MongoClient

client = MongoClient("mongodb://localhost127.0.0.1:27017")
db = client.champDB
champions = db.champions

for champion in champions.find():
    champions.update_one(
        { "_id" : champion['_id']},
        {
            "$set" : {
                "reviews" : []
            }
        }
    )