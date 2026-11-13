
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import PyMongoError

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("MONGODB_DATABASE", "webguard")

client = None
db = None


def connect_database():
    global client, db

    if not MONGODB_URI:
        raise ValueError("MONGODB_URI is missing in .env")

    try:
        client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=10000
        )

        # Verify the connection
        client.admin.command("ping")

        db = client[DATABASE_NAME]

        print("MongoDB Atlas connected successfully!")
        print(f"Database: {DATABASE_NAME}")

        return db

    except PyMongoError as error:
        print("MongoDB connection failed:", error)
        raise
def save_scan_result(scan_data):
    global db

    if db is None:
        connect_database()

    # Insert a copy to protect the original report
    db["scan_history"].insert_one(scan_data.copy())

    print("Scan result saved to MongoDB!")
def get_scan_history(limit=20):
    global db

    if db is None:
        connect_database()

    records = list(
        db["scan_history"]
        .find()
        .sort("_id", -1)
        .limit(limit)
    )

    # Convert MongoDB ObjectId into a string
    for record in records:
        record["_id"] = str(record["_id"])

    return records

def close_database():
    global client, db

    if client is not None:
        client.close()
        client = None
        db = None
        print("MongoDB connection closed.")


if __name__ == "__main__":
    connect_database()
    close_database()
