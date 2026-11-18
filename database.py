
import os
from atexit import register
from threading import Lock
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import PyMongoError

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("MONGODB_DATABASE", "webguard")

client = None
db = None
_connection_lock = Lock()


def connect_database():
    global client, db

    if not MONGODB_URI:
        raise ValueError("MONGODB_URI is missing in .env")

    with _connection_lock:
        if client is not None and db is not None:
            return db

        new_client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=10000
        )

        try:
            new_client.admin.command("ping")
        except PyMongoError as error:
            new_client.close()
            print("MongoDB connection failed:", error)
            raise

        client = new_client
        db = client[DATABASE_NAME]

        print("MongoDB Atlas connected successfully!")
        print(f"Database: {DATABASE_NAME}")

        return db


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

    with _connection_lock:
        if client is not None:
            client.close()
            client = None
            db = None
            print("MongoDB connection closed.")


register(close_database)


if __name__ == "__main__":
    connect_database()
    close_database()
