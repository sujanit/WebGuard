
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
_availability_history_index_created = False


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


def get_service_status(service_id):
    if db is None:
        connect_database()

    return db["availability_status"].find_one({"_id": service_id})


def save_availability_check(check, event=None):
    global _availability_history_index_created

    if db is None:
        connect_database()

    history = db["availability_history"]
    if not _availability_history_index_created:
        history.create_index("checked_at", expireAfterSeconds=2592000)
        _availability_history_index_created = True

    history.insert_one(check.copy())

    status = check.copy()
    status["_id"] = check["service_id"]
    status["last_checked_at"] = check["checked_at"]
    db["availability_status"].replace_one(
        {"_id": check["service_id"]},
        status,
        upsert=True
    )

    if event is not None:
        db["availability_events"].insert_one(event.copy())


def _serialize_availability_document(document):
    if document is None:
        return None

    serialized = document.copy()
    if "_id" in serialized:
        serialized["_id"] = str(serialized["_id"])

    for field in ("checked_at", "last_checked_at", "created_at"):
        value = serialized.get(field)
        if value is not None:
            serialized[field] = value.isoformat()

    return serialized


def get_availability_dashboard(services):
    if not services:
        return {"services": [], "events": []}

    if db is None:
        connect_database()

    service_ids = [service["service_id"] for service in services]
    saved_statuses = {
        status["service_id"]: status
        for status in db["availability_status"].find(
            {"_id": {"$in": service_ids}}
        )
    }

    statuses = []
    for service in services:
        status = saved_statuses.get(service["service_id"])
        if status is None:
            status = {
                **service,
                "state": "Unknown",
                "status_code": None,
                "response_time_ms": None,
                "last_checked_at": None,
                "recovery_attempts": 0,
                "error": None
            }
        else:
            status = {
                **status,
                "name": service["name"],
                "url": service["url"]
            }
        statuses.append(_serialize_availability_document(status))

    events = [
        _serialize_availability_document(event)
        for event in db["availability_events"]
        .find({"service_id": {"$in": service_ids}})
        .sort("created_at", -1)
        .limit(30)
    ]

    return {"services": statuses, "events": events}


def get_service_history(service_id, limit=50):
    if db is None:
        connect_database()

    records = (
        db["availability_history"]
        .find({"service_id": service_id})
        .sort("checked_at", -1)
        .limit(limit)
    )

    return [
        _serialize_availability_document(record)
        for record in records
    ]


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
