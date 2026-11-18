from datetime import datetime, timezone

import database


def test_connect_database_reuses_client(monkeypatch):
    class FakeDatabase:
        pass

    class FakeAdmin:
        def command(self, name):
            assert name == "ping"

    class FakeClient:
        def __init__(self, uri, serverSelectionTimeoutMS):
            assert uri == "mongodb://example"
            assert serverSelectionTimeoutMS == 10000
            self.admin = FakeAdmin()
            self.database = FakeDatabase()

        def __getitem__(self, name):
            assert name == "webguard"
            return self.database

    created_clients = []

    def create_client(*args, **kwargs):
        created_clients.append(FakeClient(*args, **kwargs))
        return created_clients[-1]

    monkeypatch.setattr(database, "MONGODB_URI", "mongodb://example")
    monkeypatch.setattr(database, "DATABASE_NAME", "webguard")
    monkeypatch.setattr(database, "MongoClient", create_client)
    monkeypatch.setattr(database, "client", None)
    monkeypatch.setattr(database, "db", None)

    first_db = database.connect_database()
    second_db = database.connect_database()

    assert first_db is second_db
    assert len(created_clients) == 1


def test_save_availability_check_persists_latest_state_history_and_event(monkeypatch):
    class FakeCollection:
        def __init__(self):
            self.inserted = []
            self.replaced = None
            self.index = None

        def create_index(self, field, **kwargs):
            self.index = (field, kwargs)

        def insert_one(self, document):
            self.inserted.append(document.copy())

        def replace_one(self, query, document, upsert):
            self.replaced = (query, document.copy(), upsert)

    class FakeDatabase:
        def __init__(self):
            self.collections = {}

        def __getitem__(self, name):
            return self.collections.setdefault(name, FakeCollection())

    fake_db = FakeDatabase()
    checked_at = datetime.now(timezone.utc)
    check = {
        "service_id": "service-1",
        "name": "API",
        "url": "https://api.example.com/health",
        "state": "Unavailable",
        "status_code": 503,
        "response_time_ms": 40,
        "checked_at": checked_at,
        "recovery_attempts": 0,
        "error": "HTTP 503"
    }
    event = {
        "service_id": "service-1",
        "type": "failure",
        "created_at": checked_at
    }
    monkeypatch.setattr(database, "db", fake_db)
    monkeypatch.setattr(database, "_availability_history_index_created", False)

    database.save_availability_check(check, event)

    history = fake_db["availability_history"]
    status = fake_db["availability_status"]
    events = fake_db["availability_events"]
    assert history.index == ("checked_at", {"expireAfterSeconds": 2592000})
    assert history.inserted == [check]
    assert status.replaced[0] == {"_id": "service-1"}
    assert status.replaced[1]["state"] == "Unavailable"
    assert status.replaced[1]["last_checked_at"] == checked_at
    assert status.replaced[2] is True
    assert events.inserted == [event]
