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
