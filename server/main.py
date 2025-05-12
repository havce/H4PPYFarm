import worker

from threading import Thread
from waitress import serve
from app import app
from database import db
from config import Config


_worker = Thread(daemon=True, target=worker.task, args=(app,))


def main() -> None:
    with app.app_context():
        db.create_all()
    _worker.start()
    serve(app, host=Config.address, port=Config.port)


if __name__ == "__main__":
    main()
