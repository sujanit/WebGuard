
import logging
from pathlib import Path


LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "webguard.log"


def get_logger():

    logger = logging.getLogger("WebGuard")

    logger.setLevel(logging.INFO)

    if not logger.handlers:

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )

        # File logging
        file_handler = logging.FileHandler(
            LOG_FILE,
            encoding="utf-8"
        )

        file_handler.setFormatter(formatter)

        logger.addHandler(file_handler)

        # Console logging
        console_handler = logging.StreamHandler()

        console_handler.setFormatter(formatter)

        logger.addHandler(console_handler)

    return logger
