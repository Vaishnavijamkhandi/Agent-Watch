"""Use an isolated temporary SQLite database for the test module; never touch agentwatch.db."""
import os, tempfile
_db = os.path.join(tempfile.gettempdir(), f"agentwatch-pytest-{os.getpid()}.db")
os.environ.setdefault("DATABASE_URL", "sqlite:///" + _db)
os.environ.setdefault("AGENTWATCH_DEMO", "1")
