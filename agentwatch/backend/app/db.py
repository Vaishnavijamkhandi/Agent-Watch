"""Database facade for the prototype's SQLAlchemy persistence layer.

The current repair build retains a generic JSON record table for backward-compatible demo
storage; normalized per-entity models/migrations remain a known limitation.
"""
from .main import Base, Record, engine, Session, all_rows, get, put, add, seed

__all__ = ['Base','Record','engine','Session','all_rows','get','put','add','seed']
