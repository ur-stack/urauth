"""urauth SQLAlchemy integration — requires ``pip install urauth[sqlalchemy]``."""

from urauth.contrib.sqlalchemy.auth import create_sqlalchemy_auth
from urauth.contrib.sqlalchemy.models import RoleMixin, UserMixin, user_role_table

__all__ = [
    "RoleMixin",
    "UserMixin",
    "create_sqlalchemy_auth",
    "user_role_table",
]
