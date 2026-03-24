"""urauth SQLModel integration — requires ``pip install urauth[sqlmodel]``."""

from urauth.contrib.sqlmodel.auth import create_sqlmodel_auth
from urauth.contrib.sqlmodel.models import RoleBase, UserBase

__all__ = [
    "RoleBase",
    "UserBase",
    "create_sqlmodel_auth",
]
