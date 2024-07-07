from datetime import datetime, UTC

import casbin
from casbin_sqlalchemy_adapter import Base, Adapter
from sqlalchemy import false, Column, DateTime, String, Integer, Boolean
from sqlalchemy.engine.default import DefaultExecutionContext

from some_user_library import get_current_user_id


def _deleted_at_default(context: DefaultExecutionContext) -> datetime | None:
    current_parameters = context.get_current_parameters()
    if current_parameters.get("is_deleted"):
        return datetime.now(UTC)
    else:
        return None


def _deleted_by_default(context: DefaultExecutionContext) -> int | None:
    current_parameters = context.get_current_parameters()
    if current_parameters.get("is_deleted"):
        return get_current_user_id()
    else:
        return None


class BaseModel(Base):
    __abstract__ = True

    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )
    deleted_at = Column(
        DateTime,
        default=_deleted_at_default,
        onupdate=_deleted_at_default,
        nullable=True,
    )

    created_by = Column(Integer, default=get_current_user_id, nullable=False)
    updated_by = Column(
        Integer,
        default=get_current_user_id,
        onupdate=get_current_user_id,
        nullable=False,
    )
    deleted_by = Column(
        Integer,
        default=_deleted_by_default,
        onupdate=_deleted_by_default,
        nullable=True,
    )
    is_deleted = Column(
        Boolean,
        server_default=false(),
        index=True,
        nullable=False,
    )


class CasbinSoftDeleteRule(BaseModel):
    __tablename__ = "casbin_rule"

    id = Column(Integer, primary_key=True)
    ptype = Column(String(255))
    v0 = Column(String(255))
    v1 = Column(String(255))
    v2 = Column(String(255))
    v3 = Column(String(255))
    v4 = Column(String(255))
    v5 = Column(String(255))


engine = your_engine_factory()
# Initialize the Adapter, pass your custom CasbinRule model
# and pass the Boolean field indicating whether a rule is deleted or not
# your model needs to handle the update of fields
# 'updated_by', 'updated_at', 'deleted_by', etc.
adapter = Adapter(
    engine,
    CasbinSoftDeleteRule,
    CasbinSoftDeleteRule.is_deleted,
)
# Create the Enforcer, etc.
e = casbin.Enforcer("path/to/model.conf", adapter)
...
