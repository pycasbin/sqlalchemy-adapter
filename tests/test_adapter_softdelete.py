import os
from pathlib import Path

import casbin
from sqlalchemy import create_engine, Column, Boolean, Integer, String
from sqlalchemy.orm import sessionmaker

from casbin_sqlalchemy_adapter import Adapter
from casbin_sqlalchemy_adapter import Base
from casbin_sqlalchemy_adapter import CasbinRule

from tests.test_adapter import TestConfig


class CasbinRuleSoftDelete(Base):
    __tablename__ = "casbin_rule_soft_delete"

    id = Column(Integer, primary_key=True)
    ptype = Column(String(255))
    v0 = Column(String(255))
    v1 = Column(String(255))
    v2 = Column(String(255))
    v3 = Column(String(255))
    v4 = Column(String(255))
    v5 = Column(String(255))

    is_deleted = Column(Boolean, default=False, index=True, nullable=False)

    def __str__(self):
        arr = [self.ptype]
        for v in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
            if v is None:
                break
            arr.append(v)
        return ", ".join(arr)

    def __repr__(self):
        return '<CasbinRule {}: "{}">'.format(self.id, str(self))


class TestConfigSoftDelete(TestConfig):
    def get_enforcer(self):
        engine = create_engine("sqlite://")
        # engine = create_engine('sqlite:///' + os.path.split(os.path.realpath(__file__))[0] + '/test.db', echo=True)
        adapter = Adapter(engine, CasbinRuleSoftDelete, "is_deleted")

        session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)
        s = session()
        s.query(CasbinRuleSoftDelete).delete()
        s.add(CasbinRuleSoftDelete(ptype="p", v0="alice", v1="data1", v2="read"))
        s.add(CasbinRuleSoftDelete(ptype="p", v0="bob", v1="data2", v2="write"))
        s.add(CasbinRuleSoftDelete(ptype="p", v0="data2_admin", v1="data2", v2="read"))
        s.add(CasbinRuleSoftDelete(ptype="p", v0="data2_admin", v1="data2", v2="write"))
        s.add(CasbinRuleSoftDelete(ptype="g", v0="alice", v1="data2_admin"))
        s.commit()
        s.close()

        scriptdir = Path(os.path.dirname(os.path.realpath(__file__)))
        model_path = scriptdir / "rbac_model.conf"

        return casbin.Enforcer(str(model_path), adapter)
