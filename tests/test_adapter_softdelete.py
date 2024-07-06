import os
from pathlib import Path

import casbin
from sqlalchemy import create_engine, Column, Boolean, Integer, String
from sqlalchemy.orm import sessionmaker

from casbin_sqlalchemy_adapter import Adapter
from casbin_sqlalchemy_adapter import Base
from casbin_sqlalchemy_adapter.adapter import Filter

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


def query_for_rule(session, adapter, ptype, v0, v1, v2):
    rule_filter = Filter()
    rule_filter.ptype = [ptype]
    rule_filter.v0 = [v0]
    rule_filter.v1 = [v1]
    rule_filter.v2 = [v2]
    query = session.query(CasbinRuleSoftDelete)
    query = adapter.filter_query(query, rule_filter)
    return query


class TestConfigSoftDelete(TestConfig):
    def get_enforcer(self):
        engine = create_engine("sqlite://")
        engine = create_engine(
            "sqlite:///" + os.path.split(os.path.realpath(__file__))[0] + "/test.db",
            echo=True,
        )
        adapter = Adapter(engine, CasbinRuleSoftDelete, CasbinRuleSoftDelete.is_deleted)

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

    def test_softdelete_flag(self):
        e = self.get_enforcer()
        session = e.adapter.session_local()
        query = query_for_rule(session, e.adapter, "p", "alice", "data5", "read")

        self.assertFalse(e.enforce("alice", "data5", "read"))
        self.assertIsNone(query.first())
        e.add_permission_for_user("alice", "data5", "read")
        self.assertTrue(e.enforce("alice", "data5", "read"))
        self.assertTrue(query.count() == 1)
        self.assertFalse(query.first().is_deleted)
        e.delete_permission_for_user("alice", "data5", "read")
        self.assertFalse(e.enforce("alice", "data5", "read"))
        self.assertTrue(query.count() == 1)
        self.assertTrue(query.first().is_deleted)

    def test_save_policy_softdelete(self):
        e = self.get_enforcer()
        session = e.adapter.session_local()

        # Turn off auto save
        e.enable_auto_save(auto_save=False)

        # Delete some preexisting rules
        e.delete_permission_for_user("alice", "data1", "read")
        e.delete_permission_for_user("bob", "data2", "write")
        # Delete a non existing rule
        e.delete_permission_for_user("bob", "data100", "read")
        # Add some new rules
        e.add_permission_for_user("alice", "data100", "read")
        e.add_permission_for_user("bob", "data100", "write")

        # Write changes to database
        e.save_policy()

        self.assertTrue(
            query_for_rule(session, e.adapter, "p", "alice", "data1", "read")
            .first()
            .is_deleted
        )
        self.assertTrue(
            query_for_rule(session, e.adapter, "p", "bob", "data2", "write")
            .first()
            .is_deleted
        )
        self.assertIsNone(
            query_for_rule(session, e.adapter, "p", "bob", "data100", "read").first()
        )
        self.assertFalse(
            query_for_rule(session, e.adapter, "p", "alice", "data100", "read")
            .first()
            .is_deleted
        )
        self.assertFalse(
            query_for_rule(session, e.adapter, "p", "bob", "data100", "write")
            .first()
            .is_deleted
        )
