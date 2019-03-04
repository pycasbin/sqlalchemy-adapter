from unittest import TestCase
from casbin_sqlalchemy_adapter import Adapter, CasbinRule
import casbin
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

dir = os.path.split(os.path.realpath(__file__))[0]


def get_enforcer():
    dsn = "sqlite:///" + dir + "/test.db"
    adapter = Adapter(dsn)

    engine = create_engine(dsn)
    session = sessionmaker(bind=engine)
    s = session()
    s.query(CasbinRule).delete(synchronize_session=False)

    s.add(CasbinRule(ptype='p', v0='alice', v1='data1', v2='read'))
    s.add(CasbinRule(ptype='p', v0='bob', v1='data2', v2='write'))
    s.add(CasbinRule(ptype='p', v0='data2_admin', v1='data2', v2='read'))
    s.add(CasbinRule(ptype='p', v0='data2_admin', v1='data2', v2='write'))
    s.add(CasbinRule(ptype='g', v0='alice', v1='data2_admin'))
    s.commit()
    s.close()

    return casbin.Enforcer(dir + '/rbac_model.conf', adapter, True)


class TestConfig(TestCase):

    def test_enforcer_basic(self):
        e = get_enforcer()
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))
