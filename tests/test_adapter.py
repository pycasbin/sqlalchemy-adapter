from casbin_sqlalchemy_adapter import Adapter
from casbin_sqlalchemy_adapter import Base
from casbin_sqlalchemy_adapter import CasbinRule
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest import TestCase
import casbin
import os
import simpleeval


def get_fixture(path):
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


def get_enforcer():
    engine = create_engine("sqlite://")
    adapter = Adapter(engine)

    session = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    s = session()

    s.add(CasbinRule(ptype='p', v0='alice', v1='data1', v2='read'))
    s.add(CasbinRule(ptype='p', v0='bob', v1='data2', v2='write'))
    s.add(CasbinRule(ptype='p', v0='data2_admin', v1='data2', v2='read'))
    s.add(CasbinRule(ptype='p', v0='data2_admin', v1='data2', v2='write'))
    s.add(CasbinRule(ptype='g', v0='alice', v1='data2_admin'))
    s.commit()
    s.close()

    return casbin.Enforcer(get_fixture('rbac_model.conf'), adapter, True)


class TestConfig(TestCase):

    def test_enforcer_basic(self):
        e = get_enforcer()
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

    def test_add_policy(self):
        adapter = Adapter('sqlite://')
        e = casbin.Enforcer(get_fixture('rbac_model.conf'), adapter, True)

        try:
            self.assertFalse(e.enforce('alice', 'data1', 'read'))
            self.assertFalse(e.enforce('bob', 'data1', 'read'))
            self.assertFalse(e.enforce('bob', 'data2', 'write'))
            self.assertFalse(e.enforce('alice', 'data2', 'read'))
            self.assertFalse(e.enforce('alice', 'data2', 'write'))
        except simpleeval.NameNotDefined:
            # This is caused by an upstream bug when there is no policy loaded
            # Should be resolved in pycasbin >= 0.3
            pass

        adapter.add_policy(sec=None, ptype='p', rule=['alice', 'data1', 'read'])
        adapter.add_policy(sec=None, ptype='p', rule=['bob', 'data2', 'write'])
        adapter.add_policy(sec=None, ptype='p', rule=['data2_admin', 'data2', 'read'])
        adapter.add_policy(sec=None, ptype='p', rule=['data2_admin', 'data2', 'write'])
        adapter.add_policy(sec=None, ptype='g', rule=['alice', 'data2_admin'])

        e.load_policy()

        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bogus', 'data2', 'write'))

    def test_save_policy(self):
        model = casbin.Enforcer(get_fixture('rbac_model.conf'), get_fixture('rbac_policy.csv')).model
        adapter = Adapter('sqlite://')
        adapter.save_policy(model)
        e = casbin.Enforcer(get_fixture('rbac_model.conf'), adapter)

        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

    def test_str(self):
        rule = CasbinRule(ptype='p', v0='alice', v1='data1', v2='read')
        self.assertEqual(str(rule), 'p, alice, data1, read')

    def test_repr(self):
        rule = CasbinRule(ptype='p', v0='alice', v1='data1', v2='read')
        self.assertEqual(repr(rule), '<CasbinRule None: "p, alice, data1, read">')
        engine = create_engine("sqlite://")

        session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)
        s = session()

        s.add(rule)
        s.commit()
        self.assertRegex(repr(rule), r'<CasbinRule \d+: "p, alice, data1, read">')
        s.close()
