from casbin_sqlalchemy_adapter import Adapter
from casbin_sqlalchemy_adapter import Base
from casbin_sqlalchemy_adapter import CasbinRule
from casbin_sqlalchemy_adapter.adapter import Filter
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest import TestCase
import casbin
import os


def get_fixture(path):
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


def get_enforcer():
    engine = create_engine("sqlite://")
    # engine = create_engine('sqlite:///' + os.path.split(os.path.realpath(__file__))[0] + '/test.db', echo=True)
    adapter = Adapter(engine)

    session = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    s = session()
    s.query(CasbinRule).delete()
    s.add(CasbinRule(ptype='p', v0='alice', v1='data1', v2='read'))
    s.add(CasbinRule(ptype='p', v0='bob', v1='data2', v2='write'))
    s.add(CasbinRule(ptype='p', v0='data2_admin', v1='data2', v2='read'))
    s.add(CasbinRule(ptype='p', v0='data2_admin', v1='data2', v2='write'))
    s.add(CasbinRule(ptype='g', v0='alice', v1='data2_admin'))
    s.commit()
    s.close()

    return casbin.Enforcer(get_fixture('rbac_model.conf'), adapter)


class TestConfig(TestCase):
    def test_enforcer_basic(self):
        e = get_enforcer()

        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

    def test_add_policy(self):
        e = get_enforcer()

        self.assertFalse(e.enforce('eve', 'data3', 'read'))
        res = e.add_policies((('eve', 'data3', 'read'), ('eve', 'data4', 'read')))
        self.assertTrue(res)
        self.assertTrue(e.enforce('eve', 'data3', 'read'))
        self.assertTrue(e.enforce('eve', 'data4', 'read'))

    def test_add_policies(self):
        e = get_enforcer()

        self.assertFalse(e.enforce('eve', 'data3', 'read'))
        res = e.add_permission_for_user('eve', 'data3', 'read')
        self.assertTrue(res)
        self.assertTrue(e.enforce('eve', 'data3', 'read'))

    def test_save_policy(self):
        e = get_enforcer()
        self.assertFalse(e.enforce('alice', 'data4', 'read'))

        model = e.get_model()
        model.clear_policy()

        model.add_policy('p', 'p', ['alice', 'data4', 'read'])

        adapter = e.get_adapter()
        adapter.save_policy(model)
        self.assertTrue(e.enforce('alice', 'data4', 'read'))

    def test_remove_policy(self):
        e = get_enforcer()

        self.assertFalse(e.enforce('alice', 'data5', 'read'))
        e.add_permission_for_user('alice', 'data5', 'read')
        self.assertTrue(e.enforce('alice', 'data5', 'read'))
        e.delete_permission_for_user('alice', 'data5', 'read')
        self.assertFalse(e.enforce('alice', 'data5', 'read'))

    def test_remove_policies(self):
        e = get_enforcer()

        self.assertFalse(e.enforce('alice', 'data5', 'read'))
        self.assertFalse(e.enforce('alice', 'data6', 'read'))
        e.add_policies((('alice', 'data5', 'read'), ('alice', 'data6', 'read')))
        self.assertTrue(e.enforce('alice', 'data5', 'read'))
        self.assertTrue(e.enforce('alice', 'data6', 'read'))
        e.remove_policies((('alice', 'data5', 'read'), ('alice', 'data6', 'read')))
        self.assertFalse(e.enforce('alice', 'data5', 'read'))
        self.assertFalse(e.enforce('alice', 'data6', 'read'))

    def test_remove_filtered_policy(self):
        e = get_enforcer()

        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        e.remove_filtered_policy(1, 'data1')
        self.assertFalse(e.enforce('alice', 'data1', 'read'))

        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

        e.remove_filtered_policy(1, 'data2', 'read')

        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertTrue(e.enforce('alice', 'data2', 'write'))

        e.remove_filtered_policy(2, 'write')

        self.assertFalse(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))

        # e.add_permission_for_user('alice', 'data6', 'delete')
        # e.add_permission_for_user('bob', 'data6', 'delete')
        # e.add_permission_for_user('eve', 'data6', 'delete')
        # self.assertTrue(e.enforce('alice', 'data6', 'delete'))
        # self.assertTrue(e.enforce('bob', 'data6', 'delete'))
        # self.assertTrue(e.enforce('eve', 'data6', 'delete'))
        # e.remove_filtered_policy(0, 'alice', None, 'delete')
        # self.assertFalse(e.enforce('alice', 'data6', 'delete'))
        # e.remove_filtered_policy(0, None, None, 'delete')
        # self.assertFalse(e.enforce('bob', 'data6', 'delete'))
        # self.assertFalse(e.enforce('eve', 'data6', 'delete'))

    def test_str(self):
        rule = CasbinRule(ptype='p', v0='alice', v1='data1', v2='read')
        self.assertEqual(str(rule), 'p, alice, data1, read')
        rule = CasbinRule(ptype='p', v0='bob', v1='data2', v2='write')
        self.assertEqual(str(rule), 'p, bob, data2, write')
        rule = CasbinRule(ptype='p', v0='data2_admin', v1='data2', v2='read')
        self.assertEqual(str(rule), 'p, data2_admin, data2, read')
        rule = CasbinRule(ptype='p', v0='data2_admin', v1='data2', v2='write')
        self.assertEqual(str(rule), 'p, data2_admin, data2, write')
        rule = CasbinRule(ptype='g', v0='alice', v1='data2_admin')
        self.assertEqual(str(rule), 'g, alice, data2_admin')

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

    def test_filtered_policy(self):
        e = get_enforcer()
        filter = Filter()

        filter.ptype = ['p']
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))

        filter.ptype = []
        filter.v0 = ['alice']
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        filter.v0 = ['bob']
        e.load_filtered_policy(filter)
        self.assertFalse(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        filter.v0 = ['data2_admin']
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce('data2_admin', 'data2', 'read'))
        self.assertTrue(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))

        filter.v0 = ['alice', 'bob']
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        filter.v0 = []
        filter.v1 = ['data1']
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        filter.v1 = ['data2']
        e.load_filtered_policy(filter)
        self.assertFalse(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('data2_admin', 'data2', 'read'))
        self.assertTrue(e.enforce('data2_admin', 'data2', 'write'))

        filter.v1 = []
        filter.v2 = ['read']
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertFalse(e.enforce('bob', 'data2', 'write'))
        self.assertTrue(e.enforce('data2_admin', 'data2', 'read'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'write'))

        filter.v2 = ['write']
        e.load_filtered_policy(filter)
        self.assertFalse(e.enforce('alice', 'data1', 'read'))
        self.assertFalse(e.enforce('alice', 'data1', 'write'))
        self.assertFalse(e.enforce('alice', 'data2', 'read'))
        self.assertFalse(e.enforce('alice', 'data2', 'write'))
        self.assertFalse(e.enforce('bob', 'data1', 'read'))
        self.assertFalse(e.enforce('bob', 'data1', 'write'))
        self.assertFalse(e.enforce('bob', 'data2', 'read'))
        self.assertTrue(e.enforce('bob', 'data2', 'write'))
        self.assertFalse(e.enforce('data2_admin', 'data2', 'read'))
        self.assertTrue(e.enforce('data2_admin', 'data2', 'write'))
