from contextlib import contextmanager

from casbin import persist
from sqlalchemy import Column, Integer, String
from sqlalchemy import create_engine, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class CasbinRule(Base):
    __tablename__ = "casbin_rule"

    id = Column(Integer, primary_key=True)
    ptype = Column(String(255))
    v0 = Column(String(255))
    v1 = Column(String(255))
    v2 = Column(String(255))
    v3 = Column(String(255))
    v4 = Column(String(255))
    v5 = Column(String(255))

    def __str__(self):
        arr = [self.ptype]
        for v in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
            if v is None:
                break
            arr.append(v)
        return ", ".join(arr)

    def __repr__(self):
        return '<CasbinRule {}: "{}">'.format(self.id, str(self))


class Filter:
    ptype = []
    v0 = []
    v1 = []
    v2 = []
    v3 = []
    v4 = []
    v5 = []


class Adapter(persist.Adapter):
    """the interface for Casbin adapters."""

    def __init__(self, engine, db_class=None, filtered=False):
        if isinstance(engine, str):
            self._engine = create_engine(engine)
        else:
            self._engine = engine

        if db_class is None:
            db_class = CasbinRule
        self._db_class = db_class
        self.session_local = sessionmaker(bind=self._engine)

        Base.metadata.create_all(self._engine)
        self._filtered = filtered

    @contextmanager
    def _session_scope(self):
        """Provide a transactional scope around a series of operations."""
        session = self.session_local()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def load_policy(self, model):
        """loads all policy rules from the storage."""
        with self._session_scope() as session:
            lines = session.query(self._db_class).all()
            for line in lines:
                persist.load_policy_line(str(line), model)

    def is_filtered(self):
        return self._filtered

    def load_filtered_policy(self, model, filter) -> None:
        """loads all policy rules from the storage."""
        with self._session_scope() as session:
            query = session.query(self._db_class)
            filters = self.filter_query(query, filter)
            filters = filters.all()

            for line in filters:
                persist.load_policy_line(str(line), model)
            self._filtered = True

    def filter_query(self, querydb, filter):
        if len(filter.ptype) > 0:
            querydb = querydb.filter(CasbinRule.ptype.in_(filter.ptype))
        if len(filter.v0) > 0:
            querydb = querydb.filter(CasbinRule.v0.in_(filter.v0))
        if len(filter.v1) > 0:
            querydb = querydb.filter(CasbinRule.v1.in_(filter.v1))
        if len(filter.v2) > 0:
            querydb = querydb.filter(CasbinRule.v2.in_(filter.v2))
        if len(filter.v3) > 0:
            querydb = querydb.filter(CasbinRule.v3.in_(filter.v3))
        if len(filter.v4) > 0:
            querydb = querydb.filter(CasbinRule.v4.in_(filter.v4))
        if len(filter.v5) > 0:
            querydb = querydb.filter(CasbinRule.v5.in_(filter.v5))
        return querydb.order_by(CasbinRule.id)

    def _save_policy_line(self, ptype, rule):
        with self._session_scope() as session:
            line = self._db_class(ptype=ptype)
            for i, v in enumerate(rule):
                setattr(line, "v{}".format(i), v)
            session.add(line)

    def save_policy(self, model):
        """saves all policy rules to the storage."""
        with self._session_scope() as session:
            query = session.query(self._db_class)
            query.delete()
            for sec in ["p", "g"]:
                if sec not in model.model.keys():
                    continue
                for ptype, ast in model.model[sec].items():
                    for rule in ast.policy:
                        self._save_policy_line(ptype, rule)
        return True

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        self._save_policy_line(ptype, rule)

    def add_policies(self, sec, ptype, rules):
        """adds a policy rules to the storage."""
        for rule in rules:
            self._save_policy_line(ptype, rule)

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        with self._session_scope() as session:
            query = session.query(self._db_class)
            query = query.filter(self._db_class.ptype == ptype)
            for i, v in enumerate(rule):
                query = query.filter(getattr(self._db_class, "v{}".format(i)) == v)
            r = query.delete()

        return True if r > 0 else False

    def remove_policies(self, sec, ptype, rules):
        """removes a policy rules from the storage."""
        if not rules:
            return
        with self._session_scope() as session:
            query = session.query(self._db_class)
            query = query.filter(self._db_class.ptype == ptype)
            rules = zip(*rules)
            for i, rule in enumerate(rules):
                query = query.filter(or_(getattr(self._db_class, "v{}".format(i)) == v for v in rule))
            query.delete()

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        with self._session_scope() as session:
            query = session.query(self._db_class)
            query = query.filter(self._db_class.ptype == ptype)
            if not (0 <= field_index <= 5):
                return False
            if not (1 <= field_index + len(field_values) <= 6):
                return False
            for i, v in enumerate(field_values):
                if v != '':
                    query = query.filter(getattr(self._db_class, "v{}".format(field_index + i)) == v)
            r = query.delete()

        return True if r > 0 else False
