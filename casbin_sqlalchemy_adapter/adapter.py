from casbin import persist
from sqlalchemy import Column, Integer, String
from sqlalchemy import create_engine, and_, or_
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
    def __init__(self, v0=None, v1=None, v2=None, v3=None, v4=None, v5=None):
        self.v0 = v0
        self.v1 = v1
        self.v2 = v2
        self.v3 = v3
        self.v4 = v4
        self.v5 = v5


class PolicyFilter:
    def __init__(self, p=None, g=None):
        self.P = p or ()
        self.G = g or ()


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
        session = sessionmaker(bind=self._engine)
        self._session = session()

        Base.metadata.create_all(self._engine)
        self._filtered = filtered

    def is_filtered(self):
        return self._filtered

    def load_filtered_policy(self, model, filter) -> None:
        """loads all policy rules from the storage."""
        self._commit()  # Commit transaction, so you can see the insert/update/delete from other transaction when use multi processes(eg. Nginx reverse proxy)
        self._filtered = True
        query = self._session.query(self._db_class)
        filters = []
        for p in filter.P:
            filters.append(and_(self._db_class.ptype == "p", *self.__build_rule_filter(p)))
        for g in filter.G:
            filters.append(and_(self._db_class.ptype == "g", *self.__build_rule_filter(g)))

        query = query.filter(or_(*filters))

        for line in query.all():
            persist.load_policy_line(str(line), model)
        self._commit()

    def __build_rule_filter(self, filter):
        rules = []
        if filter.v0:
            rules.append(self._db_class.v0 == filter.v0)
        if filter.v1:
            rules.append(self._db_class.v1 == filter.v1)
        if filter.v2:
            rules.append(self._db_class.v2 == filter.v2)
        if filter.v3:
            rules.append(self._db_class.v3 == filter.v3)
        if filter.v4:
            rules.append(self._db_class.v4 == filter.v4)
        if filter.v5:
            rules.append(self._db_class.v5 == filter.v5)

        return rules

    def load_policy(self, model):
        """loads all policy rules from the storage."""
        self._commit()  # Commit transaction, so you can see the insert/update/delete from other transaction when use multi processes(eg. Nginx reverse proxy)
        lines = self._session.query(self._db_class).all()
        for line in lines:
            persist.load_policy_line(str(line), model)
        self._commit()

    def _save_policy_line(self, ptype, rule):
        line = self._db_class(ptype=ptype)
        for i, v in enumerate(rule):
            setattr(line, "v{}".format(i), v)
        self._session.add(line)

    def _commit(self):
        self._session.commit()

    def save_policy(self, model):
        """saves all policy rules to the storage."""
        query = self._session.query(self._db_class)
        query.delete()
        for sec in ["p", "g"]:
            if sec not in model.model.keys():
                continue
            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    self._save_policy_line(ptype, rule)
        self._commit()
        return True

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        self._save_policy_line(ptype, rule)
        self._commit()

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        query = self._session.query(self._db_class)
        query = query.filter(self._db_class.ptype == ptype)
        for i, v in enumerate(rule):
            query = query.filter(getattr(self._db_class, "v{}".format(i)) == v)
        r = query.delete()
        self._commit()

        return True if r > 0 else False

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        query = self._session.query(self._db_class)
        query = query.filter(self._db_class.ptype == ptype)
        if not (0 <= field_index <= 5):
            return False
        if not (1 <= field_index + len(field_values) <= 6):
            return False
        for i, v in enumerate(field_values):
            query = query.filter(getattr(self._db_class, "v{}".format(field_index + i)) == v)
        r = query.delete()
        self._commit()

        return True if r > 0 else False

    def __del__(self):
        self._session.close()
