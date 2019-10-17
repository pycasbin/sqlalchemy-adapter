from casbin import persist
from sqlalchemy import Column, Integer, String
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class CasbinRule(Base):
    __tablename__ = 'casbin_rule'

    id = Column(Integer, primary_key=True)
    ptype = Column(String(255))
    v0 = Column(String(255))
    v1 = Column(String(255))
    v2 = Column(String(255))
    v3 = Column(String(255))
    v4 = Column(String(255))
    v5 = Column(String(255))

    def __str__(self):
        text = self.ptype

        if self.v0:
            text = text + ', ' + self.v0
        if self.v1:
            text = text + ', ' + self.v1
        if self.v2:
            text = text + ', ' + self.v2
        if self.v3:
            text = text + ', ' + self.v3
        if self.v4:
            text = text + ', ' + self.v4
        if self.v5:
            text = text + ', ' + self.v5
        return text

    def __repr__(self):
        return '<CasbinRule {}: "{}">'.format(self.id, str(self))


class Adapter(persist.Adapter):
    """the interface for Casbin adapters."""

    def __init__(self, engine):
        if isinstance(engine, str):
            self._engine = create_engine(engine)
        else:
            self._engine = engine

        session = sessionmaker(bind=self._engine)
        self._session = session()

        Base.metadata.create_all(self._engine)

    def load_policy(self, model):
        """loads all policy rules from the storage."""
        lines = self._session.query(CasbinRule).all()
        for line in lines:
            persist.load_policy_line(str(line), model)

    def _save_policy_line(self, ptype, rule):
        line = CasbinRule(ptype=ptype)
        if len(rule) > 0:
            line.v0 = rule[0]
        if len(rule) > 1:
            line.v1 = rule[1]
        if len(rule) > 2:
            line.v2 = rule[2]
        if len(rule) > 3:
            line.v3 = rule[3]
        if len(rule) > 4:
            line.v4 = rule[4]
        if len(rule) > 5:
            line.v5 = rule[5]
        self._session.add(line)
        self._session.commit()

    def save_policy(self, model):
        """saves all policy rules to the storage."""
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

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        query = self._session.query(CasbinRule)
        query = query.filter(CasbinRule.ptype == ptype)
        if len(rule) > 0:
            query = query.filter(CasbinRule.v0 == rule[0])
        if len(rule) > 1:
            query = query.filter(CasbinRule.v1 == rule[1])
        if len(rule) > 2:
            query = query.filter(CasbinRule.v2 == rule[2])
        if len(rule) > 3:
            query = query.filter(CasbinRule.v3 == rule[3])
        if len(rule) > 4:
            query = query.filter(CasbinRule.v4 == rule[4])
        if len(rule) > 5:
            query = query.filter(CasbinRule.v5 == rule[5])

        r = query.delete()
        self._session.commit()

        return True if r > 0 else False

    def remove_filtered_policy1(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        query = self._session.query(CasbinRule)
        query = query.filter(CasbinRule.ptype == ptype)
        if field_index < 0:
            return False
        for i in range(field_index, len(field_values)):
            query = query.filter(CasbinRule.get('v' + str(i)) == field_values[0])

        r = query.delete()
        self._session.commit()

        return True if r > 0 else False

    def __del__(self):
        self._session.close()
