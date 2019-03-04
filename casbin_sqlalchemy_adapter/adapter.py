from casbin import persist
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String
from sqlalchemy import create_engine
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


class Adapter(persist.Adapter):
    """the interface for Casbin adapters."""

    def __init__(self, dsn):
        self._engine = create_engine(dsn)
        session = sessionmaker(bind=self._engine)
        self._session = session()

        Base.metadata.create_all(self._engine)

    def load_policy(self, model):
        """loads all policy rules from the storage."""
        lines = self._session.query(CasbinRule).all()
        for line in lines:
            text = line.ptype

            if line.v0:
                text = text + ', ' + line.v0
            if line.v1:
                text = text + ', ' + line.v1
            if line.v2:
                text = text + ', ' + line.v2
            if line.v3:
                text = text + ', ' + line.v3
            if line.v4:
                text = text + ', ' + line.v4
            if line.v5:
                text = text + ', ' + line.v5

            persist.load_policy_line(text, model)

    def _save_policy_line(self, ptype, rule):
        line = CasbinRule(ptype=ptype)
        if len(rule) > 0:
            line.v0 = rule[0]
        if len(rule) > 1:
            line.v0 = rule[1]
        if len(rule) > 2:
            line.v0 = rule[2]
        if len(rule) > 3:
            line.v0 = rule[3]
        if len(rule) > 4:
            line.v0 = rule[4]
        if len(rule) > 5:
            line.v0 = rule[5]
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
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        pass

    def __del__(self):
        self._session.close()
