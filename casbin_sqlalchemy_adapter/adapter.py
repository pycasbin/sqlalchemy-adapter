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


class CoreAdapter(persist.Adapter, persist.adapters.UpdateAdapter):
    """the interface for Casbin adapters."""

    def __init__(self, engine, db_class=None, filtered=False):
        if isinstance(engine, str):
            self._engine = create_engine(engine)
        else:
            self._engine = engine

        if db_class is None:
            db_class = CasbinRule
        else:
            for attr in (
                "id",
                "ptype",
                "v0",
                "v1",
                "v2",
                "v3",
                "v4",
                "v5",
            ):  # id attr was used by filter
                if not hasattr(db_class, attr):
                    raise Exception(f"{attr} not found in custom DatabaseClass.")
            Base.metadata = db_class.metadata

        self._db_class = db_class
        Base.metadata.create_all(self._engine)
        self._filtered = filtered
        self.session = None

    def set_session(self, session):
        self.session = session

    def _commit(self):
        self.session.commit()

    def _close(self):
        self.session.close()

    def load_policy(self, model):
        """loads all policy rules from the storage."""
        lines = self.session.query(self._db_class).all()
        for line in lines:
            persist.load_policy_line(str(line), model)
        self._close()

    def is_filtered(self):
        return self._filtered

    def load_filtered_policy(self, model, filter) -> None:
        """loads all policy rules from the storage."""
        query = self.session.query(self._db_class)
        filters = self.filter_query(query, filter)
        filters = filters.all()

        for line in filters:
            persist.load_policy_line(str(line), model)
        self._filtered = True
        self._close()

    def filter_query(self, querydb, filter):
        for attr in ("ptype", "v0", "v1", "v2", "v3", "v4", "v5"):
            if len(getattr(filter, attr)) > 0:
                querydb = querydb.filter(
                    getattr(self._db_class, attr).in_(getattr(filter, attr))
                )
        return querydb.order_by(self._db_class.id)

    def _save_policy_line(self, ptype, rule):
        line = self._db_class(ptype=ptype)
        for i, v in enumerate(rule):
            setattr(line, "v{}".format(i), v)
        self.session.add(line)
        # commit in save_policy

    def save_policy(self, model):
        """saves all policy rules to the storage."""
        query = self.session.query(self._db_class)
        query.delete()
        for sec in ["p", "g"]:
            if sec not in model.model.keys():
                continue
            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    self._save_policy_line(ptype, rule)

        self._commit()

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        self._save_policy_line(ptype, rule)
        self._commit()

    def add_policies(self, sec, ptype, rules):
        """adds a policy rules to the storage."""
        for rule in rules:
            self._save_policy_line(ptype, rule)
        self._commit()

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        query = self.session.query(self._db_class)
        query = query.filter(self._db_class.ptype == ptype)
        for i, v in enumerate(rule):
            query = query.filter(getattr(self._db_class, "v{}".format(i)) == v)
        query.delete()

        self._commit()

    def remove_policies(self, sec, ptype, rules):
        """remove policy rules from the storage."""
        if not rules:
            return
        query = self.session.query(self._db_class)
        query = query.filter(self._db_class.ptype == ptype)
        rules = zip(*rules)
        for i, rule in enumerate(rules):
            query = query.filter(
                or_(getattr(self._db_class, "v{}".format(i)) == v for v in rule)
            )
        query.delete()
        self._commit()

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        query = self.session.query(self._db_class).filter(self._db_class.ptype == ptype)

        if not (0 <= field_index <= 5):
            return False
        if not (1 <= field_index + len(field_values) <= 6):
            return False
        for i, v in enumerate(field_values):
            if v != "":
                v_value = getattr(self._db_class, "v{}".format(field_index + i))
                query = query.filter(v_value == v)
        query.delete()
        self._commit()

    def update_policy(
        self, sec: str, ptype: str, old_rule: [str], new_rule: [str]
    ) -> None:
        """
        Update the old_rule with the new_rule in the database (storage).

        :param sec: section type
        :param ptype: policy type
        :param old_rule: the old rule that needs to be modified
        :param new_rule: the new rule to replace the old rule

        :return: None
        """

        query = self.session.query(self._db_class).filter(self._db_class.ptype == ptype)

        # locate the old rule
        for index, value in enumerate(old_rule):
            v_value = getattr(self._db_class, "v{}".format(index))
            query = query.filter(v_value == value)

        # need the length of the longest_rule to perform overwrite
        longest_rule = old_rule if len(old_rule) > len(new_rule) else new_rule
        old_rule_line = query.one()

        # overwrite the old rule with the new rule
        for index in range(len(longest_rule)):
            if index < len(new_rule):
                exec(f"old_rule_line.v{index} = new_rule[{index}]")
            else:
                exec(f"old_rule_line.v{index} = None")

        self._commit()
        return old_rule_line

    def update_policies(
        self,
        sec: str,
        ptype: str,
        old_rules: [
            [str],
        ],
        new_rules: [
            [str],
        ],
    ) -> None:
        """
        Update the old_rules with the new_rules in the database (storage).

        :param sec: section type
        :param ptype: policy type
        :param old_rules: the old rules that need to be modified
        :param new_rules: the new rules to replace the old rules

        :return: None
        """
        for i in range(len(old_rules)):
            self.update_policy(sec, ptype, old_rules[i], new_rules[i])

        self._commit()

    def update_filtered_policies(
        self, sec, ptype, new_rules: [[str]], field_index, *field_values
    ) -> [[str]]:
        """update_filtered_policies updates all the policies on the basis of the filter."""

        filter = Filter()
        filter.ptype = ptype

        # Creating Filter from the field_index & field_values provided
        for i in range(len(field_values)):
            if field_index <= i < field_index + len(field_values):
                setattr(filter, f"v{i}", field_values[i - field_index])
            else:
                break

        self._update_filtered_policies(new_rules, filter)
        self._commit()

    def _update_filtered_policies(self, new_rules, filter) -> [[str]]:
        """_update_filtered_policies updates all the policies on the basis of the filter."""

        # Load old policies
        query = self.session.query(self._db_class).filter(
            self._db_class.ptype == filter.ptype
        )
        filtered_query = self.filter_query(query, filter)
        old_rules = filtered_query.all()
        self.remove_policies("p", filter.ptype, old_rules)
        self.add_policies("p", filter.ptype, new_rules)
        self._commit()
        return old_rules


class Adapter(CoreAdapter):
    """the interface for Casbin adapters."""

    @staticmethod
    def refresh_session_decorator(func, refresh_session):
        def wrapper(*args):
            refresh_session()
            return func(*args)

        return wrapper

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.load_policy = self.refresh_session_decorator(
            self.load_policy, self.refresh_session
        )
        self.load_filtered_policy = self.refresh_session_decorator(
            self.load_filtered_policy, self.refresh_session
        )
        self.filter_query = self.refresh_session_decorator(
            self.filter_query, self.refresh_session
        )
        self.save_policy = self.refresh_session_decorator(
            self.save_policy, self.refresh_session
        )
        self.add_policy = self.refresh_session_decorator(
            self.add_policy, self.refresh_session
        )
        self.add_policies = self.refresh_session_decorator(
            self.add_policies, self.refresh_session
        )
        self.remove_policy = self.refresh_session_decorator(
            self.remove_policy, self.refresh_session
        )
        self.remove_policies = self.refresh_session_decorator(
            self.remove_policies, self.refresh_session
        )
        self.remove_filtered_policy = self.refresh_session_decorator(
            self.remove_filtered_policy, self.refresh_session
        )
        self.update_policy = self.refresh_session_decorator(
            self.update_policy, self.refresh_session
        )
        self.update_policies = self.refresh_session_decorator(
            self.update_policies, self.refresh_session
        )
        self.update_filtered_policies = self.refresh_session_decorator(
            self.update_filtered_policies, self.refresh_session
        )

    def refresh_session(self):
        if self.session:
            self.session.expire_all()
        self.session = sessionmaker(bind=self._engine)()
