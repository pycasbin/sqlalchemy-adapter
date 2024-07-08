from contextlib import contextmanager

import sqlalchemy
from casbin import persist
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy import create_engine, or_, not_
from sqlalchemy.orm import sessionmaker

# declarative base class
if sqlalchemy.__version__.startswith("1."):
    from sqlalchemy.orm import declarative_base

    Base = declarative_base()

else:
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):
        pass


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


class Adapter(persist.Adapter, persist.adapters.UpdateAdapter):
    """the interface for Casbin adapters."""

    def __init__(
        self,
        engine,
        db_class=None,
        db_class_softdelete_attribute=None,
        filtered=False,
        create_all_models=True,
    ):
        if isinstance(engine, str):
            self._engine = create_engine(engine)
        else:
            self._engine = engine

        self.softdelete_attribute = None

        if db_class is None:
            db_class = CasbinRule
        else:
            if db_class_softdelete_attribute is not None and not isinstance(
                db_class_softdelete_attribute.type, Boolean
            ):
                msg = f"The type of db_class_softdelete_attribute needs to be {str(Boolean)!r}. "
                msg += f"An attribute of type {str(type(db_class_softdelete_attribute.type))!r} was given."
                raise ValueError(msg)
            # Softdelete is only supported when using custom class
            self.softdelete_attribute = db_class_softdelete_attribute

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
        self.session_local = sessionmaker(bind=self._engine)

        if create_all_models:
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
            query = session.query(self._db_class)
            query = self._softdelete_query(query)
            lines = query.all()
            for line in lines:
                persist.load_policy_line(str(line), model)

    def is_filtered(self):
        return self._filtered

    def load_filtered_policy(self, model, filter) -> None:
        """loads all policy rules from the storage."""
        with self._session_scope() as session:
            query = session.query(self._db_class)
            query = self._softdelete_query(query)
            filters = self.filter_query(query, filter)
            filters = filters.all()

            for line in filters:
                persist.load_policy_line(str(line), model)
            self._filtered = True

    def filter_query(self, querydb, filter):
        for attr in ("ptype", "v0", "v1", "v2", "v3", "v4", "v5"):
            if len(getattr(filter, attr)) > 0:
                querydb = querydb.filter(
                    getattr(self._db_class, attr).in_(getattr(filter, attr))
                )
        return querydb.order_by(self._db_class.id)

    def _save_policy_line(self, ptype, rule, session=None):
        line = self._db_class(ptype=ptype)
        for i, v in enumerate(rule):
            setattr(line, "v{}".format(i), v)
        if session:
            session.add(line)
        else:
            with self._session_scope() as session:
                session.add(line)

    def save_policy(self, model):
        """saves all policy rules to the storage."""

        # Use the default strategy when soft delete is not enabled
        if self.softdelete_attribute is None:
            with self._session_scope() as session:
                query = session.query(self._db_class)
                query.delete()
                for sec in ["p", "g"]:
                    if sec not in model.model.keys():
                        continue
                    for ptype, ast in model.model[sec].items():
                        for rule in ast.policy:
                            self._save_policy_line(ptype, rule, session=session)
            return True

        # Custom stategy for softdelete since it does not make sense to recreate all of the
        # entries when using soft delete
        with self._session_scope() as session:
            query = session.query(self._db_class)
            query = self._softdelete_query(query)

            # Delete entries that are not part of the model anymore
            lines_before_changes = query.all()

            # Create new entries in the database
            for sec in ["p", "g"]:
                if sec not in model.model.keys():
                    continue
                for ptype, ast in model.model[sec].items():
                    for rule in ast.policy:
                        # Filter for rule in the database
                        filter_query = query.filter(self._db_class.ptype == ptype)
                        for index, value in enumerate(rule):
                            v_value = getattr(self._db_class, "v{}".format(index))
                            filter_query = filter_query.filter(v_value == value)
                        # If the rule is not present, create an entry in the database
                        if filter_query.count() == 0:
                            self._save_policy_line(ptype, rule, session=session)

            for line in lines_before_changes:
                ptype = line.ptype
                sec = ptype[0]  # derived from persist.load_policy_line function
                fields_with_None = [
                    line.v0,
                    line.v1,
                    line.v2,
                    line.v3,
                    line.v4,
                    line.v5,
                ]
                rule = [element for element in fields_with_None if element is not None]
                # If the the rule is not part of the model, set the deletion flag to True
                if not model.has_policy(sec, ptype, rule):
                    setattr(line, self.softdelete_attribute.name, True)

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
            query = self._softdelete_query(query)
            query = query.filter(self._db_class.ptype == ptype)
            for i, v in enumerate(rule):
                query = query.filter(getattr(self._db_class, "v{}".format(i)) == v)

            if self.softdelete_attribute is None:
                r = query.delete()
            else:
                r = query.update({self.softdelete_attribute: True})

        return True if r > 0 else False

    def remove_policies(self, sec, ptype, rules):
        """remove policy rules from the storage."""
        if not rules:
            return
        with self._session_scope() as session:
            query = session.query(self._db_class)
            query = self._softdelete_query(query)
            query = query.filter(self._db_class.ptype == ptype)
            rules = zip(*rules)
            for i, rule in enumerate(rules):
                query = query.filter(
                    or_(getattr(self._db_class, "v{}".format(i)) == v for v in rule)
                )

            if self.softdelete_attribute is None:
                query.delete()
            else:
                query.update({self.softdelete_attribute: True})

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        with self._session_scope() as session:
            query = session.query(self._db_class)
            query = self._softdelete_query(query)
            query = query.filter(self._db_class.ptype == ptype)

            if not (0 <= field_index <= 5):
                return False
            if not (1 <= field_index + len(field_values) <= 6):
                return False
            for i, v in enumerate(field_values):
                if v != "":
                    v_value = getattr(self._db_class, "v{}".format(field_index + i))
                    query = query.filter(v_value == v)

            if self.softdelete_attribute is None:
                r = query.delete()
            else:
                r = query.update({self.softdelete_attribute: True})

        return True if r > 0 else False

    def update_policy(
        self, sec: str, ptype: str, old_rule: list[str], new_rule: list[str]
    ) -> None:
        """
        Update the old_rule with the new_rule in the database (storage).

        :param sec: section type
        :param ptype: policy type
        :param old_rule: the old rule that needs to be modified
        :param new_rule: the new rule to replace the old rule

        :return: None
        """

        with self._session_scope() as session:
            query = session.query(self._db_class)
            query = self._softdelete_query(query)
            query = query.filter(self._db_class.ptype == ptype)

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

    def update_policies(
        self,
        sec: str,
        ptype: str,
        old_rules: list[list[str]],
        new_rules: list[list[str]],
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

    def update_filtered_policies(
        self, sec, ptype, new_rules: list[list[str]], field_index, *field_values
    ) -> list[list[str]]:
        """update_filtered_policies updates all the policies on the basis of the filter."""

        filter = Filter()
        filter.ptype = ptype

        # Creating Filter from the field_index & field_values provided
        for i in range(len(field_values)):
            if field_index <= i and i < field_index + len(field_values):
                setattr(filter, f"v{i}", field_values[i - field_index])
            else:
                break

        self._update_filtered_policies(new_rules, filter)

    def _update_filtered_policies(self, new_rules, filter) -> list[list[str]]:
        """_update_filtered_policies updates all the policies on the basis of the filter."""

        with self._session_scope() as session:
            # Load old policies

            query = session.query(self._db_class)
            query = self._softdelete_query(query)
            query = query.filter(self._db_class.ptype == filter.ptype)
            filtered_query = self.filter_query(query, filter)
            old_rules = filtered_query.all()

            # Delete old policies

            self.remove_policies("p", filter.ptype, old_rules)

            # Insert new policies

            self.add_policies("p", filter.ptype, new_rules)

            # return deleted rules

            return old_rules

    def _softdelete_query(self, query):
        query_softdelete = query
        if self.softdelete_attribute is not None:
            query_softdelete = query_softdelete.where(not_(self.softdelete_attribute))
        return query_softdelete
