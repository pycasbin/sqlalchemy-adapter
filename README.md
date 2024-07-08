SQLAlchemy Adapter for PyCasbin 
====

[![GitHub Actions](https://github.com/pycasbin/sqlalchemy-adapter/workflows/build/badge.svg?branch=master)](https://github.com/pycasbin/sqlalchemy-adapter/actions)
[![Coverage Status](https://coveralls.io/repos/github/pycasbin/sqlalchemy-adapter/badge.svg)](https://coveralls.io/github/pycasbin/sqlalchemy-adapter)
[![Version](https://img.shields.io/pypi/v/casbin_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_sqlalchemy_adapter/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/casbin_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_sqlalchemy_adapter/)
[![Pyversions](https://img.shields.io/pypi/pyversions/casbin_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_sqlalchemy_adapter/)
[![Download](https://img.shields.io/pypi/dm/casbin_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_sqlalchemy_adapter/)
[![License](https://img.shields.io/pypi/l/casbin_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_sqlalchemy_adapter/)

SQLAlchemy Adapter is the [SQLAlchemy](https://www.sqlalchemy.org) adapter for [PyCasbin](https://github.com/casbin/pycasbin). With this library, Casbin can load policy from SQLAlchemy supported database or save policy to it.

Based on [Officially Supported Databases](http://www.sqlalchemy.org/), The current supported databases are:

- PostgreSQL
- MySQL
- SQLite
- Oracle
- Microsoft SQL Server
- Firebird
- Sybase

## Installation

```
pip install casbin_sqlalchemy_adapter
```

## Simple Example

```python
import casbin_sqlalchemy_adapter
import casbin

adapter = casbin_sqlalchemy_adapter.Adapter('sqlite:///test.db')

e = casbin.Enforcer('path/to/model.conf', adapter)

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1
    pass
else:
    # deny the request, show an error
    pass
```

## Soft Delete example

Soft Delete for casbin rules is supported, only when using a custom casbin rule model.
The Soft Delete mechanism is enabled by passing the attribute of the flag indicating whether
a rule is deleted to `db_class_softdelete_attribute`.
That attribute needs to be of type `sqlalchemy.Boolean`.

```python
adapter = Adapter(
    engine,
    db_class=MyCustomCasbinRuleModel,
    db_class_softdelete_attribute=MyCustomCasbinRuleModel.is_deleted,
)
```

Please be aware that this adapter only sets a flag like `is_deleted` to `True`.
The provided model needs to handle the update of fields like `deleted_by`, `deleted_at`, etc.
An example for this is given in [examples/softdelete.py](examples/softdelete.py).

### Getting Help

- [PyCasbin](https://github.com/casbin/pycasbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).
