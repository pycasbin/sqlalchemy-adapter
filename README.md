SQLAlchemy Adapter for PyCasbin 
====

[![Build Status](https://www.travis-ci.com/pycasbin/sqlalchemy-adapter.svg?branch=master)](https://www.travis-ci.com/pycasbin/sqlalchemy-adapter)
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

e = casbin.Enforcer('path/to/model.conf', adapter, True)

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1casbin_sqlalchemy_adapter
    pass
else:
    # deny the request, show an error
    pass
```


### Getting Help

- [PyCasbin](https://github.com/casbin/pycasbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).
