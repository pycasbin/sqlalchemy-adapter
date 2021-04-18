import setuptools

desc_file = "README.md"

with open(desc_file, "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="casbin_sqlalchemy_adapter",
    version="0.3.0",
    author="TechLee",
    author_email="techlee@qq.com",
    description="SQLAlchemy Adapter for PyCasbin",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pycasbin/sqlalchemy-adapter",
    keywords=["casbin", "SQLAlchemy", "casbin-adapter", "rbac", "access control", "abac", "acl", "permission"],
    packages=setuptools.find_packages(),
    install_requires=['casbin>=0.8.1', 'SQLAlchemy>=1.2.18'],
    python_requires=">=3.3",
    license="Apache 2.0",
    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    data_files=[desc_file],
)
