from setuptools import setup, find_packages
setup(
    name="linkapp.authentication",
    version="0.1",
    packages=["linkapp.authentication"],
    install_requires=['redis', 'pika', 'strict_rfc3339', 'passlib', 'jsonschema', 'webob']
)