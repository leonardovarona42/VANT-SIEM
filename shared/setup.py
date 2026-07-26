from setuptools import setup, find_packages

setup(
    name="vant_common",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        "PyJWT>=2.10.0",
        "redis>=5.2.0",
        "requests>=2.32.0",
        "gunicorn>=23.0.0",
        "Django>=5.2,<7.0",
        "djangorestframework>=3.16.0",
        "psycopg2-binary>=2.9.10",
    ],
)
