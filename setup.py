from setuptools import setup, find_packages

setup(
    name="cmx-standalone-app",
    version="0.1.0",
    packages=find_packages(where="."),
    package_dir={"": "."},
)