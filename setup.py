from setuptools import setup, find_packages

setup(
    name='kxicli',
    version='1.1.0-rc.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=7.0",
        "requests>=2.26.0",
        "tabulate>=0.8.9",
        "kubernetes>=18.20.0",
        "pyyaml>=6.0",
        "cryptography>=2.8",
        "pakxcli==1.0.0rc1",
        "packaging>=21.3"
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "kxi=kxicli.main:cli",
        ],
    },
)
