from setuptools import setup, find_packages

setup(
    name='kxicli',
    version='0.4.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click>=7.0',
        'requests>=2.26.0',
        'tabulate>=0.8.9',
        'kubernetes>=18.20.0',
        'pyyaml>=6.0',
        'cryptography>=2.8'
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'kxi=kxicli.main:cli',
        ],
    },
)
