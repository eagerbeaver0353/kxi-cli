from setuptools import setup

setup(
    name='kxi',
    version='0.1',
    py_modules=['kxi'],
    install_requires=[
        'click',
        'requests',
        'tabulate',
        'kubernetes'
    ],
    entry_points='''
        [console_scripts]
        kxi=kxi:cli
    ''',
)
