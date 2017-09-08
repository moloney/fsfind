import sys
from setuptools import setup

if sys.version_info < (3,):
    install_requires = ['scandir']

setup(name='fsfind',
      version='0.1dev',
      description='Find files and directories',
      author='Brendan Moloney',
      author_email='moloney@ohsu.edu',
      install_requires=install_requires,
      extras_require = {'test': ["nose"]},
      py_modules=['fsfind'],
      test_suite = 'nose.collector'
     )
