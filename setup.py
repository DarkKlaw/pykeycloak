import os
import sys

from setuptools import  find_packages, setup

VERSION = '0.0.2'
EXCLUDED_PACKAGES = []


setup(
    name='pykeycloak',
    version=VERSION,
    description='A Simple wrapper for python-keycloak-client',
    url='https://github.com/cccs-is/pykeycloak',
    author='IS',
    author_email='',
    license='MIT',
    package_dir={'': 'src'},
    packages=find_packages('src', EXCLUDED_PACKAGES),
    install_requires=['python-keycloak-client>=0.2.2',
                      ],

    classifiers=[
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',  
        'Operating System :: POSIX :: Linux',        
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
