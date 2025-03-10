from setuptools import  find_packages, setup

VERSION = '0.2.2'
EXCLUDED_PACKAGES = []


setup(
    name='pykeycloak',
    version=VERSION,
    description='A Simple wrapper for python-keycloak. Mainly used for simplifying keycloak interactions in Jupyter Notebooks.',
    url='https://github.com/cse-cst/pykeycloak',
    author='IS',
    author_email='',
    license='MIT',
    package_dir={'': 'src'},
    packages=find_packages('src', EXCLUDED_PACKAGES),
    install_requires=[
        'python-keycloak>=3.3.0',
        'filelock>=3.10.6',
        'pydantic>=1.10.4'
    ],
    classifiers=[
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',  
        'Operating System :: POSIX :: Linux',        
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10'
    ],
)
