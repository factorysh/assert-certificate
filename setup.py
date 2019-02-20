from setuptools import setup, find_packages

setup(
    name='assert_certificate',
    version='0.0.1.dev0',
    description='',
    install_requires=[
        'x5092json',
    ],
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    extras_require={
        'test': ['pytest', 'pytest-cov', 'pytest-mock'],
    },
    licence="BSD",
    classifiers=[
      'Operating System :: MacOS',
      'Operating System :: POSIX',
      'License :: OSI Approved :: BSD License',
      'Programming Language :: Python :: 3.5',
      'Programming Language :: Python :: 3.6',
    ]
)
