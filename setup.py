#!/usr/bin/env python3
"""
Setup script for Steam Proton Helper
"""

from setuptools import setup
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='steam-proton-helper',
    version='1.9.0',
    description='A comprehensive Linux tool to help setup Steam and Proton for gaming',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='SteamProtonHelper Contributors',
    url='https://github.com/AreteDriver/SteamProtonHelper',
    py_modules=['steam_proton_helper'],
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Games/Entertainment',
        'Topic :: System :: Installation/Setup',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console',
    ],
    keywords='steam proton linux gaming wine vulkan',
    entry_points={
        'console_scripts': [
            'steam-proton-helper=steam_proton_helper:main',
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/AreteDriver/SteamProtonHelper/issues',
        'Source': 'https://github.com/AreteDriver/SteamProtonHelper',
        'Documentation': 'https://github.com/AreteDriver/SteamProtonHelper#readme',
    },
)
