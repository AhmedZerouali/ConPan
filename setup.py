#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA.
#
# Authors:
#     Ahmed Zerouali <mr.hmed@gmail.com>
#     Valerio Cosentino <valcos@bitergia.com>
#

from setuptools import setup

setup(
        name='ConPan',
        version='1.0.0',
        description='ConPan: a tool to analyze your Docker container in peace',
        long_description='ConPan inspect Docker containers and extract their installed packages to analyze them. '
                         'ConPan analyze packages technical lag, vulnerabilities and other type of bugs.',
        license="GPLv3",
        url='https://github.com/neglectos/ConPan',

        author='Ahmed Zerouali',
        author_email='mr.hmed@gmail.com',

        classifiers=[
            'Intended Audience :: Developers',
            'Intended Audience :: Science/Research',
            'Topic :: Scientific/Engineering :: Information Analysis',
            'Programming Language :: Python :: 3.5',
            'License :: OSI Approved :: GPL License'
        ],
        keywords='docker packages technical-lag',
        packages=[
            'conpan',
            'conpan.backend',
            'analysis'
        ],
        install_requires=[
            'pandas>=0.22.0',
            'requests>=2.18.2',
            'psycopg2-binary>=2.7.4',
            'psycopg2>=2.7.4'
        ],
        scripts=[
            'bin/conpan'
        ],
        zip_safe=False
)
