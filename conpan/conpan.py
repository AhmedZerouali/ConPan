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

import logging
import warnings

import pandas as pd
import requests

from conpan.backend.debian import Debian
from conpan.backend.npm import npm

from .errors import ParamsError

warnings.simplefilter(action='ignore', category=Warning)

log = logging.getLogger()
console = logging.StreamHandler()
log.addHandler(console)

allPackages = ['debian','npm']

class ConPan:
    """ConPan, a tool to calculate analyze packages in Docker containers

    :param packages: targets packages kind
    :param docker: targets the Docker image
    """
    version = '0.1.0'
    description = 'ConPan, a tool to calculate analyze packages in Docker containers'

    def __init__(self, packages=None, image=None, dir_data=None):
        if not packages:
            raise ParamsError(cause="kind of packages cannot be null")

        if not image:
            raise ParamsError(cause="the Docker image cannot be null")

        if str(packages).lower() not in allPackages:
            raise ParamsError(cause="the packages type is not supported yet")

        self.image = image
        self.packages = str(packages).lower()
        self.VERO = True
        self.trackedPackages = pd.DataFrame()

        if self.packages == 'debian':
            self.backend = Debian(image, dir_data)

        if self.packages == 'npm':
            self.backend = npm(image, dir_data)

    def analyze(self):
        """Analyze packages for the target Docker image

        :return dataframes with all installed packages, their technical lag, vulnerabilities and other kind of bugs.
        """

        ####### PROCESS #######
        print('Connecting to DockerHub... ', end='')
        general_info = self.general_info()

        print('Done\nPulling the Docker image... ', end='')
        self.download()  ### DOWNLOAD THE IMAGES
        self.VERO = False

        print('Done\nExtracting installed packages... ', end='')
        installed_packages = self.installed_packages() ### GET THE INSTALLED PACKAGES

        print('Done\nTracking installed packages... ', end='')
        tracked_packages = self.tracked_packages()  ### TRACK THE INSTALLED PACKAGES

        print('Done\nIdentifying vulnerabilities... ', end='')
        vulnerabilities = self.vulnerabilities()

        print('Done\nIdentifying other kind of bugs... ', end='')

        bugs = self.bugs()
        #bugs = pd.DataFrame()

        print('Done\n')
        self.remove_files()
        return general_info, installed_packages, tracked_packages, vulnerabilities, bugs

    def general_info(self):
        """inspect information from the Docker api
        :return results: general information about the analyzed Docker container
        """

        if ':' in self.image:
            slug = self.image.split(':')[0]
            tag = str(self.image.split(':')[1])
        else:
            slug = self.image
            tag = 'latest'

        if '/' in slug:
            url = 'https://registry.hub.docker.com/v2/repositories/' + slug
            slug_info = requests.get(url=url).json()
            url = 'https://registry.hub.docker.com/v2/repositories/' + slug + '/tags/' + tag
            tag_info = requests.get(url=url).json()

        else:
            url = 'https://registry.hub.docker.com/v2/repositories/library/' + slug
            slug_info = requests.get(url=url).json()
            url = 'https://registry.hub.docker.com/v2/repositories/library/' + slug + '/tags/' + tag
            tag_info = requests.get(url=url).json()

        keys = ['description', 'star_count', 'pull_count', 'full_size', 'last_updated', 'architectures']
        results = {}
        for key in keys:
            try:
                results[key] = str(tag_info[key])
            except:
                try:
                    results[key] = str(slug_info[key])
                except:
                    pass

        return results

    def download(self):
        self.backend.download()

    def installed_packages(self):
        if self.VERO:
            self.download()
            self.VERO = False
        installed_packages =  self.backend.parse_packages()
        return installed_packages

    def tracked_packages(self):
        installed_packages = self.installed_packages()
        self.trackedPackages = self.backend.track_packages(installed_packages)
        return self.trackedPackages

    def vulnerabilities(self):
        if len(self.trackedPackages) == 0:
            self.trackedPackages = self.tracked_packages()
        return self.backend.get_vuls(self.trackedPackages)

    def bugs(self):
        if len(self.trackedPackages) == 0:
            self.trackedPackages = self.tracked_packages()
        return self.backend.get_bugs(self.trackedPackages)

    def remove_files(self):
        self.backend.remove_files()






