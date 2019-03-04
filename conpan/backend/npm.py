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
import os
import subprocess
import pandas as pd
import warnings
import json as js
import codecs
import apt_pkg
import psycopg2
import requests
apt_pkg.init_system()
from conpan.errors import ParamsError
warnings.simplefilter(action='ignore', category=Warning)

VULS_JSON = 'vulnerabilities.json'
PACKAGES = 'packages.csv'
VULS_CSV = 'vulnerabilities.csv'
BUGS_CSV = 'bugs.csv'

removed = False


class npm:
    """npm, a backend to analyze npm packages

    :param docker: targets the Docker image
    """

    def __init__(self, image=None, data_dir=None):
        self.image = image
        self.data_dir = data_dir
        self.file = image.replace('/', '_')
        self.container_npm = ''

    def command_system(self, cmd):
        """Excutes a Shell command
        :return result: the output of the command
        """

        result = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        result = list(filter(lambda x: len(x) > 0, (line.strip().decode('utf-8') for line in result.stdout)))

        return result

    def download(self):
        """Pulls and runs the Docker images
        """

        cmd = "docker run --entrypoint '/bin/bash' " + self.image + " -c 'npm ls -g' "
        self.container_npm = self.command_system(cmd)

        if removed:
            os.system("docker stop $(docker ps -a | grep '" + self.image + " ' | cut -d' ' -f1)")
            os.system("docker rm $(docker ps -a | grep '" + self.image + " ' | cut -d' ' -f1)")

    def parse_packages(self):
        """Extracts installed packages in the Docker container
        :return data: a dataframe with the installed packages
        """
        packages = []
        versions = []

        for line in self.container_npm:
            if '@' not in line:
                continue
            line = line.split('@')
            package = line[0].split()[-1]
            version = line[1].split()[0]
            packages.append(package)
            versions.append(version)

        df = pd.DataFrame({'name': self.file, 'package': packages, 'version': versions})
        df.drop_duplicates(inplace=True)

        return df


    def track_packages(self, installed_packages):
        """Tracks installed packages from npm.
        :param installed_packages: packages found installed in the Container
        :return tracked_packages: tracked packages from npm
        """

        # NOT IMPLEMENTED YET
        installed_packages['outdate'] = 0
        return installed_packages

    def get_vuls(self, tracked_packages):
        """Extracts and Merges vulnerabilities with tracked packages.
        :param tracked_packages: packages found installed in the container
        :return docker_vuls: knows vulnerabilities of the installed packages
        """

        # NOT IMPLEMENTED YET
        return pd.DataFrame()


    def get_bugs(self, tracked_packages):

        """Extracts and Merges vulnerabilities with tracked packages.
        :param tracked_packages: packages found installed in the container
        :return docker_vuls: knows vulnerabilities of the installed packages
        """

        # NOT IMPLEMENTED YET
        return pd.DataFrame()

    def remove_files(self):
        """Remove created files
        """
        pass