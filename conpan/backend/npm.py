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
import apt_pkg
apt_pkg.init_system()
import logging
logger = logging.getLogger(__name__)
import re
import requests
from urllib.parse import urljoin
import warnings
warnings.simplefilter(action='ignore', category=Warning)

from conpan.errors import ParamsError

NPM_URL = 'http://registry.npmjs.org'
removed = False

RELEASE_MINOR = 'minor'
RELEASE_MAJOR = 'major'
RELEASE_PATCH = 'patch'
RE = r'^(?:v|V)?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?P<misc>.+)?$'

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


    def fetch_from_url(self, url):
        """Fetch package information from a URL and return its content.
        :param url: the target url
        :return: the content of the url
        """
        response = requests.get(url)

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as error:
            logger.error(error)

        to_json = response.json()
        return to_json

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

    def get_versions(self, package):
        """Get the version of a given package.
        :param package: target package name
        :return: pandas data frame of package versions
        """
        url = urljoin(NPM_URL, package)
        versions = self.fetch_from_url(url)['time']
        versions.pop('modified')
        versions.pop('created')
        versions = (pd.DataFrame({'version': list(versions.keys()),
                                  'date': list(versions.values()),
                                  'package': package}))

        versions['version'] = versions['version'].apply(lambda x: x.split('-')[0])
        versions.drop_duplicates(inplace=True)

        return versions

    def convert_version(self, version):
        """Convert version to a numeric value.
        :param version: the version of a package
        :return: a numeric value of the package version
        """
        major = 0
        minor = 0
        patch = 0

        prog = re.compile("^\d+(\.\d+)*$")
        result = prog.match(version)

        if not result:
            msg = "Impossible to convert version %s" % version
            raise ParamsError(cause=msg)

        groups = version.split('.')
        if len(groups) >= 1:
            major = int(groups[0]) * 1000000
        if len(groups) >= 2:
            minor = int(groups[1]) * 1000
        if len(groups) >= 3:
            patch = int(groups[2])

        return major + minor + patch

    def release_type(self, old_version, new_version):
        """Determine the type of a release by comparing two versions. The
        outcome can be: major, minor or patch.
        :param old_version: The source version of a package
        :param new_version: The target version of a package
        :return: the type of the release
        """
        old_version = str(old_version).split('.')
        new_version = str(new_version).split('.')

        release = RELEASE_PATCH
        if new_version[0] != old_version[0]:
            release = RELEASE_MAJOR
        elif new_version[1] != old_version[1]:
            release = RELEASE_MINOR

        return release

    def compute_lag(self, versions, used):
        """Compute the technical lag for the set of versions of a given package.
        :param versions: pandas data frame of the package versions
        :param used: version in use of the package
        :param latest: latest version available of the package
        :return: the technical lag
        """

        versions['vc_converted'] = versions['version'].apply(lambda v: self.convert_version(v))
        versions.sort_values('vc_converted', ascending=True, inplace=True)

        latest = versions.version.tolist()[-1]
        used = self.convert_version(used.split('-')[0])

        versions['version_old'] = versions['version'].shift(1)
        versions['release_type'] = versions.apply(lambda d:
                                                  self.release_type(d['version_old'], d['version']),
                                                  axis=1)
        
        versions = versions.query('vc_converted>' + str(used))

        if len(versions) == 0:
            return {RELEASE_MAJOR: 0, RELEASE_MINOR: 0, RELEASE_PATCH: 0, 'latest': latest}


        lag = versions.groupby('release_type').count()[['version']].to_dict()['version']
        lag['latest'] = latest

        if RELEASE_MAJOR not in lag.keys():
            lag[RELEASE_MAJOR] = 0
        if RELEASE_MINOR not in lag.keys():
            lag[RELEASE_MINOR] = 0
        if RELEASE_PATCH not in lag.keys():
            lag[RELEASE_PATCH] = 0

        return lag

    def track_packages(self, installed_packages):
        """Tracks installed packages from npm.
        :param installed_packages: packages found installed in the Container
        :return tracked_packages: tracked packages from npm
        """

        installed_packages[RELEASE_MAJOR + '_lag'] = ''
        installed_packages[RELEASE_MINOR + '_lag'] = ''
        installed_packages[RELEASE_PATCH + '_lag'] = ''
        installed_packages['latest'] = ''

        for row in range(0, len(installed_packages)):
            packages_registry = self.get_versions(installed_packages.iloc[row].package)
            lag = self.compute_lag(packages_registry, installed_packages.iloc[row].version)

            installed_packages.major_lag.iloc[row] = lag[RELEASE_MAJOR]
            installed_packages.minor_lag.iloc[row] = lag[RELEASE_MINOR]
            installed_packages.patch_lag.iloc[row] = lag[RELEASE_PATCH]
            installed_packages.latest.iloc[row] = lag['latest']

        # NOT IMPLEMENTED YET
        installed_packages['outdate'] = installed_packages.apply(lambda d:
                                                                 d['major_lag']+d['minor_lag']+d['patch_lag'],
                                                                 axis=1)
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
