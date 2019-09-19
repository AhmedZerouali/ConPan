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
import psycopg2
import io
from tqdm import tqdm
import requests
import logging
import re
logger = logging.getLogger(__name__)
warnings.simplefilter(action='ignore', category=Warning)

VULS_JSON = 'https://security-tracker.debian.org/tracker/data/json'
PACKAGES = 'https://raw.githubusercontent.com/neglectos/datasets/master/debian_packages.csv'
VULS_CSV = 'vulnerabilities.csv'
BUGS_CSV = 'bugs.csv'
removed = False

re_all_digits_or_not = re.compile("\d+|\D+")
re_digits = re.compile("\d+")
re_digit = re.compile("\d")
re_alpha = re.compile("[A-Za-z]")

re_valid_version = re.compile(
            r"^((?P<epoch>\d+):)?"
             "(?P<upstream_version>[A-Za-z0-9.+:~-]+?)"
             "(-(?P<debian_revision>[A-Za-z0-9+.~]+))?$")


class Debian:
    """Debian, a backend to analyze Debian packages

    :param docker: targets the Docker image
    """

    def __init__(self, image=None, data_dir=None):
        self.image = image
        self.data_dir = data_dir
        self.file = image.replace('/', '_')
        self.debian_version = ''
        self.container_dpkg = ''

    def read_csv(self, CSV):
        """Reads a csv file
        :param CSV: the csv file to read
        :return df: dataframe of the csv file
        """
        df = pd.read_csv(self.data_dir + CSV, sep=';', dtype=object, index_col=None)
        df.drop_duplicates(inplace=True)

        return df

    def read_csv_url(slef,url):
        """Reads a csv file from url
        :param url: the url of the csv file to read
        :return df: dataframe of the csv file
        """
        content = requests.get(url).content
        df = pd.read_csv(io.StringIO(content.decode('utf-8')), dtype=object, index_col=None)
        df.drop_duplicates(inplace=True)

        return df

    def json_from_url(self, url):
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
        cmd = "docker run --entrypoint '/bin/bash' " + self.image + " -c 'cat /etc/debian_version' "
        self.debian_version = self.command_system(cmd)

        cmd = "docker run --entrypoint '/bin/bash' " + self.image + " -c 'dpkg -l' "
        self.container_dpkg = self.command_system(cmd)

        if removed:
            os.system("docker stop $(docker ps -a | grep '" + self.image + " ' | cut -d' ' -f1)")
            os.system("docker rm $(docker ps -a | grep '" + self.image + " ' | cut -d' ' -f1)")

    @property
    def parse_release(self):
        """Returns the Debian release used in the Container
        """
        try:
            return self.debian_version[0]
        except:
            return ''

    def parse_packages(self):
        """Extracts installed packages in the Docker container
        :return data: a dataframe with the installed packages
        """

        columns = ['name', 'package', 'version']
        data = pd.DataFrame(columns=columns)

        packages = []
        versions = []
        for line in self.container_dpkg:
            if not str(line).startswith('ii'):
                continue
            line = line.split(' ')
            line = sorted(set(line), key=lambda x: line.index(x))
            packages.append(line[2])
            versions.append(line[3])

        df = pd.DataFrame({'name': self.file, 'package': packages, 'version': versions})
        data = data.append(df)
        data.set_index('name', inplace=True)

        data['debian_release'] = self.parse_release

        data['image_debian'] = data['debian_release'].apply(lambda x: 'jessie' if x.startswith('8')
                                                                          else 'stretch' if x.startswith('9')
                                                                          else 'wheezy' if x.startswith('7')
                                                                          else 'squeeze' if x.startswith('6')
                                                                          else 'buster' if x.startswith('buster')
                                                                          else x)
        data['package'] = data['package'].apply(lambda x: x.split(':')[0])

        data.drop_duplicates(inplace=True)

        return data

    def oudated_packages(self, tracked, packages):

        """Compute the number of missing updates of installed package: How outdated packages are
        :param tracked: set of installed package versions
        :return packages: historical data of Debian
        """
        for x in packages:
            packages[x] = packages[x].apply(str)
        tracked = (tracked
                   .set_index(['package', 'first_seen'])
                   .merge(packages
                          .set_index(['package', 'first_seen'])
                          .rename(columns={'version': 'version_compare'}),
                          left_index=True,
                          right_index=True,
                          how='left')
                   .dropna()
                   .reset_index()
                   .drop_duplicates()
                   )

        tracked['missing_updates'] = tracked.apply(lambda d:
                                             self.compare(d['version'],
                                                                     d['version_compare']) < 0,
                                             axis=1)

        tracked = (tracked.query('missing_updates == True')
                   .groupby(['package', 'version'])
                   .count()[['missing_updates']]
                   .reset_index())

        return tracked

    def track_packages(self, installed_packages):
        """Tracks installed packages to check if they are coming from Debian.
        :param installed_packages: packages found installed in the Container
        :return tracked_packages: packages found installed in the Container and coming from Debian.
        """
        debian_p = self.read_csv_url(PACKAGES)

        tracked_packages = (installed_packages.
                            set_index(['package', 'version']).
                            merge(debian_p.
                                  set_index(['package', 'version']),
                                  left_index=True,
                                  right_index=True,
                                  how='left')
                            ).reset_index().dropna()

        tracked = self.oudated_packages(tracked_packages[['package', 'version', 'first_seen']],
                                   debian_p[['package', 'version', 'first_seen', 'package_date']])

        tracked_packages = (tracked_packages
                             .set_index(['package', 'version'])
                             .merge(tracked
                                    .set_index(['package', 'version']),
                                    left_index=True,
                                    right_index=True,
                                    how='left')
                             .fillna(0)
                             .reset_index()
                             .drop_duplicates()
                             )

        return tracked_packages


    def dates_release_debian(self):
        """many packages are seen in different releases of Debian: We choose the first release where a package version was seen as the Debian release
        :return dict_date: a dictionary with packages and their release date
        :return dict_release: a dictionary with packages and their Debian release version.
        """

        debian_p = self.read_csv_url(PACKAGES)
        df_packages = (debian_p.
                       sort_values('package_date', ascending=True).
                       groupby(['source', 'source_version', 'first_seen']).
                       first().
                       drop(['package', 'version'], axis=1)
                       )

        dict_date = df_packages.to_dict()  # dict of source version dates

        df_packages_release = (debian_p.
                               sort_values('package_date', ascending=True).
                               groupby(['source', 'source_version']).
                               first().
                               drop(['package', 'version', 'package_date'], axis=1)
                               )

        dict_release = df_packages_release.to_dict()  # dict of releases
        return dict_date, dict_release

    def unique_installed_packages(self,tracked_packages):
        """Identify unique source packages.
        A source package may have many binary packages.
        :param tracked_packages: packages found installed in the container
        :return df: a dataframe with unique source packages.
        """

        df = (tracked_packages.  # We create a DF with source packages found in Docker containers
              groupby(['source', 'source_version']).
              count().
              drop(['package', 'version'], axis=1).
              reset_index()
              )  # only source versions and distinct.

        return df


    def final_vuls(self, tracked_packages):
        """Extract knows vulnerabilities from the Debian Security Tracker, for all packages found in the container.
        We consider versions where the vulnerability was fixed as the stop point.
        It extracts bugs for all versions and save them in a file.
        :param tracked_packages: packages found installed in the container
        :return
        """
        vulnerabilities = self.json_from_url(VULS_JSON)
        dict_date, dict_release = self.dates_release_debian()
        sorted_ip = self.unique_installed_packages(tracked_packages)
        tcsv = []

        for index, raw in tqdm(enumerate(sorted_ip.iterrows())):  # we iterate over the sources (docker)
            source = raw[1]['source']
            source_version = raw[1]['source_version']
            release = dict_release['first_seen'][(source, source_version)]
            try:
                vuls = vulnerabilities[source]  # check if the source has any vulnerabilities
            except:
                continue
            for cve in vuls:  # for each vulnerability
                if not cve.startswith('CVE'):
                    continue
                v = vulnerabilities[source][cve]
                try:
                    status = v['releases'][release]['status']  # check only the release of source
                    urgency = v['releases'][release]['urgency']  # check only the release of source

                    try:
                        debianbug = str(v['debianbug'])
                    except:
                        debianbug = "undefined"

                    if status == "open" or status == "undetermined":  # if the vulnerability is still OPEN
                        fixed = "undefined"
                    else:  # if the vulnerability is RESOLVED
                        try:
                            fixed = v['releases'][release]["fixed_version"]
                        except:
                            continue
                        if self.compare(source_version,fixed) >= 0:  # Compare between the used source and fixed one (dates comparison)
                            continue
                    tcsv.append([source, source_version,urgency,status,fixed,debianbug,cve])

                except:
                    pass

        tcsv = list(zip(*tcsv))
        columns = ['source', 'source_version','urgency','status','fixed','debianbug','cve']
        df = pd.DataFrame(columns=columns)
        for index, col in enumerate(columns):
            df[col] = tcsv[index]

        return df

    def get_vuls(self, tracked_packages):
        """Extracts and Merges vulnerabilities with tracked packages.
        :param tracked_packages: packages found installed in the container
        :return docker_vuls: knows vulnerabilities of the installed packages
        """
        vuls = self.final_vuls(tracked_packages)
        docker_vuls = (tracked_packages
                       .set_index(['source', 'source_version'])[['missing_updates']]
                       .merge(vuls
                              .set_index(['source', 'source_version']),
                              left_index=True,
                              right_index=True,
                              how='left')
                       .dropna()
                       .reset_index()
                       .drop_duplicates()
        )

        return docker_vuls

    def connexion_udd(self):
        """Connects to the UDD (Ultimate Debian Database)
        """
        conn_string = "host='udd-mirror.debian.net' port='5432' dbname='udd' user='udd-mirror' password='udd-mirror'"
        conn = psycopg2.connect(conn_string)
        conn.set_client_encoding('UTF8')
        cursor = conn.cursor()
        return cursor

    def extract_bugs_from_udd(self, tracked_packages):
        """Extract knows bugs from UDD ( Ultimate Debian Database), for all packages found in the container.
        It extracts bugs for all versions and save them in a file.
        :param tracked_packages: packages found installed in the container
        """
        cursor = self.connexion_udd()
        sources = tracked_packages.source.drop_duplicates().values
        normal = []
        archive = []
        for source in tqdm(sources):
            cursor.execute(
                "SELECT DISTINCT bugs.source, bugs.id, bugs.status, bugs.severity, " +
                "bugs.arrival, bugs.last_modified, bugs_found_in.version, bugs_fixed_in.version " +
                "FROM bugs_found_in, bugs LEFT JOIN bugs_fixed_in " +
                "ON bugs.id=bugs_fixed_in.id " +
                "WHERE bugs.id=bugs_found_in.id " +
                "AND bugs.source='" + source + "' ")
            n = cursor.fetchall()

            cursor.execute(
                "SELECT DISTINCT archived_bugs.source, archived_bugs.id, archived_bugs.status, archived_bugs.severity, " +
                "archived_bugs.arrival, archived_bugs.last_modified, " +
                "archived_bugs_found_in.version, archived_bugs_fixed_in.version " +
                "FROM archived_bugs_found_in, archived_bugs LEFT JOIN archived_bugs_fixed_in " +
                "ON archived_bugs.id=archived_bugs_fixed_in.id " +
                "WHERE archived_bugs.id=archived_bugs_found_in.id " +
                "AND archived_bugs.source='" + source + "'")
            a = cursor.fetchall()

            normal = normal + n
            archive = archive + a
        normal = list(zip(*normal))
        archive = list(zip(*archive))

        columns = ['source', 'debianbug', 'status', 'severity', 'arrival', 'last_modified', 'found_in', 'fixed_in']
        df_normal = pd.DataFrame(columns=columns)
        df_archive = pd.DataFrame(columns=columns)

        for index, col in enumerate(columns):
            df_normal[col] = normal[index]
            df_archive[col] = archive[index]

        df_normal['type'] = 'normal'
        df_archive['type'] = 'archive'
        data = pd.concat([df_normal, df_archive])
        return data

    def get_bugs(self,tracked_packages):
        """Track bugs of the installed package versions: version where bug found <= version used < version where the bug was fixed
        After you extract the data, analyze it carefully; because sometimes the data coming from UDD is not correct.
        :param tracked_packages: packages found installed in the container
        :return bugs: knows bugs of the installed packages
        """

        bugs = self.extract_bugs_from_udd(tracked_packages)

        bugs['fixed_in'] = bugs['fixed_in'].apply(lambda x: str(x).split('/')[-1])
        bugs['found_in'] = bugs['found_in'].apply(lambda x: str(x).split('/')[-1])
        bugs['last_modified'] = bugs['last_modified'].apply(lambda x: str(x).split()[0])
        bugs['arrival'] = bugs['arrival'].apply(lambda x: str(x).split()[0])

        bugs['source'] = bugs['source'].apply(str)

        bugs = (tracked_packages
                .set_index(['source'])[['source_version', 'missing_updates', 'package_date']]
                .merge(bugs
                       .set_index(['source']),
                       left_index=True,
                       right_index=True,
                       how='left')
                .dropna()
                .drop_duplicates()
                .reset_index()
                )

        mask = bugs.apply(
            lambda row: True if self.compare(str(row['found_in']), str(row['source_version'])) <= 0
            and self.compare(str(row['source_version']), str(row['fixed_in'])) < 0
            else False, axis=1)
        # Filtre on bugs that were created before the creation of the package and fixed after that (or not)
        bugs = bugs[mask]

        bugs_pending = bugs.query('status != "done"')
        bugs_done = bugs.query('status == "done"')
        mask = bugs_done.apply(
            lambda d:  True if d['last_modified'].replace('-', '') > d['package_date']
            else False, axis=1)
        bugs_done = bugs_done[mask] # some done bugs do not have the fixed_in packages, we compare by date
        bugs = pd.concat([bugs_done, bugs_pending])

        bugs.drop(['package_date'], axis=1, inplace=True)
        bugs = bugs.groupby(['debianbug', 'source']).first().reset_index()

        return bugs

    def cmp(self,a, b):
        """Compares between two integers. Normally this exists in python, but JIC"""
        if a == b:
            return 0
        elif a < b:
            return -1
        else:
            return 1

    def order(self,x):
        """Returns an integer value for character x"""
        if x == '~':
            return -1
        elif re_digit.match(x):
            return int(x) + 1
        elif re_alpha.match(x):
            return ord(x)
        else:
            return ord(x) + 256

    def version_cmp_string(self,va, vb):
        """Compares between two string"""
        la = [self.order(x) for x in va]
        lb = [self.order(x) for x in vb]
        while la or lb:
            a = 0
            b = 0
            if la:
                a = la.pop(0)
            if lb:
                b = lb.pop(0)
            res = self.cmp(a, b)
            if res != 0:
                return res
        return 0

    def version_cmp_part(self,va, vb):
        """Compares between two parts of a version, e.g. epoch_1 vs epoch_2 """
        la = re_all_digits_or_not.findall(va)
        lb = re_all_digits_or_not.findall(vb)
        while la or lb:
            a = "0"
            b = "0"
            if la:
                a = la.pop(0)
            if lb:
                b = lb.pop(0)
            if re_digits.match(a) and re_digits.match(b):
                a = int(a)
                b = int(b)
                res = self.cmp(a, b)
                if res != 0:
                    return res
            else:
                res = self.version_cmp_string(a, b)
                if res != 0:
                    return res
        return 0

    def compare(self,a, b):
        """Compares between two version numbers"""
        a = re_valid_version.match(a).groupdict()
        b = re_valid_version.match(b).groupdict()

        res = self.cmp(int(a['epoch'] or "0"), int(b['epoch'] or "0"))
        if res != 0:
            return res
        res = self.version_cmp_part(a['upstream_version'], b['upstream_version'])
        if res != 0:
            return res
        res = self.version_cmp_part(a['debian_revision'] or "0", b['debian_revision'] or "0")
        return res

    def remove_files(self): # I am not sure if this is needed
        """Remove created files
        """
        os.system('rm {0}{1}'.format(self.data_dir, BUGS_CSV))
        os.system('rm {0}{1}'.format(self.data_dir, VULS_CSV))
