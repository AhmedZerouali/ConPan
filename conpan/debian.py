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

DIR = '/home/neglectos/Desktop/ConPan/data/debian/'
VULS_JSON = 'vulnerabilities.json'
PACKAGES = 'packages.csv'
VULS_CSV = 'vulnerabilities.csv'
BUGS_CSV = 'bugs.csv'
DIR_SAVE ='./'

removed = False


class Debian:
    """Debian, a backend to analyze Debian packages

    :param docker: targets the Docker image
    """

    def __init__(self, image=None):
        self.image = image
        self.file = image.replace('/', '_')

    def testo(self):
        return self.image + '---hola'

    def download(self):
        os.system(
            "docker run --entrypoint '/bin/bash' " + self.image + " -c 'cat /etc/issue' > " + DIR_SAVE + self.file + "_issue")
        os.system(
            "docker run --entrypoint '/bin/bash' " + self.image + " -c 'cat /etc/debian_version' > " + DIR_SAVE + self.file + "_debian")
        os.system("docker run --entrypoint '/bin/bash' " + self.image + " -c 'dpkg -l' > " + DIR_SAVE + self.file + "_dpkg")
        if removed:
            os.system("docker stop $(docker ps -a | grep '" + self.image + " ' | cut -d' ' -f1)")
            os.system("docker rm $(docker ps -a | grep '" + self.image + " ' | cut -d' ' -f1)")

    def parse_packages(self):
        columns = ['name', 'package', 'version']
        data = pd.DataFrame(columns=columns)
        command_package = "grep ^ii " + DIR_SAVE + self.file + "_dpkg"  # sed 's/  */ /g' |

        proc = subprocess.Popen(command_package, stdout=subprocess.PIPE, shell=True)
        lines = list(filter(lambda x: len(x) > 0, (line.strip().decode('utf-8') for line in proc.stdout)))
        packages = []
        versions = []
        for line in lines:
            line = line.split(' ')
            line = sorted(set(line), key=lambda x: line.index(x))
            packages.append(line[2])
            versions.append(line[3])

        df = pd.DataFrame({'name': self.file, 'package': packages, 'version': versions})
        data = data.append(df)
        return data.set_index('name')

    def parse_release(self):
        release=''
        with open(DIR_SAVE + self.file + "_debian") as lines:
            for line in lines.readlines():
                release = line.strip('\n')
        return release

    def parse_debian(self):
        installed_packages = self.parse_packages()
        installed_packages['release_number'] = self.parse_release()

        installed_packages['debian'] = installed_packages['release_number'].apply(lambda x:
                                                                                  'jessie' if x.startswith('8')
                                                                                  else 'stretch' if x.startswith('9')
                                                                                  else 'wheezy' if x.startswith('7')
                                                                                  else 'squeeze' if x.startswith('6')
                                                                                  else 'buster' if x.startswith(
                                                                                      'buster')
                                                                                  else x)
        installed_packages['package'] = installed_packages['package'].apply(lambda x: x.split(':')[0])

        installed_packages.drop_duplicates(inplace=True)

        return installed_packages

    ###### TRACK THE PACKAGES

    def debian_packages(self):
        #TRACK THE PACKAGES
        debian_packages = pd.read_csv(DIR+PACKAGES, sep=';', dtype=object, index_col=None,
                                      error_bad_lines=False)
        return debian_packages


    def track_packages(self, installed_packages):
        debian_p = self.debian_packages()

        tracked_packages = (installed_packages.
                            set_index(['package', 'version']).
                            merge(debian_p.
                                  set_index(['package', 'version']),
                                  left_index=True,
                                  right_index=True,
                                  how='outer')
                            ).reset_index().dropna()

        for column in ['last_order', 'version_order']:
            tracked_packages[column] = tracked_packages[column].apply(int)
        tracked_packages['outdate'] = tracked_packages['last_order'] - tracked_packages['version_order']
        return tracked_packages


################# IDENTIFY VULNERABIITIES
################# version where the vulnerability was fixed > version used



    def parse_json_vuls(self):
        vulnerabilities = js.load(codecs.open(DIR+VULS_JSON, 'r', 'utf-8'))
        return vulnerabilities


    def dates_release_debian(self):
        debian_p = self.debian_packages()
        df_packages = (debian_p.
                       sort_values('date', ascending=True).
                       groupby(['source', 'source_version', 'release_snapshot']).
                       first().
                       drop(['package', 'version'], axis=1)
                       )

        dict_date = df_packages.to_dict()  ### dict of source version dates

        df_packages_release = (debian_p.
                               sort_values('date', ascending=True).
                               groupby(['source', 'source_version']).
                               first().
                               drop(['package', 'version', 'date'], axis=1)
                               )

        dict_release = df_packages_release.to_dict()  # dict of releases
        return dict_date, dict_release


    def unique_installed_packages(self,tracked_packages):
        df = (tracked_packages.  ######## We create a DF with source packages found in Docker containers
              groupby(['source', 'source_version']).
              count().
              drop(['package', 'version'], axis=1).
              reset_index()
              )  ######## only source versions and distinct.

        return df


    def final_vuls(self, tracked_packages):
        vulnerabilities = self.parse_json_vuls()

        dict_date, dict_release = self.dates_release_debian()

        sorted_ip = self.unique_installed_packages(tracked_packages)

        fcsv = open(DIR_SAVE+VULS_CSV, 'w')
        fcsv.write('source;source_version;urgency;status;fixed_version;debianbug;release;cve\n')

        for index, raw in enumerate(sorted_ip.iterrows()):  ######## we iterate over the sources (docker)
            source = raw[1]['source']
            source_version = raw[1]['source_version']
            release = dict_release['release_snapshot'][(source, source_version)]
            date_source = dict_date['date'][(source, source_version, release)]
            try:
                vuls = vulnerabilities[source]  ###### check if the source has any vulnerabilities
            except:
                continue
            for cve in vuls:  ###### for each vulnerability
                if not cve.startswith('CVE'):
                    continue
                v = vulnerabilities[source][cve]
                try:
                    status = v['releases'][release]['status']  ###### check only the release of source
                    urgency = v['releases'][release]['urgency']  ###### check only the release of source

                    try:
                        debianbug = str(v['debianbug'])
                    except:
                        debianbug = "undefined"

                    if status == "open" or status == "undetermined":  ###### if the vulnerability is still OPEN
                        fixed = "undefined"
                        fcsv.write(
                            source + ';' + source_version + ';' + urgency + ';' + status + ';' + fixed + ';' + debianbug + ';' + release + ';' + cve + '\n')
                    else:  ###### if the vulnerability is RESOLVED
                        try:
                            fixed = v['releases'][release]["fixed_version"]
                        except:
                            continue
                        if apt_pkg.version_compare(source_version,
                                                   fixed) < 0:  #### Compare between the used source and fixed one (dates comparison)
                            fcsv.write(
                                source + ';' + source_version + ';' + urgency + ';' + status + ';' + fixed + ';' + debianbug + ';' + release + ';' + cve + '\n')

                except:
                    pass
        fcsv.close()


    def get_vuls(self, tracked_packages):
        self.final_vuls(tracked_packages)

        docker_vulnerabilities = pd.read_csv(DIR_SAVE + VULS_CSV, sep=';', dtype=object,
                                             index_col=None, error_bad_lines=False)
        docker_vulnerabilities.drop_duplicates(inplace=True)

        return docker_vulnerabilities

    #### MERGE FOUND VULNERABILITIES WITH INSTALLED PACKAGES
    def merge_vuls(self, tracked_packages):
        vuls = self.get_vuls(tracked_packages)  ### GET VULNERABILITIES
        # Here we merge vulnerabilities with community outdated packages
        docker_vuls = (
            tracked_packages.
                set_index(['source', 'source_version']).
                merge(vuls.
                      set_index(['source', 'source_version']),
                      left_index=True,
                      right_index=True,
                      how='outer').dropna().reset_index().drop_duplicates()
        )
        return docker_vuls

    ########## HERE WE EXTRACT BUGS FROM UDD ###############

    def connexion_udd(self):
        conn_string = "host='udd-mirror.debian.net' port='5432' dbname='udd' user='udd-mirror' password='udd-mirror'"
        conn = psycopg2.connect(conn_string)
        conn.set_client_encoding('UTF8')
        cursor = conn.cursor()
        return cursor

    def extract_bugs_from_udd(self, tracked_packages):

        cursor = self.connexion_udd()

        unique_packages = tracked_packages.groupby('source').count().loc[:, []].reset_index()

        f = open(DIR_SAVE+BUGS_CSV, 'w')
        f.write('source;debianbug;found_in;fixed_in;type;status;severity;arrival;last_modified\n')

        for index, raw in enumerate(unique_packages.iterrows()):
            source = raw[1]['source']

            cursor.execute(
                "SELECT DISTINCT bugs.id, bugs.status, bugs.severity, " +
                "bugs.arrival, bugs.last_modified, bugs_found_in.version, bugs_fixed_in.version " +
                "FROM bugs_found_in, bugs LEFT JOIN bugs_fixed_in " +
                "ON bugs.id=bugs_fixed_in.id " +
                "WHERE bugs.id=bugs_found_in.id " +
                "AND bugs.source='" + source + "' ")
            data = cursor.fetchall()
            for x in data:
                id, status, severity, arrival, last_modified, found_in, fixed_in = x
                f.write(source + ';' + str(id) + ';' + found_in + ';' + str(
                    fixed_in) + ';normal;' + status + ';' + severity + ';' + str(arrival) + ';' + str(
                    last_modified) + '\n')

            cursor.execute(
                "SELECT DISTINCT archived_bugs.id, archived_bugs.status, archived_bugs.severity, " +
                "archived_bugs.arrival, archived_bugs.last_modified, " +
                "archived_bugs_found_in.version, archived_bugs_fixed_in.version " +
                "FROM archived_bugs_found_in, archived_bugs LEFT JOIN archived_bugs_fixed_in " +
                "ON archived_bugs.id=archived_bugs_fixed_in.id " +
                "WHERE archived_bugs.id=archived_bugs_found_in.id " +
                "AND archived_bugs.source='" + source + "'")
            data2 = cursor.fetchall()
            for x in data2:
                id, status, severity, arrival, last_modified, found_in, fixed_in = x
                f.write(source + ';' + str(id) + ';' + found_in + ';' + str(
                    fixed_in) + ';archived;' + status + ';' + severity + ';' + str(arrival) + ';' + str(
                    last_modified) + '\n')

        f.close()


################# We identify which sources versions are affected by the bugs #########""

################# version where bug found <= version used < version where the bug was fixed

    def get_bugs(self,tracked_packages):

        self.extract_bugs_from_udd(tracked_packages)

        bugs = pd.read_csv(DIR_SAVE+BUGS_CSV, sep=';', dtype=object, index_col=None, error_bad_lines=False)
        bugs.drop_duplicates(inplace=True)

        bugs['fixed_in'] = bugs['fixed_in'].apply(lambda x: str(x).split('/')[-1])
        bugs['found_in'] = bugs['found_in'].apply(lambda x: str(x).split('/')[-1])

        sources = tracked_packages.groupby(['source', 'source_version', 'release_snapshot', 'date']).count().loc[:,
                  []].reset_index()
        deb_packages = self.debian_packages()
        bugs = (bugs.
                set_index(['source']).
                merge(sources.
                      set_index(['source']),
                      left_index=True,
                      right_index=True,
                      how='left').dropna().reset_index()
                )

        bugs = (bugs.
                set_index(['source', 'found_in']).
                merge(deb_packages.
                      rename(columns={'date': 'date_found', 'source_version': 'found_in'}).
                      set_index(['source', 'found_in']),
                      left_index=True,
                      right_index=True,
                      how='left').dropna().reset_index().drop_duplicates()
                )

        bugs['filtre'] = bugs.apply(
            lambda row: True if apt_pkg.version_compare(str(row['found_in']), str(row['source_version'])) <= 0
            else False, axis=1)

        bugs = bugs.query('filtre==True')  # date_found<=date and

        bugs = (bugs.
                set_index(['source', 'fixed_in']).
                merge(deb_packages.
                      rename(columns={'date': 'date_fixed', 'source_version': 'fixed_in'}).
                      set_index(['source', 'fixed_in']),
                      left_index=True,
                      right_index=True,
                      how='left').fillna('undefined').reset_index().drop_duplicates()
                )
        deb_packages == self.debian_packages()
        bugs['filtre'] = bugs.apply(
            lambda row: True if apt_pkg.version_compare(str(row['source_version']), str(row['fixed_in'])) < 0
            else False, axis=1)

        bugs = bugs.query('filtre==True')  # date_fixed>date

        bugs = bugs.groupby(['debianbug', 'source']).first().reset_index()

        return bugs

    ####### HERE WE GET GENERAL INFOR from the repo


    def general_information(self):

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
                results[key] = str(slug_info[key])
            except:
                pass

        # results = {'description': slug_info['description'],
        #            'star_count': str(slug_info['star_count']),
        #             'pull_count': str(slug_info['pull_count']),
        #             'full_size': str(tag_info['full_size']),
        #             'last_updated': tag_info['last_updated'],
        #            'architectures': [a['architecture'] for a in tag_info['images']]}
        return results

    def remove_files(self):
        os.system('rm {0}{1}_*'.format(DIR_SAVE, str(self.image)))
        os.system('rm {0}{1}'.format(DIR_SAVE, BUGS_CSV))
        os.system('rm {0}{1}'.format(DIR_SAVE, VULS_CSV))
