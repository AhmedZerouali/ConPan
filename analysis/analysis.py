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

class Analysis:
    """Analysis, a class to show results in graphic way

    :param docker: targets the Docker image
    """

    def outdateness(self, tracked_packages, axis):

        tracked_packages['isOutdate']=tracked_packages['outdate'].apply(lambda x: 'Up to date' if x==0
                                                                       else 'Out of date')

        ax=tracked_packages.groupby('isOutdate').count().plot(kind='pie',
                                                              autopct='%1.1f%%',
                                                              y='source',
                                                              ax=axis,
                                                              title='Installed Packages',
                                                              fontsize=17)#, explode=explode)

        ax.legend('')
        ax.set_ylabel('')
        ax.tick_params(labelsize=30, width=4)
        ax.figure.set_size_inches(5,5)

    def security(self, vulnerabilities, axis):

        ax=vulnerabilities.groupby('urgency').count().plot(kind='pie',
                                                       autopct='%1.1f%%',
                                                       y='source',
                                                        ax=axis,
                                                       title='Vulnerabilities',
                                                       fontsize=17)#, explode=explode)

        ax.legend('')
        ax.set_ylabel('')
        ax.tick_params(labelsize=30, width=4)
        ax.figure.set_size_inches(5,5)

    def bugs(self, bugs, axis):

        ax=bugs.groupby('severity').count().plot(kind='pie',
                                                 autopct='%1.1f%%',
                                                 y='source',
                                                 ax=axis,
                                                 title='Bugs',
                                                 fontsize=17)#, explode=explode)
        ax.legend('')
        ax.set_ylabel('')
        ax.tick_params(labelsize=30, width=4)
        ax.figure.set_size_inches(5,5)
