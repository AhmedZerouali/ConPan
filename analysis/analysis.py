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

    def piePlot(self, df, axis):

        if 'severity' in df.columns:
            groupby = 'severity'
            title = 'Bugs'
        elif 'urgency' in df.columns:
            groupby = 'urgency'
            title = 'Vulnerabilities'
        else:
            groupby = 'isOutdate'
            title = 'Installed Packages'
            df['isOutdate'] = df['outdate'].apply(
                lambda x: 'Up to date' if x==0
                else 'Out of date')

        ax = (df
              .groupby(groupby)
              .count()
              .plot(kind='pie',
                    autopct='%1.1f%%',
                    y='source',
                    ax=axis,
                    title=title,
                    fontsize=17,
                    legend=None)#, explode=explode)
              )

        ax.set_ylabel('')
        ax.tick_params(labelsize=30, width=4)
        ax.figure.set_size_inches(5,5)
