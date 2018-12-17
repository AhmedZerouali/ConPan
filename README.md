# ConPan: Analyze your Docker container in peace

ConPan inspect Docker containers and extract their installed packages to analyze them. 

ConPan analyzes packages technical lag, vulnerabilities and other type of bugs.
## How it works
ConPan workflow is very simple:
- Pulls the Docker image.
- Run it and extract installed packages.
- Track installed packages from their package managers.
- Inspect their technical lag: checks if they are outdated and how much they are lagging behind the latest available versions.
- Identify vulnerable packages.
- Identify other kind of bugs for installed packages.


## Requirements
- docker-ce
- pandas>=0.22.0
- requests>=2.18.2
- psycopg2-binary>=2.7.4
- psycopg2>=2.7.4
- apt_pkg


##  How to install/uninstall
ConPan is developed and tested mainly on GNU/Linux platforms. Thus it is very likely it will work out of the box
on any Linux-like (or Unix-like) platform, upon providing the right version of Python (3.5, 3.6).


**To install**, run:
```
$> git clone https://github.com/neglectos/ConPan
$> python3 setup.py build
$> python3 setup.py install
```

**To uninstall**, run:
```
$> pip3 uninstall conpan
```

## How to use

ConPan can be used from command line or directly from Python, both usages are described below.

You will need permission to use the Docker tool first.
### From command line
Launching ConPan from command line does not require much effort.

```
$ conpan -p debian -c debian:buster-slim -d Path-to/data
```

### From Python
ConPan can be embedded in your Python scripts. Again, the effort of using it is minimum.

```
#! /usr/bin/env python3
from conpan.conpan import ConPan

# With 2 parameters
image_community = 'weboaks/chromium-xvfb-node'
image_official = 'debian:buster-slim'
dir_data = 'Path-to/data/'

cp = ConPan(packages="debian", image=image_official, dir_data=dir_data)

# extracting all information
general_info, installed_packages, tracked_packages, vulnerabilities, bugs = cp.analyze()

OR
# Extracting specific information


```
