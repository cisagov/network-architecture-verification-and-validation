# NAVV

The **NAVV** (**N**etwork **A**rchitecture **V**erification and **V**alidation) tool creates a spreadsheet for network traffic analysis from PCAP data and Zeek logs, automating Zeek analysis of PCAP files, the collation of Zeek logs and the dissection of `conn.log` and `dns.log` to create a summary or network traffic in an XLSX-formatted spreadsheet. After manually updating the spreadsheet with names and color codes for network segments (by CIDR-formatted address groups) and hosts (by IP address), running the tool again will integrate these labels and color coding into the spreadsheet to aid in conducting an evaluation of the network traffic.

* [Installation](#Installation)
    * [Latest release](#InstallLatest)
    * [Directly using `git`](#InstallGit)
    * [External dependencies](#ExternalDeps)
    * [Building and packaging](#Packaging)
* [Usage](#Usage)
    * [Running NAVV](#Running)
    * [Identifying network segments and hosts](#Analysis)
* [Docker](#Docker)
* [Copyright](#Footer)
* [Contact](#Contact)

[![PyPI Release](https://img.shields.io/pypi/v/navv)](https://pypi.python.org/pypi/navv/)
[![Docker Image](https://github.com/cisagov/network-architecture-verification-and-validation/workflows/navv-build-push-ghcr/badge.svg)](https://github.com/cisagov/network-architecture-verification-and-validation/actions)
[![Total Alerts](https://img.shields.io/lgtm/alerts/g/cisagov/network-architecture-verification-and-validation.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/network-architecture-verification-and-validation/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/cisagov/network-architecture-verification-and-validation.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/network-architecture-verification-and-validation/context:python)
[![Known Vulnerabilities](https://snyk.io/test/github/cisagov/network-architecture-verification-and-validation/badge.svg)](https://snyk.io/test/github/cisagov/network-architecture-verification-and-validation)

## <a name="Installation"></a>Installation

The NAVV tool is a Python script requiring `python3` and its `pip` tool. As installation of Python varies from platform to platform, please consult your operating system's documentation or the [python.org Wiki](https://wiki.python.org/moin/BeginnersGuide/Download) to install and configure Python 3 on your system.

The recommended method for installing packages with `pip` is using [User Installs](https://pip.pypa.io/en/stable/user_guide/#user-installs) which installs to a user-specific location rather than system-wide. Usually this is done by running `pip` with the `--user` flag. It is generally *not* recommended to run `pip` with elevated/administrator/root privileges.

### <a name="InstallLatest"></a>Latest release

Download the [latest NAVV release from GitHub](https://github.com/cisagov/network-architecture-verification-and-validation/releases/latest). Either of the `.whl` [built distribution](https://packaging.python.org/glossary/#term-Built-Distribution) or the `.tar.gz` [source archive](https://packaging.python.org/glossary/#term-Source-Archive) release artifacts should suffice.

NAVV can then be installed via `pip`:

```shell
$ python3 -m pip install --user ~/Downloads/navv-3.0.0-py3-none-any.whl 
Processing /home/user/Downloads/navv-3.0.0-py3-none-any.whl 
…
Successfully installed et-xmlfile-1.1.0 lxml-4.6.3 navv-3.0.0 netaddr-0.8.0 openpyxl-3.0.7 tqdm-4.61.1
```

Alternately, also using `pip`, to install the latest [release from PyPI](https://pypi.org/project/navv/):

```
python3 -m pip install -U navv
```

### <a name="InstallGit"></a>Directly using `git`

NAVV can be installed via `pip` using `git`:

```shell
$ python3 -m pip install --user  git+https://github.com/cisagov/network-architecture-verification-and-validation
Collecting git+https://github.com/cisagov/network-architecture-verification-and-validation
  Cloning https://github.com/cisagov/network-architecture-verification-and-validation to /tmp/pip-req-build-pl6llgda
  Running command git clone -q https://github.com/cisagov/network-architecture-verification-and-validation /tmp/pip-req-build-pl6llgda
  Installing build dependencies ... done
…
Successfully installed et-xmlfile-1.1.0 lxml-4.6.3 navv-3.0.0 netaddr-0.8.0 openpyxl-3.0.7 tqdm-4.61.1

$ navv --help
usage: navv [-h] [-o OUTPUT_DIR] [-p PCAP] [-z ZEEK_LOGS] customer_name
…
```

### <a name="ExternalDeps"></a>External dependencies

These Python libraries will be automatically [downloaded](https://pypi.org/) and installed as runtime dependencies of the NAVV tool:

* **et-xmlfile** XML processing library ([Home](https://foss.heptapod.net/openpyxl/et_xmlfile), [PyPI](https://pypi.org/project/et-xmlfile/))
* **lxml** XML processing library ([Home](https://lxml.de/), [PyPI](https://pypi.org/project/lxml/))
* **netaddr** network address manipulation library ([Home](https://github.com/netaddr/netaddr), [PyPI](https://pypi.org/project/netaddr/))
* **openpyxl** library for interacting with Excel 2010 xlsx/xlsm ([Home](https://openpyxl.readthedocs.io/en/stable/), [PyPI](https://pypi.org/project/openpyxl/))
* **tqdm** progress bar decorator library ([Home](https://tqdm.github.io/), [PyPI](https://pypi.org/project/tqdm/))

The NAVV tool requires [Zeek](https://zeek.org/) to be installed with the `zeek` and `zeek-cut` utilities available in the `PATH`. Please consult the [Zeek manual](https://docs.zeek.org/en/current/install.html) for operating system-specifc instructions for installing and configuring Zeek. A NAVV [Docker](#Docker) image can be built which bundles both Zeek and the NAVV tool together.

### <a name="Packaging"></a>Building and packaging

PyPA's [build](https://packaging.python.org/key_projects/#build) module can be used to build and package the NAVV tool. At the command line, navigate to the directory containing the NAVV source code, then:

* install the Python 3 `build` module

```shell
$ python3 -m pip install --user --upgrade build
Collecting build
  Downloading build-0.4.0-py2.py3-none-any.whl (14 kB)
…
Installing collected packages: toml, pyparsing, pep517, packaging, build
…
Successfully installed build-0.4.0 packaging-20.9 pep517-0.10.0 pyparsing-2.4.7 toml-0.10.2
```

* build and package the NAVV tool:

```shell
$ python3 -m build
Found existing installation: setuptools 49.2.1
Uninstalling setuptools-49.2.1:
  Successfully uninstalled setuptools-49.2.1
Collecting setuptools>=42
  Downloading setuptools-57.0.0-py3-none-any.whl (821 kB)
     |████████████████████████████████| 821 kB 1.2 MB/s 
Collecting wheel
  Downloading wheel-0.36.2-py2.py3-none-any.whl (35 kB)
Installing collected packages: setuptools, wheel
…
creating navv-3.0.0
…
adding 'navv/__init__.py'
adding 'navv/__main__.py'
…
adding 'navv-3.0.0.dist-info/RECORD'
removing build/bdist.linux-x86_64/wheel
```

You will then see the packaged NAVV artifacts (the `.whl` [built distribution](https://packaging.python.org/glossary/#term-Built-Distribution) and the `.tar.gz` [source archive](https://packaging.python.org/glossary/#term-Source-Archive) files) in the `dist/` directory:

```shell
$  ls -l ./dist/
total 672
-rw-r--r-- 1 build build 673878 Jun 15 22:05 navv-3.0.0-py3-none-any.whl
-rw-r--r-- 1 build build  11709 Jun 15 22:05 navv-3.0.0.tar.gz
```

You can then follow the same method from the [Latest Release](#InstallLatest) section to install the NAVV tool.

Note that the resulting packaged NAVV artifacts do not contain the [external dependencies](#ExternalDeps) required to run the tool. Those Python libraries will be automatically [downloaded](https://pypi.org/) during the installation of the NAVV tool. If you are packaging the NAVV tool for distribution to a host without internet access, you will need to use `pip` to download the [external dependencies](#ExternalDeps) separately and install them prior to installing the NAVV tool.

```shell
$ python3 -m pip download lxml netaddr openpyxl tqdm
…
Saved ./lxml-4.6.3-cp39-cp39-manylinux2014_x86_64.whl
Saved ./netaddr-0.8.0-py2.py3-none-any.whl
Saved ./openpyxl-3.0.7-py2.py3-none-any.whl
Saved ./tqdm-4.61.1-py2.py3-none-any.whl
Saved ./et_xmlfile-1.1.0-py3-none-any.whl
Successfully downloaded lxml netaddr openpyxl tqdm et-xmlfile
```

Transfer the downloaded `.whl` files and the NAVV `.whl` file to the offline host and install them:

```shell
$ ls -lh
total 9.4M
-rw-r--r-- 1 build build 4.6K Jun 15 22:21 et_xmlfile-1.1.0-py3-none-any.whl
-rw-r--r-- 1 build build 6.6M Jun 15 22:21 lxml-4.6.3-cp39-cp39-manylinux2014_x86_64.whl
-rw-r--r-- 1 build build 659K Jun 15 22:22 navv-3.0.0-py3-none-any.whl
-rw-r--r-- 1 build build 1.9M Jun 15 22:21 netaddr-0.8.0-py2.py3-none-any.whl
-rw-r--r-- 1 build build 238K Jun 15 22:21 openpyxl-3.0.7-py2.py3-none-any.whl
-rw-r--r-- 1 build build  75K Jun 15 22:21 tqdm-4.61.1-py2.py3-none-any.whl

$ python3 -m pip install et_xmlfile-1.1.0-py3-none-any.whl lxml-4.6.3-cp39-cp39-manylinux2014_x86_64.whl netaddr-0.8.0-py2.py3-none-any.whl openpyxl-3.0.7-py2.py3-none-any.whl tqdm-4.61.1-py2.py3-none-any.whl 
…
Successfully installed et-xmlfile-1.1.0 lxml-4.6.3 netaddr-0.8.0 openpyxl-3.0.7 tqdm-4.61.1

$ python3 -m pip install navv-3.0.0-py3-none-any.whl 
…
Successfully installed navv-3.0.0

$ navv --help
usage: navv [-h] [-o OUTPUT_DIR] [-p PCAP] [-z ZEEK_LOGS] customer_name
…
```

Also, see [`docker/README.md`](./docker/README.md#BuildEnv) for a script which can be used to build and package the NAVV tool and its dependencies.

## <a name="Usage"></a>Usage

### <a name="Running"></a>Running NAVV

The NAVV tool can be run with the command `python3 -m navv`, or simply `navv` if your `PATH` contains the installation location used by `pip` during [installation](#Installation).

Run the NAVV tool with `--help` to get a listing of its arguments:

```shell
$ python3 -m navv --help
usage: __main__.py [-h] [-o OUTPUT_DIR] [-p PCAP] [-z ZEEK_LOGS] customer_name

One stop shop for all your zeek-cut commands

positional arguments:
  customer_name         Name of the customer

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Directory to place resultant files in
  -p PCAP, --pcap PCAP  Path to pcap file. Will run zeek and output logs in cwd or --zeek-logs
  -z ZEEK_LOGS, --zeek-logs ZEEK_LOGS
                        Directory containing log files
```

The NAVV tool will accept as input a PCAP file, in which case it will run `zeek` to generate the Zeek log files containing the metadata about the network traffic; or, a directory containing Zeek logs from a previous analysis.

For example:

```shell
analyst@host tmp> ll
total 178M
drwxrwxr-x 2 analyst analyst    6 Jun 15 22:36 ACME_logs
-rw-r--r-- 1 analyst analyst 178M Jun 15 22:35 ACME.pcap
analyst@host tmp> navv -o ./ACME_logs -p ACME.pcap ACME
get_inventory_data:
  Hours: 0
  Minutes: 0
  Seconds: 0
get_segments_data:
  Hours: 0
  Minutes: 0
  Seconds: 0
WARNING: No Site::local_nets have been defined.  It's usually a good idea to define your local networks.
Zeek returned with code: 0
run_zeek:
  Hours: 0
  Minutes: 0
  Seconds: 4
create_analysis_array:
  Hours: 0
  Minutes: 0
  Seconds: 0
Trimming DNS.log data:
100%|████████████████████████| 2319/2319 [00:00<00:00, 1190525.21it/s]
Performing analysis(including lookups). This may take a while:
100%|████████████████████████| 4425/4425 [00:03<00:00, 1427.59it/s]
perform_analysis:
  Hours: 0
  Minutes: 0
  Seconds: 3
main:
  Hours: 0
  Minutes: 0
  Seconds: 9
analyst@host tmp> ls -l ACME_logs/
total 208896
-rw-rw-r-- 1 analyst analyst    150 Jun 15 22:36 ACME_dns_data.pkl
-rw-rw-r-- 1 analyst analyst 203483 Jun 15 22:36 ACME_network_analysis.xlsx
```

As the example illustrates, the NAVV tool generated `.pkl` and `.xlsx` files as a result of the processing of `ACME.pcap`.

### <a name="Analysis"></a>Identifying network segments and hosts

Adding information about network segments and/or inventory can assist in packet capture analysis. Open the NAVV-generated `.xlsx` file and navigate to the `Segments` tab. Enter the relevant network segments and choose background colors for the corresponding cells. For example: 

![](./docs/images/segments.png)

Save your changes and re-run the NAVV tool with the `-z` option on the directory containing the Zeek log files and `.xlsx` file. The tool will modify the contents of the spreadsheet, recoloring the contents of the `Analysis` tab to match the segments specified in the `Segments` tab. This simplifies the task of identifying cross-segment traffic.

When available, the NAVV tool will use responses for queries found in Zeek's `dns.log` file to populate the `Src_Desc` and `Dest_Desc` fields in the `Analysis` tab. When DNS information is not available, it is possible to provide this information manually in the `Inventory` tab. Note that color formatting from the `Inventory` tab is applied **after** that from the `Segments` tab. Again, saving changes to the spreadsheet file and re-running the NAVV tool with the `-z` option will update the spreadsheet with the new inventory information and color formatting.

## <a name="Docker"></a>Docker

See [`docker/README.md`](./docker/README.md) for setup and instructions for running the NAVV tool in Docker.

## <a name="Footer"></a>Copyright

[NAVV](https://github.com/cisagov/network-architecture-verification-and-validation) is Copyright 2023 Battelle Energy Alliance, LLC, licensed under the BSD-3 Clause License.

See [`LICENSE`](./LICENSE) for the terms of its release.

Developers, by contributing to this software project, you are agreeing to the following terms and conditions for your contributions:

* You agree your contributions are submitted under the BSD 3-Clause license.
* You represent you are authorized to make the contributions and grant the license. If your employer has rights to intellectual property that includes your contributions, you represent that you have received permission to make contributions and grant the required license on behalf of that employer.

## Other software

Idaho National Laboratory is a cutting edge research facility which is constantly producing high quality research and software. Feel free to take a look at our other software and scientific offerings at:

* [Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)
* [Supported Open Source Software](https://github.com/cisagov)
* [Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)
* [Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

## <a name="Contact"></a>Contact information of maintainer(s):

[Seth Grover](mailto:seth.grover@inl.gov?subject=NAVV)
