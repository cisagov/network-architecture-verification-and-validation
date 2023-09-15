# NAVV #

The **NAVV** (**N**etwork **A**rchitecture **V**erification and **V**alidation) tool creates a spreadsheet for network traffic analysis from PCAP data and Zeek logs, automating Zeek analysis of PCAP files and the collation of Zeek logs to create a summary or network traffic in an XLSX-formatted spreadsheet. After manually updating the spreadsheet with names and color codes for network segments (by CIDR-formatted address groups) and hosts (by IP address), running the tool again will integrate these labels and color coding into the spreadsheet to aid in conducting an evaluation of the network traffic. 

* [Requirements](#Requirements)
* [Installation](#Installation)
    * [Development](#Development)
    * [Production](#Production)
* [Usage](#Usage)
    * [Running NAVV](#Running)
    * [Identifying network segments and hosts](#Analysis)
* [Docker](#Docker)
* [Copyright](#Footer)
* [Contact](#Contact)

[![PyPI Release](https://img.shields.io/pypi/v/navv)](https://pypi.python.org/pypi/navv/)
[![Docker Image](https://github.com/cisagov/network-architecture-verification-and-validation/workflows/navv-build-push-ghcr/badge.svg)](https://github.com/cisagov/network-architecture-verification-and-validation/actions)

## Requirements ##

- This project only works on Linux or MacOS environments
- Zeek must be installed: [Get Zeek](https://zeek.org/get-zeek/)
- Python version 3.10 or later
  - As installation of Python varies from platform to platform, please consult your operating system's documentation or the [python.org Wiki](https://wiki.python.org/moin/BeginnersGuide/Download) to install and configure Python on your system.

## Installation ##

### Development ###

If you intend to develop the NAVV tool:
- Verify you have the Zeek tool installed
  - [Install Zeek](https://zeek.org/get-zeek/)
- Clone this repository
  - `git clone https://github.com/cisagov/network-architecture-verification-and-validation.git`
- Setup your locally virtual environment
  - `python3 -m venv .venv`
- Activate your local environment
  - `source .venv/bin/activate`
- Install the project and its dependencies to your local virtual environment
  - `pip install -e .`

### Production ###

If you would like to use the NAVV tool, its recommended you install from PYPI
- Verify you have the Zeek tool installed
  - [Install Zeek](https://zeek.org/get-zeek/)
- Simply install the project using `pip`
  - install the latest version of NAVV
    - `pip install -U navv`
  - install a specific version of NAVV
    - example:  `pip install -U navv==3.0.1`
  - The recommended method for installing packages with `pip` is using [User Installs](https://pip.pypa.io/en/stable/user_guide/#user-installs) which installs to a user-specific location rather than system-wide.

Verify the NAVV tool has been installed by running `navv` in your console:

```shell
NAVV: Network Architecture Verification and Validation 3.2.2
Usage: navv [OPTIONS] COMMAND [ARGS]...

  Network Architecture Verification and Validation.

Options:
  --version   Show the version and exit.
  -h, --help  Show this message and exit.

Commands:
  generate  Generate excel sheet.
  launch    Launch the NAVV GUI.
```

## Usage ##

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

[Donovan Nichols](mailto:donovan.nichols@inl.gov?subject=NAVV)
