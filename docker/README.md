# Running NAVV in Docker

* [Building the Docker Image](#Build)
* [Running the NAVV Tool](#Run)
* [Exporting the Docker Image to Run on Another Host](#Export)
* [Using the Docker Image as a Build Environment](#BuildEnv)


## <a name="Build"></a>Building the Docker image

Run `./docker/build_docker.sh` to build the `ghcr.io/cisagov/network-architecture-verification-and-validation:latest` image. You can include `--force-rm --no-cache` to build the image from scratch without using any previously cached layers.

This build process doesn't require any previous building or configuration of the `navv` Python code: it's entirely self-contained.

```shell
$ ./docker/build_docker.sh --force-rm --no-cache
Sending build context to Docker daemon  6.873MB
Step 1/17 : FROM ubuntu:latest
…
Successfully tagged ghcr.io/cisagov/network-architecture-verification-and-validation:latest

$ docker images | head
REPOSITORY                                   TAG           IMAGE ID       CREATED          SIZE
navv                                    latest        xxxxxxxxxxxx   38 seconds ago   313MB
…
```

## <a name="Run"></a>Running the NAVV tool

The script `./docker/navv-docker.sh` is a convenient wrapper script to make running the NAVV tool in Docker easier by putting together the command line arguments to set up the docker bind mounts and running a `navv` container. Copy or symlink `./docker/navv-docker.sh` somewhere in your `$PATH` (e.g., `/usr/local/bin` or `~/.local/bin`).

Run `navv-docker.sh` with arguments like the ones you'd pass to `navv` natively, the only difference being that you'll need to use the short-form command line argument options instead of the long-form (e.g., use `-p` instead of `--pcap`).

```shell
$ navv-docker.sh -p /home/user/tmp/4SICS-GeekLounge-151020.pcap -o /home/user/tmp/logs ACME
WARNING: No Site::local_nets have been defined.  It's usually a good idea to define your local networks.
100%|██████████| 15139/15139 [00:00<00:00, 1191525.18it/s]
100%|██████████| 2590/2590 [00:01<00:00, 1510.21it/s]
…
Zeek returned with code: 0
…
Trimming DNS.log data:
Performing analysis(including lookups). This may take a while:
…

$ ls -l /home/user/tmp/logs/
total 4,157,440
-rw-rw-r-- 1 user user       155 Feb 19 11:40 ACME_dns_data.pkl
-rw-rw-r-- 1 user user   109,683 Feb 19 11:40 ACME_network_analysis.xlsx
-rw-rw-r-- 1 user user 1,946,035 Feb 19 11:40 conn.log
-rw-rw-r-- 1 user user 2,069,766 Feb 19 11:40 dns.log
-rw-rw-r-- 1 user user       233 Feb 19 11:40 known_hosts.log
-rw-rw-r-- 1 user user       554 Feb 19 11:40 known_services.log
-rw-rw-r-- 1 user user     1,165 Feb 19 11:40 ntp.log
-rw-rw-r-- 1 user user       254 Feb 19 11:40 packet_filter.log
-rw-rw-r-- 1 user user     2,859 Feb 19 11:40 weird.log
```

A default `local.zeek` file is included and built into the Docker image. Creating your own `local.zeek` file and placing it either (in order of precedence) in the current working directory or the directory containing `navv-docker.sh` will override the default `local.zeek` policy in favor of your custom version.

## <a name="Export"></a>Exporting the Docker image to run on another host

Use the script `./docker/backup_docker.sh`:

```shell
$ /home/user/navv/docker/backup_docker.sh
Transfer navv-docker_20210219_114718_59a26a647a3f.tar.gz and navv-docker.sh to destination host
Import ghcr.io/cisagov/network-architecture-verification-and-validation:latest with docker load -i navv-docker_20210219_114718_59a26a647a3f.tar.gz
Run with navv-docker.sh
```

Copy the files `navv-docker_########_######_xxxxxxxxxxxx.tar.gz` and `navv-docker.sh` to the destination host, then run `docker load -i` with the `.tar.gz` as an argument to import the image.

```shell
docker load -i navv-docker_20210219_114718_59a26a647a3f.tar.gz 
7a8aada2513d: Loading layer [==================================================>]  6.878MB/6.878MB
5c42a13ea084: Loading layer [==================================================>]  42.98MB/42.98MB
b62a2ff84161: Loading layer [==================================================>]  341.5kB/341.5kB
Loaded image: ghcr.io/cisagov/network-architecture-verification-and-validation:latest
```

Then use `navv-docker.sh` as described above.

## <a name="BuildEnv"></a>Using the Docker image as a build environment

It's possible to use the Docker image as a build environment from which the packaged NAVV Python library and its dependencies can be extracted for native installation on another system:

```shell
$ mkdir ./dist
$ docker run --rm --entrypoint=/bin/bash \
  -u $(id -u) \
  -v $(pwd)/dist:/dist \
  ghcr.io/cisagov/network-architecture-verification-and-validation:latest navv-build-for-export.sh
Collecting build
…
total 9.4M
-rw-r--r-- 1 analyst analyst 4.6K Jun 16 14:30 et_xmlfile-1.1.0-py3-none-any.whl
-rw-r--r-- 1 analyst analyst 6.6M Jun 16 14:30 lxml-4.6.3-cp38-cp38-manylinux2014_x86_64.whl
-rw-r--r-- 1 analyst analyst 661K Jun 16 14:30 navv-3.0.0-py3-none-any.whl
-rw-r--r-- 1 analyst analyst  16K Jun 16 14:30 navv-3.0.0.tar.gz
-rw-r--r-- 1 analyst analyst 1.9M Jun 16 14:30 netaddr-0.8.0-py2.py3-none-any.whl
-rw-r--r-- 1 analyst analyst 238K Jun 16 14:30 openpyxl-3.0.7-py2.py3-none-any.whl
-rw-r--r-- 1 analyst analyst  75K Jun 16 14:30 tqdm-4.61.1-py2.py3-none-any.whl
```
## <a name="Footer"></a>Copyright

[NAVV](https://github.com/cisagov/network-architecture-verification-and-validation) is Copyright 2023 Battelle Energy Alliance, LLC, licensed under the BSD-3 Clause License.

See [`LICENSE`](./LICENSE) for the terms of its release.