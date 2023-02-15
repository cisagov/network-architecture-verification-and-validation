FROM ubuntu:22.04

# Copyright 2023 Battelle Energy Alliance, LLC

LABEL maintainer="seth.grover@inl.gov"
LABEL org.opencontainers.image.authors='seth.grover@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/network-architecture-verification-and-validation'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/network-architecture-verification-and-validation/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/network-architecture-verification-and-validation'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='cisagov/network-architecture-verification-and-validation'
LABEL org.opencontainers.image.description='The NAVV (Network Architecture Verification and Validation) tool'

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

# Environment variables for dropping privileges from root
# to an unprivileged user for running the script.
# Overriding the environment variables PUID and PGID
# at runtime will be detected by the docker-uid-gid-setup.sh
# entrypoint and processes will be run (and files created)
# with the appropriate ownership.
ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "analyst"
ENV PGROUP "analyst"
ENV PUSER_PRIV_DROP true

# install OS dependencies for navv python3 package build, and Zeek LTS
RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
      curl \
      gnupg2 \
      python3-pip \
      python3-setuptools \
      python3-venv \
      python3-wheel && \
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null && \
    apt-get -q update && \
    apt-get install -q -y --no-install-recommends zeek-lts && \
    ln -s -r /opt/zeek/bin/zeek /usr/local/bin/ && \
    ln -s -r /opt/zeek/bin/zeek-cut /usr/local/bin/ && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# include zeek binaries in PATH
ENV ZEEK_DIR "/opt/zeek"
ENV PATH "${ZEEK_DIR}/bin:${PATH}"

# build and install navv python3 package
ADD . /usr/local/src/navv
RUN python3 -m pip install --no-cache-dir /usr/local/src/navv && \
    cp -v /usr/local/src/navv/docker/local.zeek /opt/zeek/share/zeek/site/local.zeek && \
      chmod 644 /opt/zeek/share/zeek/site/local.zeek && \
    cp -v /usr/local/src/navv/docker/docker-uid-gid-setup.sh \
          /usr/local/src/navv/docker/navv-build-for-export.sh \
        /usr/local/bin/ && \
      chmod 755 /usr/local/bin/docker-uid-gid-setup.sh /usr/local/bin/navv-build-for-export.sh && \
    rm -rf /tmp/* /var/tmp/*

# create unprivileged default user
RUN groupadd --gid ${DEFAULT_GID} ${PUSER} && \
    useradd --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /home/${PUSER} ${PUSER} && \
    usermod -a -G tty ${PUSER} && \
    mkdir -p /home/${PUSER} /dist && \
    chown ${DEFAULT_UID}:${DEFAULT_GID} /home/${PUSER} /dist && \
    chmod 755 /home/${PUSER} /dist

# entrypoint to drop privileges to non-privileged user and run navv
ENTRYPOINT [ "/usr/local/bin/docker-uid-gid-setup.sh", "/usr/bin/python3", "-m", "navv" ]
