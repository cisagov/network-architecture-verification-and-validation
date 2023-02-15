#!/usr/bin/env bash

# Copyright 2023 Battelle Energy Alliance, LLC

# navv_docker.sh
#
# Wrapper script for running navv via Docker
# (see Dockerfile and build_docker.sh), setting up
# bind mounts appropriately for input (PCAP file or
# Zeek log directory) and output (Zeek .log files,
# .xlsx file and .pkl file)

set -o pipefail
set -u
set -e
shopt -s nullglob

ENCODING="utf-8"

# image name (can be overriden via NAVV_DOCKER_IMAGE env. var.)
NAVV_DOCKER_IMAGE="${NAVV_DOCKER_IMAGE:-ghcr.io/cisagov/network-architecture-verification-and-validation:latest}"
# container engine (docker vs. podman, can be overriden via CONTAINER_ENGINE env. var.)
CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"
if [[ "$CONTAINER_ENGINE" == "podman" ]]; then
  PUID=0
  PGID=0
else
  PUID=$(id -u)
  PGID=$(id -g)
fi

# run navv -h to get help
function print_usage() {
  $CONTAINER_ENGINE run --rm "$NAVV_DOCKER_IMAGE" -h | sed "s/\(options\):/\1 (use short option syntax for $CONTAINER_ENGINE):/" >&2
}

# figure out actual executable names for realpath, dirname and basename
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
[[ "$(uname -s)" = 'Darwin' ]] && BASENAME=gbasename || BASENAME=basename
if ! (type "$REALPATH" && type "$DIRNAME" && type "$BASENAME" && type $CONTAINER_ENGINE) > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH, $DIRNAME, $BASENAME and $CONTAINER_ENGINE"
  exit 1
fi

# evaluate/expand full path containing this script
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"

# get command-line options for this script which will be translated
# to command-line options for navv below

unset OUTPUT_DIR
unset PCAP_FILE
unset ZEEK_LOGS_DIR
unset CUSTOMER_NAME
unset SHOW_VERSION

while getopts 'vxeho:p:z:' OPTION; do
  case "$OPTION" in

    # show version and exit
    v)
      $CONTAINER_ENGINE run --rm \
        -e PUID=$(id -u) -e PGID=$(id -g) \
        "$NAVV_DOCKER_IMAGE" --version ACME
      exit 0
      ;;

    # enable verbose bash execution tracing
    x)
      set -x
      ;;

    # exit on any process error
    e)
      set -e
      ;;

    # run help and exit
    h)
      print_usage
      exit 0
      ;;

    # specify output directory
    o)
      OUTPUT_DIR="$OPTARG"
      ;;

    # specify PCAP file
    p)
      PCAP_FILE="$OPTARG"
      ZEEK_LOGS_DIR=""
      ;;

    # specify zeek logs directory
    z)
      ZEEK_LOGS_DIR="$OPTARG"
      PCAP_FILE=""
      ;;

    ?)
      print_usage
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

# at this point there should be ONE argument left and it's the customer name
if [[ $# -ne 1 ]]; then
  print_usage
  exit 1
fi
CUSTOMER_NAME="$1"

set +u

# if no output directory specified, output to the current directory
[[ -z $OUTPUT_DIR ]] && OUTPUT_DIR="$("$REALPATH" -e "$(pwd)")"
mkdir -p "$OUTPUT_DIR" >/dev/null 2>&1 || true

# if no PCAP file and no Zeek logs directory specified try to guess what was intended
if [[ -z $PCAP_FILE ]] && [[ -z $ZEEK_LOGS_DIR ]]; then
  PCAP_FILE=""
  ZEEK_LOGS_DIR=""
  logfiles=( *.log )
  if (( ${#logfiles[@]} > 0 )); then
    # there are SOME zeek logs here, assume -z pwd
    ZEEK_LOGS_DIR="$("$REALPATH" -e "$(pwd)")"
  else
    pcapfiles=( *.pcap )
    if (( ${#pcapfiles[@]} == 1 )); then
      # there is ONE PCAP file here, assume that PCAP file
      PCAP_FILE="$($REALPATH -e "${pcapfiles[0]}")"
    fi
  fi
fi

set -u

# set up bind mounts for input and output directories

MOUNT_ARGS=()
IN_ARGS=()
OUT_ARGS=()

if [[ -n $PCAP_FILE ]] && [[ -r "$PCAP_FILE" ]]; then
  # mount directory containing PCAP file as /input and pass -p to navv
  PCAP_BASE="$($BASENAME "$PCAP_FILE")"
  PCAP_PATH="$($DIRNAME "$($REALPATH -e "$PCAP_FILE")")"
  MOUNT_ARGS+=( -v )
  MOUNT_ARGS+=( "$PCAP_PATH:/input" )
  IN_ARGS+=( -p )
  IN_ARGS+=( "/input/$PCAP_BASE" )

elif [[ -n $ZEEK_LOGS_DIR ]] && [[ -d "$ZEEK_LOGS_DIR" ]]; then
  # mount directory containing Zeek logs as /input and pass -z to navv
  MOUNT_ARGS+=( -v )
  MOUNT_ARGS+=( "$($REALPATH -e "$ZEEK_LOGS_DIR"):/input" )
  IN_ARGS+=( -z )
  IN_ARGS+=( "/input" )
fi

if [[ -d "$OUTPUT_DIR" ]]; then
  # mount directory to contain output files as /output
  MOUNT_ARGS+=( -v )
  MOUNT_ARGS+=( "$($REALPATH -e "$OUTPUT_DIR"):/output" )
  OUT_ARGS+=( -o )
  OUT_ARGS+=( "/output" )
fi

# if there is a local.zeek file 1) here or 2) in the script directory,
# use that instead of the default one in the image
if [[ -r local.zeek ]]; then
  MOUNT_ARGS+=( -v )
  MOUNT_ARGS+=( "$($REALPATH -e "local.zeek"):/opt/zeek/share/zeek/site/local.zeek:ro" )
elif [[ -r "$SCRIPT_PATH"/local.zeek ]]; then
  MOUNT_ARGS+=( -v )
  MOUNT_ARGS+=( "$SCRIPT_PATH/local.zeek:/opt/zeek/share/zeek/site/local.zeek:ro" )
fi

# run a navv container and remove it when it finishes
$CONTAINER_ENGINE run --rm \
  -e PUID=$PUID -e PGID=$PUID \
  -w /output \
  "${MOUNT_ARGS[@]}" \
  "$NAVV_DOCKER_IMAGE" \
  "${IN_ARGS[@]}" \
  "${OUT_ARGS[@]}" \
  "$CUSTOMER_NAME"
