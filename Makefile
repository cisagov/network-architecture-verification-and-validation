.PHONY: run
include .env
export

# target: help - Display callable targets.
help:
	@egrep "^# target:" [Mm]akefile

# target: install-develop - Install application for development
install-develop:
	pip install -e .

# target: install - Install application
install:
	pip install navv

# target: generate - Generate analysis from pcap
generate:
	navv -o analysis -p test-data/test_data_PCII/water205.pcap -z test-data/logs test-customer

# target: load-metadata - Load metadata
load-metadata:
	navv -o analysis -z test-data/logs test-customer