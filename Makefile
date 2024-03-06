.PHONY: generate launch

include .env
export

# target: help - Display callable targets.
help:
	@egrep "^# target:" [Mm]akefile

# target: install-develop - Install application for development
install-develop:
	python3 -m pip install -e .

# target: install - Install production application
install:
	python3 -m pip install navv

# target: generate - Generate analysis excel sheet
# optionally set PCAP_PATH to a relative pcap file path
# example: make generate PCAP_PATH=test-path/to/file.pcap
generate:
	navv generate -o analysis -z test-data/logs test-customer $(if $(PCAP_PATH), -p $(PCAP_PATH))

# target: launch - Launch GUI application
launch:
	navv launch
