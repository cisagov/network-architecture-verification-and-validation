#!/usr/bin/env python3

# Copyright 2023 Battelle Energy Alliance, LLC

# python std library imports
import pkg_resources

# third party imports
import click

# package imports
from navv.commands import generate, launch
from navv.message_handler import info_msg
from navv._version import __version__


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
HEADER = f"NAVV: Network Architecture Verification and Validation {__version__}"
DATA_PATH = pkg_resources.resource_filename("navv", "data/")


@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.version_option(__version__)
@click.pass_context
def cli(ctx):
    """Network Architecture Verification and Validation."""
    if ctx.invoked_subcommand is None:
        info_msg(HEADER)
        print(ctx.command.get_help(ctx))
    pass


def main():
    """Main function for performing zeek-cut commands and sorting the output"""

    cli.add_command(generate)
    cli.add_command(launch)
    cli()


if __name__ == "__main__":
    main()
