"""Return messages handler."""
# Third-Party Libraries
import click


def info_msg(text):
    """Informational message."""
    click.echo(click.style(text, fg="cyan"))


def success_msg(text):
    """Success message."""
    click.echo(click.style(text, fg="bright_green"))


def success_msg_via_pager(text):
    """Success message."""
    click.echo_via_pager(click.style(text, fg="green"))


def warning_msg(text):
    """Warning message."""
    click.echo(click.style(text, fg="yellow"))


def error_msg(text):
    """Error message."""
    click.echo(click.style(text, fg="red"))


def unknown_command():
    """Unknown command response."""
    click.echo("Sorry we didn't understand that command.")
