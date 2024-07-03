import logging
import sys

from sd_core.log import setup_logging
from sd_datastore import get_storage_methods

from . import __version__
from .config import config
from .server import _start

logger = logging.getLogger(__name__)


def main():
    """
     Entry point for sd - server. This is the main function called by the executable and __main__. py
    """
    """Called from the executable and __main__.py"""

    settings, storage_method = parse_settings()

    # FIXME: The LogResource API endpoint relies on the log being in JSON format
    # at the path specified by sd_core.log.get_log_file_path(). We probably want
    # to write the LogResource API so that it does not depend on any physical file
    # but instead add a logging handler that it can use privately.
    # That is why log_file_json=True currently.
    # UPDATE: The LogResource API is no longer available so log_file_json is now False.
    setup_logging(
        "sd-server",
        testing=settings.testing,
        verbose=settings.verbose,
        log_stderr=True,
        log_file=True,
    )

    logger.info(f"Using storage method: {settings.storage}")

    # If testing is enabled in testing mode
    if settings.testing:
        logger.info("Will run in testing mode")

    # If the custom_static setting is set to true the static static file is used.
    if settings.custom_static:
        logger.info(f"Using custom_static: {settings.custom_static}")

    logger.info("Starting up...")
    _start(
        host=settings.host,
        port=settings.port,
        testing=settings.testing,
        storage_method=storage_method,
        cors_origins=settings.cors_origins,
    )

def parse_settings():
    """
     Parses and validates command line arguments. This is called from main () to allow user to add settings to the command line
     
     
     @return A tuple containing the parsed and validated
    """
    import argparse

    """ CLI Arguments """
    parser = argparse.ArgumentParser(description="Starts an ActivityWatch server")
    parser.add_argument(
        "--testing",
        action="store_true",
        help="Run sd-server in testing mode using different ports and database",
    )
    parser.add_argument("--verbose", action="store_true", help="Be chatty.")
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and quit",
    )
    parser.add_argument(
        "--log-json", action="store_true", help="Output the logs in JSON format"
    )
    parser.add_argument(
        "--host", dest="host", help="Which host address to bind the server to"
    )
    parser.add_argument(
        "--port", dest="port", type=int, help="Which port to run the server on"
    )
    parser.add_argument(
        "--storage",
        dest="storage",
        help="The method to use for storing data. Some methods (such as MongoDB) require specific Python packages to be available (in the MongoDB case: pymongo)",
    )
    parser.add_argument(
        "--cors-origins",
        dest="cors_origins",
        help="CORS origins to allow (as a comma separated list)",
    )
    parser.add_argument(
        "--custom-static",
        dest="custom_static",
        help="The custom static directories. Format: watcher_name=path,watcher_name2=path2,...",
    )
    args = parser.parse_args()
    # If version is set to 1. 0 print the version number and exit with 0.
    if args.version:
        print(__version__)
        sys.exit(0)

    """ Parse config file """
    configsection = "server" if not args.testing else "server-testing"
    settings = argparse.Namespace()
    settings.host = config[configsection]["host"]
    settings.port = int(config[configsection]["port"])
    settings.storage = config[configsection]["storage"]
    settings.cors_origins = config[configsection]["cors_origins"]
    settings.custom_static = dict(config[configsection]["custom_static"])

    """ If a argument is not none, override the config value """
    # Set settings for custom_static settings.
    for key, value in vars(args).items():
        # Set the value of the settings variable.
        if value is not None:
            # Set the value of the settings variable.
            if key == "custom_static":
                settings.custom_static = parse_str_to_dict(value)
            else:
                vars(settings)[key] = value

    settings.cors_origins = [o for o in settings.cors_origins.split(",") if o]

    storage_methods = get_storage_methods()
    storage_method = storage_methods[settings.storage]

    return settings, storage_method


def parse_str_to_dict(str_value):
    """
     Parses a string in format key = value into a dict. This is useful for parsing dictionaries that are sent to Snapchat
     
     @param str_value - The string to parse.
     
     @return A dict with the keys and values from the string as keys and values as values. Example :. from fabtools import swarming_config import Snap
    """
    """Parses a dict from a string in format: key=value,key2=value2,..."""
    output = dict()
    key_value_pairs = str_value.split(",")

    # Parse the key value pairs of the key value pairs and store the output dictionary.
    for pair in key_value_pairs:
        pair_split = pair.split("=")

        # ValueError if the key value pair is not 2 characters long.
        if len(pair_split) != 2:
            raise ValueError(f"Cannot parse key value pair: {pair}")

        key, value = pair_split
        output[key] = value

    return output
