import argparse
import errno
import logging
import os
import sys

import domeneshop


import domeneshopper.dns
# Importing dotenv if available

# importing rich if available
try:
    from rich import print
    import rich.traceback
    from rich.logging import RichHandler
    print_exception = rich.console.Console().print_exception
    LOG_FORMAT = '%(message)s'
except ImportError:
    LOG_FORMAT = "[%(levelname)s:%(filename)s:%(lineno)s - %(funcName)20s ] %(message)s"
    RichHandler = logging.StreamHandler
    print_exception = print


LOG = logging.getLogger(__name__)


def build_arguments(secret_help, token_help, usage_help):
    arg_parser = argparse.ArgumentParser(prog='domeneshopper',
                                         usage=usage_help,
                                         description='Create new records on domene.shop')
    arg_parser.add_argument("--debug", action="store_true")
    arg_parser.add_argument("--pprint", action="store_true")
    arg_parser.add_argument("--token", type=str, default=None, help=token_help)
    arg_parser.add_argument("--secret", type=str, default=None, help=secret_help)
    arg_parser.add_argument("function", type=str,
                            choices=['create'], default='create')
    arg_parser.add_argument("domain", type=str)
    arg_parser.add_argument("ip", nargs='?', default=None, type=str)
    arg_parser.add_argument("type", nargs='?', type=str,
                            choices=domeneshopper.dns.VALID_RECORD_TYPES,
                            default=domeneshopper.dns.VALID_RECORD_TYPES[0])
    arguments = arg_parser.parse_args()
    return arguments


def main():
    token_help = "Will use environment variable DOMENESHOP_TOKEN{token_found} by default"
    secret_help = "Will use environement variable DOMENESHOP_SECRET{secret_found} by default"
    usage_help = '%(prog)s [options] create subdomain.domain.name ip-address record-type'

    log_format = LOG_FORMAT
    logging.basicConfig(level=logging.INFO if "--debug" not in sys.argv else logging.DEBUG, format=log_format,
                        handlers=[RichHandler()])

    domeneshopper.dns.load_dotenv()
    found_secret = '(not found)' if 'DOMENESHOP_SECRET' not in os.environ else ''
    found_token = '(not found)' if 'DOMENESHOP_TOKEN' not in os.environ else ''

    arguments = build_arguments(secret_help.format(secret_found=found_secret), token_help.format(token_found=found_token), usage_help)

    try:
        client = domeneshopper.dns.build_client(token=arguments.token, secret=arguments.secret)

        domain = '.'.join(arguments.domain.split('.')[1:])
        subdomain = arguments.domain.split('.')[0]

        LOG.debug('{subdomain} {domain}'.format(subdomain, domain))

        create_result = domeneshopper.dns.create_record(domain_name=domain, subdomain=subdomain, ip=arguments.ip, record_type=arguments.type, client=client)
    except domeneshop.client.DomeneshopError as err:
        print(str(err), file=sys.stderr)
        sys.exit(errno.EREMOTEIO)
    except FileNotFoundError as err:
        print('[red]{}[/red]'.format(str(err)), file=sys.stderr)
        sys.exit(errno.ENOENT)
    except FileExistsError as err:
        print(str(err), file=sys.stderr)
        sys.exit(errno.EEXIST)
    except ValueError as err:
        print(str(err), file=sys.stderr)
        sys.exit(errno.EINVAL)
    except Exception as err:
        import rich.console
        print_exception()
        sys.exit(errno.EPERM)

    if not create_result:
        sys.exit(errno.EIO)

    return client


client = None
if __name__ == '__main__':
    client = main()