import argparse
import errno
import logging
import os
import socket

import domeneshop

#Importing dotenv if available

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv():
        LOG.debug('Missing recommended module python-dotenv')

#importing rich if available
try:
    from rich import print
    import rich.traceback
    from rich.logging import RichHandler
    print_exception = rich.console.Console().print_exception
    LOG_FORMAT = '%(message)s'
except ModuleNotFoundError:
    LOG_FORMAT = "[%(levelname)s:%(filename)s:%(lineno)s - %(funcName)20s ] %(message)s"
    RichHandler = logging.StreamHandler
    print_exception = print


LOG = logging.getLogger(__name__)
VALID_RECORD_TYPES = ['A', 'AAAA']


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def create_record(domain_name, subdomain='www', ip='10.0.0.1', record_type='A', client=None):
    # Use a breakpoint in the code line below to debug your script.
    arg_errs = check_arguments(client, domain_name, ip, record_type, subdomain)

    if arg_errs:
        raise ValueError('. '.join(arg_errs))

    the_client = build_client() if not client else client

    LOG.debug(f'Loading domain {domain_name}')
    domains = load_domains(the_client)

    main_domain = next((domain for domain in domains if domain['domain'] == domain_name), None)

    if not main_domain:
        raise FileNotFoundError(f'Did not find the domain {domain_name}')

    records = the_client.get_records(main_domain['id'])
    LOG.debug(f'Found {len(records)} records for {domain_name}')

    old_record = next((record for record in records if record['host'] == subdomain and record['type']==record_type), None)

    LOG.debug(f'Matching record is {old_record}')
    if old_record:
        print(f'Record {subdomain} already exists')
        print(old_record)
        raise FileExistsError(f'{domain_name} already has the {record_type} record {subdomain} ({old_record["data"]})')
        return the_client

    new_record = {'host': subdomain,
                  'ttl': 3600,
                  'type': record_type,
                  'data': ip}

    create_result = client.create_record(main_domain['id'], record=new_record)

    LOG.debug(f'Create returned "{create_result}"')

    if create_result:
        return True
    return False


def load_domains(client=None):
    the_client = client if client else build_client()
    if not the_client:
        raise ValueError('domeneshop.Client cannot be None')

    domains = the_client.get_domains()

    return domains


def build_client(token=None, secret=None):
    LOG.debug('Building client for domene.shop')
    load_dotenv()
    arg_errs = []
    if not token and 'DOMENESHOP_TOKEN' not in os.environ:
        arg_errs.append('DOMENESHOP_TOKEN')
    if not secret and 'DOMENESHOP_SECRET' not in os.environ:
        arg_errs.append('DOMENESHOP_SECRET')
    if arg_errs:
        raise ValueError(f'Cannot continue without credentials. Missing {arg_errs}')

    the_token = os.environ['DOMENESHOP_TOKEN'] if not token else token
    the_secret = os.environ['DOMENESHOP_SECRET'] if not secret else secret

    the_client = domeneshop.Client(token=the_token, secret=the_secret)

    return the_client


def check_arguments(client, domain_name, ip, record_type, subdomain):
    arg_errs = []
    LOG.debug(f'Checking arguments {domain_name} {subdomain} {ip} {record_type} client set={client is not None}')
    if not domain_name:
        arg_errs.append('domain_name is empty')
    if not subdomain:
        arg_errs.append('subdomain is empty')
    if not ip or not (is_valid_ipv4_address(ip) or is_valid_ipv6_address(ip)):
        arg_errs.append(f'{ip} is not a valid ip address')
    elif record_type == 'A' and not is_valid_ipv4_address(ip):
        arg_errs.append(f'A {ip} is not a valid ipv4 address as required for record type A')
    elif record_type == 'AAAA' and not is_valid_ipv6_address(ip):
        arg_errs.append(f'{ip} is not a valid ipv6 address as required for record type AAAA')
    if record_type not in VALID_RECORD_TYPES:
        arg_errs.append(f'Only {VALID_RECORD_TYPES} are valid for record_type')
    return arg_errs

