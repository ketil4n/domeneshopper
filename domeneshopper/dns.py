import argparse
import errno
import logging
import os
import pprint
import socket
import sys

import domeneshop

#Importing dotenv if available

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        LOG.debug('Missing recommended module python-dotenv')

#importing rich if available
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


def delete_record(domain_name, subdomain='www', ip='10.0.0.1', record_type='A', client=None):
    arg_errs = check_arguments(client, domain_name, ip, record_type, subdomain)

    if arg_errs:
        raise ValueError('. '.join(arg_errs))

    the_client = build_client() if not client else client

    LOG.debug('Loading domain %s', domain_name)
    domains = load_domains(the_client)

    main_domain = next((domain for domain in domains if domain['domain'] == domain_name), None)

    if not main_domain:
        raise FileNotFoundError('Did not find the domain {domain_name}'.format(domain_name=domain_name))

    records = the_client.get_records(main_domain['id'])
    LOG.debug('Found %s records for %s', len(records), domain_name)

    old_record = next((record for record in records if record['host'] == subdomain and record['type']==record_type), None)

    LOG.debug('Matching record is %s', old_record)
    if not old_record or old_record['data'] != ip:
        error_msg = '{domain_name} has no {record_type} record {subdomain} {ip} ({old_record})'.format(
            domain_name=domain_name,
            record_type=record_type,
            subdomain=subdomain,
            ip=ip,
            old_record='is '+ old_record['data'] if old_record and 'data' in old_record else '')

        LOG.error(error_msg)
        LOG.debug(old_record)
        raise FileNotFoundError(error_msg)
        return the_client

    domain_id = main_domain['id']
    record_id = old_record['id']

    try:
        delete_result = client.delete_record(domain_id=domain_id, record_id=record_id)
        LOG.debug('Delete returned "%s" (Will normally return None for some reason)', delete_result)
        return True
    except domeneshop.client.DomeneshopError as ex:
        LOG.error('Delete operation raised DomeneshopError.')
        return False
    return False


def create_record(domain_name, subdomain='www', ip='10.0.0.1', record_type='A', client=None):
    # Use a breakpoint in the code line below to debug your script.
    arg_errs = check_arguments(client, domain_name, ip, record_type, subdomain)

    if arg_errs:
        raise ValueError('. '.join(arg_errs))

    the_client = build_client() if not client else client

    LOG.debug('Loading domain %s', domain_name)
    domains = load_domains(the_client)

    main_domain = next((domain for domain in domains if domain['domain'] == domain_name), None)

    if not main_domain:
        raise FileNotFoundError('Did not find the domain {domain_name}'.format(domain_name=domain_name))

    records = the_client.get_records(main_domain['id'])
    LOG.debug('Found %s records for %s', len(records), domain_name)

    old_record = next((record for record in records if record['host'] == subdomain and record['type']==record_type), None)

    LOG.debug('Matching record is %s', old_record)
    if old_record:
        print('Record %s already exists', subdomain)
        print(old_record)
        raise FileExistsError('{domain_name} already has the {record_type} record {subdomain} ({old_record})'.format(
            domain_name=domain_name, record_type=record_type, subdomain=subdomain, old_record=old_record['data']))
        return the_client

    new_record = {'host': subdomain,
                  'ttl': 3600,
                  'type': record_type,
                  'data': ip}

    create_result = client.create_record(main_domain['id'], record=new_record)

    LOG.debug('Create returned "%s"', create_result)

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
        raise ValueError('Cannot continue without credentials. Missing {arg_errs}'.format(arg_errs=arg_errs))

    the_token = os.environ['DOMENESHOP_TOKEN'] if not token else token
    the_secret = os.environ['DOMENESHOP_SECRET'] if not secret else secret

    the_client = domeneshop.Client(token=the_token, secret=the_secret)

    return the_client


def check_arguments(client, domain_name, ip, record_type, subdomain):
    arg_errs = []
    LOG.debug('Checking arguments %s %s %s %s client set=%s',
              domain_name, subdomain, ip, record_type, client is not None)
    if not domain_name:
        arg_errs.append('domain_name is empty')
    if not subdomain:
        arg_errs.append('subdomain is empty')
    if not ip or not (is_valid_ipv4_address(ip) or is_valid_ipv6_address(ip)):
        arg_errs.append('{ip} is not a valid ip address'.format(ip=ip))
    elif record_type == 'A' and not is_valid_ipv4_address(ip):
        arg_errs.append('A {ip} is not a valid ipv4 address as required for record type A'.format(ip=ip))
    elif record_type == 'AAAA' and not is_valid_ipv6_address(ip):
        arg_errs.append('{ip} is not a valid ipv6 address as required for record type AAAA'.format(ip=ip))
    if record_type not in VALID_RECORD_TYPES:
        arg_errs.append('Only {valid_record_types} are valid for record_type'.format(
            valid_record_types=VALID_RECORD_TYPES))
    return arg_errs

