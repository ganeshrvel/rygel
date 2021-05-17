#!/bin/env python3

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see https://www.gnu.org/licenses/.

import argparse
import configparser
import hashlib
import io
import itertools
import json
import os
import re
import shutil
import sys
import subprocess
from dataclasses import dataclass

@dataclass
class DomainConfig:
    directory = None
    socket = None
    mismatch = False

@dataclass
class ServiceStatus:
    running = False
    inode = None

def parse_ini(filename, allow_no_value = False):
    ini = configparser.ConfigParser(allow_no_value = allow_no_value)
    ini.optionxform = str

    with open(filename, 'r') as f:
        ini.read_file(f)

    return ini

def load_config(filename):
    ini = parse_ini(filename, allow_no_value = True)
    config = {}

    for section in ini.sections():
        for key, value in ini.items(section):
            if not section in config:
                config[section] = {}
            config[section][key] = value

            name = f'{section}.{key}'
            config[name] = value

    return config

def execute_command(args):
    subprocess.run(args, check = True)

def commit_file(filename, data):
    try:
        with open(filename, 'rb') as f:
            m = hashlib.sha256()
            for chunk in iter(lambda: f.read(4096), b""):
                m.update(chunk)
            hash1 = m.digest()
    except Exception:
        hash1 = None

    data = data.encode('UTF-8')
    m = hashlib.sha256()
    m.update(data)
    hash2 = m.digest()

    if hash1 != hash2:
        with open(filename, 'wb') as f:
            f.write(data)
        return True
    else:
        return False

def list_domains(root_dir, names):
    domains = {}

    for domain in names:
        directory = os.path.join(root_dir, domain)
        filename = os.path.join(directory, 'goupile.ini')

        if os.path.isfile(filename):
            config = load_config(filename)

            info = DomainConfig()
            info.directory = directory
            info.socket = f'/run/goupile/{domain}.sock'

            prev_socket = config.get('HTTP.UnixPath')
            if prev_socket != info.socket:
                info.mismatch = True

            domains[domain] = info

    return domains

def create_domain(binary, root_dir, domain, backup_key,
                  owner_user, owner_group, admin_username, admin_password):
    directory = os.path.join(root_dir, domain)
    print(f'>>> Create domain {domain} ({directory})', file = sys.stderr)

    execute_command([binary, 'init', '-o', owner_user, '--backup_key', backup_key,
                     '--username', admin_username, '--password', admin_password, directory])

def migrate_domain(binary, domain, info):
    print(f'>>> Migrate domain {domain} ({info.directory})', file = sys.stderr)
    filename = os.path.join(info.directory, 'goupile.ini')
    execute_command([binary, 'migrate', '-C', filename])

    # Does not hurt safety
    os.chmod(info.directory, 0o700)

def list_services():
    services = {}

    output = subprocess.check_output(['systemctl', 'list-units', '--type=service', '--all'])
    output = output.decode()

    for line in output.splitlines():
        parts = re.split(' +', line)

        if len(parts) >= 4:
            match = re.search('^goupile@([0-9A-Za-z_\\-\\.]+)\\.service$', parts[1])

            if match is not None:
                name = match.group(1)

                status = ServiceStatus()
                status.running = (parts[3] == 'active')

                if status.running:
                    try:
                        pid = int(subprocess.check_output(['systemctl', 'show', '-p', 'ExecMainPID', '--value', parts[1]]))

                        sb = os.stat(f'/proc/{pid}/exe')
                        status.inode = sb.st_ino
                    except Exception:
                        status.running = False

                services[name] = status

    return services

def run_service_command(domain, cmd):
    service = f'goupile@{domain}.service'
    print(f'>>> {cmd.capitalize()} {service}', file = sys.stderr)
    execute_command(['systemctl', cmd, '--quiet', service])

def list_system_libraries(binary):
    output = subprocess.check_output(['ldd', binary])
    output = output.decode()

    libraries = []
    for line in output.splitlines():
        match = re.search('(?:=> )?(\\/.*) \\(0x[0-9abcdefABCDEF]+\\)$', line)
        if match is not None:
            libraries.append(match.group(1))

    return libraries

def update_domain_config(info, backup_key, smtp, sms):
    filename = os.path.join(info.directory, 'goupile.ini')
    ini = parse_ini(filename)

    ini.set('Data', 'BackupKey', backup_key)

    if not ini.has_section('HTTP'):
        ini.add_section('HTTP')
    ini.set('HTTP', 'SocketType', 'Unix')
    ini.set('HTTP', 'UnixPath', info.socket)
    ini.set('HTTP', 'TrustXRealIP', 'On')
    ini.remove_option('HTTP', 'Port')

    ini.remove_section('SMTP')
    if smtp is not None:
        ini.add_section('SMTP')
        for key, value in smtp.items():
            ini.set('SMTP', key, value)

    ini.remove_section('SMS')
    if sms is not None:
        ini.add_section('SMS')
        for key, value in sms.items():
            ini.set('SMS', key, value)

    with io.StringIO() as f:
        ini.write(f)
        return commit_file(filename, f.getvalue())

def run_sync(config):
    binary = os.path.join(config['Goupile.BinaryDirectory'], 'goupile')

    # Create missing domains
    for domain, backup_key in config['Domains'].items():
        directory = os.path.join(config['Goupile.DomainDirectory'], domain)
        if not os.path.exists(directory):
            create_domain(binary, config['Goupile.DomainDirectory'], domain, backup_key,
                          config['Goupile.RunUser'], config['Goupile.RunGroup'],
                          config['Goupile.DefaultAdmin'], config['Goupile.DefaultPassword'])

    # List existing domains and services
    domains = list_domains(config['Goupile.DomainDirectory'], config['Domains'].keys())
    services = list_services()

    # Detect binary mismatches
    binary_inode = os.stat(binary).st_ino
    for domain, info in domains.items():
        status = services.get(domain)
        if status is not None and status.running and status.inode != binary_inode:
            print(f'+++ Domain {domain} is running old version')
            info.mismatch = True

    changed = False

    # Update instance configuration files
    print('>>> Write Goupile configuration files', file = sys.stderr)
    for domain, info in domains.items():
        backup_key = config['Domains'][domain]
        smtp = config.get('SMTP')
        sms = config.get('SMS')
        if update_domain_config(info, backup_key, smtp, sms):
            info.mismatch = True
            changed = True

    # Sync systemd services
    for domain in services:
        info = domains.get(domain)
        if info is None:
            run_service_command(domain, 'stop')
            run_service_command(domain, 'disable')
            changed = True
    for domain, info in domains.items():
        status = services.get(domain)
        if status is None:
            run_service_command(domain, 'enable')
        if status is None or info.mismatch or not status.running:
            run_service_command(domain, 'stop')
            migrate_domain(binary, domain, info)
            run_service_command(domain, 'start')
            changed = True

    # Nothing changed!
    if not changed:
        print('>>> Nothing has changed', file = sys.stderr)
        return

if __name__ == '__main__':
    # Always work from sync.py directory
    script = os.path.abspath(__file__)
    directory = os.path.dirname(script)
    os.chdir(directory)

    # Parse configuration
    config = load_config('sync.ini')
    config['Goupile.BinaryDirectory'] = os.path.abspath(config['Goupile.BinaryDirectory'])
    config['Goupile.DomainDirectory'] = os.path.abspath(config['Goupile.DomainDirectory'])

    run_sync(config)