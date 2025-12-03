# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 s3rj1k

"""Custom deployment hardware manager."""

import json
import os
import random
import stat
import subprocess
import tempfile
import time
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.parse import urlunparse

from oslo_log import log
import requests

from ironic_python_agent import device_hints
from ironic_python_agent import hardware

LOG = log.getLogger(__name__)

CUSTOM_DEPLOY_KEY = 'custom_deploy'
DEFAULT_MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_VERIFY_SSL = True
DEFAULT_RETRY_DELAY_BASE = 2
DEFAULT_RETRY_DELAY_JITTER = 2
DEFAULT_SCRIPT_TEMP_PREFIX = 'custom_deploy'
DEFAULT_DEBUG_SLEEP_DURATION = 0
HTTP_PREFIX = 'http://'
HTTPS_PREFIX = 'https://'
HTTPS_SELFSIGNED_PREFIX = 'https+selfsigned://'
FILE_PREFIX = 'file://'


def parse_cmdline_debug_sleep_duration():
    """Parse kernel cmdline for debug sleep duration.

    Looks for ipa.debug_sleep_duration parameter.

    :returns: Integer duration in seconds, or None if not found in cmdline.
    """
    try:
        with open('/proc/cmdline', 'r', encoding='utf-8') as f:
            cmdline = f.read().strip()
    except (OSError, IOError) as e:
        LOG.info('Failed to read /proc/cmdline: %s', e)
        return None

    for param in cmdline.split():
        if param.startswith('ipa.debug_sleep_duration='):
            try:
                duration = int(param.split('=', 1)[1])
                if duration < 0:
                    LOG.warning('Invalid ipa.debug_sleep_duration: '
                                'must be non-negative')
                    return None
                LOG.info('Parsed cmdline debug sleep duration: %s', duration)
                return duration
            except ValueError as e:
                LOG.warning('Invalid ipa.debug_sleep_duration value: %s', e)
                return None

    return None


def has_interactive_users():
    """Check if there are any interactive users logged in.

    :returns: Boolean indicating if interactive users are logged in
    """
    try:
        result = subprocess.run(
            ['who'],
            capture_output=True,
            text=True,
            check=True,
            timeout=5)

        # who returns empty output if no users are logged in
        users = result.stdout.strip()
        if users:
            LOG.debug('Interactive users detected: %s', users)
            return True
        return False
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            OSError) as e:
        LOG.warning('Failed to check for interactive users: %s', e)
        return False


def get_configdrive_data(node):
    """Extract configdrive data from node instance_info.

    :param node: Node dictionary containing instance_info
    :returns: Dictionary containing configdrive data
    :raises: ValueError if node is invalid or configdrive data is missing
    """
    if node is None:
        raise ValueError('Node cannot be None')
    if not isinstance(node, dict):
        raise ValueError('Node must be a dictionary')

    instance_info = node.get('instance_info', {})
    if not isinstance(instance_info, dict):
        raise ValueError('instance_info must be a dictionary')

    configdrive = instance_info.get('configdrive')
    if configdrive is None:
        raise ValueError('configdrive not found in instance_info')

    if not isinstance(configdrive, dict):
        raise ValueError('configdrive must be a dictionary')

    LOG.info('Extracted configdrive data: %s', configdrive)
    return configdrive


def get_custom_deploy_value(configdrive_data):
    """Extract custom_deploy value from configdrive metadata.

    :param configdrive_data: Dictionary containing configdrive data
    :returns: Value of custom_deploy key from meta_data
    :raises: ValueError if configdrive_data is invalid or custom_deploy missing
    """
    if configdrive_data is None:
        raise ValueError('configdrive_data cannot be None')

    if not isinstance(configdrive_data, dict):
        raise ValueError('configdrive_data must be a dictionary')

    meta_data = configdrive_data.get('meta_data')
    if meta_data is None:
        raise ValueError('meta_data not found in configdrive')

    if not isinstance(meta_data, dict):
        raise ValueError('meta_data must be a dictionary')

    custom_deploy_value = meta_data.get(CUSTOM_DEPLOY_KEY)
    if custom_deploy_value is None:
        raise ValueError(f'{CUSTOM_DEPLOY_KEY} not found in meta_data')

    LOG.info('Extracted %s value: %s', CUSTOM_DEPLOY_KEY, custom_deploy_value)
    return custom_deploy_value


def get_metal3_name(configdrive_data):
    """Extract metal3-name from configdrive metadata.

    :param configdrive_data: Dictionary containing configdrive data
    :returns: String containing metal3-name value
    :raises: ValueError if configdrive_data is invalid or metal3-name missing
    """
    if configdrive_data is None:
        raise ValueError('configdrive_data cannot be None')

    if not isinstance(configdrive_data, dict):
        raise ValueError('configdrive_data must be a dictionary')

    meta_data = configdrive_data.get('meta_data')
    if meta_data is None:
        raise ValueError('meta_data not found in configdrive')

    if not isinstance(meta_data, dict):
        raise ValueError('meta_data must be a dictionary')

    metal3_name = meta_data.get('metal3-name')
    if metal3_name is None:
        raise ValueError('metal3-name not found in meta_data')

    if not isinstance(metal3_name, str):
        raise ValueError('metal3-name must be a string')

    LOG.info('Extracted metal3-name: %s', metal3_name)
    return metal3_name


def get_metal3_namespace(configdrive_data):
    """Extract metal3-namespace from configdrive metadata.

    :param configdrive_data: Dictionary containing configdrive data
    :returns: String containing metal3-namespace value
    :raises: ValueError if configdrive_data is invalid or
        metal3-namespace missing
    """
    if configdrive_data is None:
        raise ValueError('configdrive_data cannot be None')

    if not isinstance(configdrive_data, dict):
        raise ValueError('configdrive_data must be a dictionary')

    meta_data = configdrive_data.get('meta_data')
    if meta_data is None:
        raise ValueError('meta_data not found in configdrive')

    if not isinstance(meta_data, dict):
        raise ValueError('meta_data must be a dictionary')

    metal3_namespace = meta_data.get('metal3-namespace')
    if metal3_namespace is None:
        raise ValueError('metal3-namespace not found in meta_data')

    if not isinstance(metal3_namespace, str):
        raise ValueError('metal3-namespace must be a string')

    LOG.info('Extracted metal3-namespace: %s', metal3_namespace)
    return metal3_namespace


def get_root_device(node):
    """Extract root_device from node instance_info.

    :param node: Node dictionary containing instance_info
    :returns: Dictionary containing root_device data
    :raises: ValueError if node is invalid or root_device is missing
    """
    if node is None:
        raise ValueError('Node cannot be None')
    if not isinstance(node, dict):
        raise ValueError('Node must be a dictionary')

    instance_info = node.get('instance_info', {})
    if not isinstance(instance_info, dict):
        raise ValueError('instance_info must be a dictionary')

    root_device = instance_info.get('root_device')
    if root_device is None:
        raise ValueError('root_device not found in instance_info')

    if not isinstance(root_device, dict):
        raise ValueError('root_device must be a dictionary')

    LOG.info('Extracted root_device data: %s', root_device)
    return root_device


def get_boot_mode(node):
    """Extract boot_mode from node, with fallback to /sys detection.

    :param node: Node dictionary
    :returns: String containing boot mode value ('uefi' or 'bios')
    :raises: ValueError if node is invalid
    """
    if node is None:
        raise ValueError('Node cannot be None')
    if not isinstance(node, dict):
        raise ValueError('Node must be a dictionary')

    boot_mode = node.get('boot_mode')

    if boot_mode is None or not isinstance(boot_mode, str):
        # Fallback: detect boot mode from /sys/firmware/efi
        if boot_mode is not None:
            LOG.warning('boot_mode must be a string, got %s, '
                        'falling back to detection',
                        type(boot_mode).__name__)

        if os.path.exists('/sys/firmware/efi'):
            boot_mode = 'uefi'
        else:
            boot_mode = 'bios'
        LOG.info('boot_mode detected from /sys: %s', boot_mode)
    else:
        LOG.info('Extracted boot_mode from node: %s', boot_mode)

    return boot_mode


def get_secure_boot(node):
    """Extract secure_boot from node.

    :param node: Node dictionary
    :returns: Boolean containing secure boot value (defaults to False)
    :raises: ValueError if node is invalid
    """
    if node is None:
        raise ValueError('Node cannot be None')
    if not isinstance(node, dict):
        raise ValueError('Node must be a dictionary')

    secure_boot = node.get('secure_boot', False)

    if not isinstance(secure_boot, bool):
        LOG.warning('secure_boot must be a boolean, got %s, '
                    'defaulting to False',
                    type(secure_boot).__name__)
        secure_boot = False

    LOG.info('Extracted secure_boot: %s', secure_boot)
    return secure_boot


def get_pxe_mac_address(ports):
    """Extract MAC address from first PXE-enabled port.

    :param ports: List of port dictionaries
    :returns: String containing MAC address, or None if no PXE-enabled port
    :raises: ValueError if ports is invalid
    """
    if ports is None:
        raise ValueError('Ports cannot be None')

    if not isinstance(ports, list):
        raise ValueError('Ports must be a list')

    if not ports:
        LOG.warning('Ports list is empty, no PXE MAC address available')
        return None

    for port in ports:
        if not isinstance(port, dict):
            continue

        if port.get('pxe_enabled') is True:
            mac_address = port.get('address')
            if mac_address:
                LOG.info('Found PXE-enabled MAC address: %s', mac_address)
                return mac_address

    LOG.warning('No PXE-enabled port found, PXE MAC address not available '
                '(normal for virtual media boot)')
    return None


def resolve_root_device(root_device_hints):
    """Resolve root device path from hints.

    :param root_device_hints: Dictionary containing root device hints
    :returns: String containing device path (e.g., /dev/sda)
    :raises: ValueError if device cannot be resolved
    """
    if root_device_hints is None:
        raise ValueError('root_device_hints cannot be None')

    if not isinstance(root_device_hints, dict):
        raise ValueError('root_device_hints must be a dictionary')

    LOG.info('Resolving root device from hints: %s', root_device_hints)

    devices = hardware.list_all_block_devices()
    LOG.debug('list_all_block_devices returned type: %s',
              type(devices).__name__)
    LOG.info('Found %d block devices', len(devices))

    serialized_devs = [dev.serialize() for dev in devices]

    matched_raw = device_hints.find_devices_by_hints(
        serialized_devs, root_device_hints)
    LOG.debug('find_devices_by_hints returned type: %s',
              type(matched_raw).__name__)
    matched = list(matched_raw)

    if not matched:
        raise ValueError(
            f'No device found matching hints: {root_device_hints}')

    if len(matched) > 1:
        device_names = [dev['name'] for dev in matched]
        raise ValueError(
            f'Multiple devices match hints: {device_names}. '
            f'Hints must match exactly one device.')

    device_path = matched[0]['name']
    LOG.info('Resolved root device: %s', device_path)

    return device_path


def append_url_params(url, metal3_name, metal3_namespace):
    """Append metal3 parameters to URL if it's a remote URL.

    :param url: URL string (http/https/https+selfsigned or local path)
    :param metal3_name: Metal3 name value
    :param metal3_namespace: Metal3 namespace value
    :returns: URL with appended parameters if remote, original if local
    :raises: ValueError if url is invalid
    """
    if not url:
        raise ValueError('URL cannot be empty')

    if not isinstance(url, str):
        raise ValueError('URL must be a string')

    prefixes = (HTTP_PREFIX, HTTPS_PREFIX, HTTPS_SELFSIGNED_PREFIX)
    if not url.startswith(prefixes):
        LOG.info('Not a remote URL, skipping parameter append: %s', url)
        return url

    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        query_params['metal3_name'] = [metal3_name]
        query_params['metal3_namespace'] = [metal3_namespace]

        new_query = urlencode(query_params, doseq=True)

        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        LOG.info('Appended URL parameters: %s', new_url)
        return new_url

    except Exception as e:
        raise ValueError(f'Failed to append URL parameters: {e}') from e


def dump_configs(**kwargs):
    """Dump configuration data as JSON files in temporary directory.

    :param kwargs: Key-value pairs where key is filename and value is data
    :returns: String containing path to temporary directory
    :raises: ValueError if kwargs is empty or contains invalid data
    :raises: RuntimeError if unable to create directory or write files
    """
    if not kwargs:
        raise ValueError('No data provided to dump')

    try:
        temp_dir = tempfile.mkdtemp(prefix=DEFAULT_SCRIPT_TEMP_PREFIX + '_')
        LOG.info('Created temporary directory: %s', temp_dir)

        for filename, data in kwargs.items():
            if not isinstance(filename, str):
                raise ValueError(f'Filename must be a string: {filename}')

            if not filename:
                raise ValueError('Filename cannot be empty')

            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            LOG.info('Saved %s data to: %s', filename, file_path)

        return temp_dir

    except (OSError, TypeError, ValueError) as e:
        raise RuntimeError(
            f'Failed to dump configs: {e}') from e


def get_script(location, timeout, max_retries, max_redirects,
               retry_delay_base, retry_delay_jitter,
               temp_prefix, verify_ssl):
    """Get script from local path or remote URL.

    :param location: Path to local script or HTTP/HTTPS URL
    :param timeout: Timeout in seconds for HTTP requests
    :param max_retries: Maximum number of retry attempts
    :param max_redirects: Maximum number of redirects to follow (0 to disable)
    :param retry_delay_base: Base delay in seconds between retries
    :param retry_delay_jitter: Maximum jitter in seconds to add to delay
    :param temp_prefix: Prefix for temporary file
    :param verify_ssl: Whether to verify SSL certificates
    :returns: Absolute path to executable script
    :raises: ValueError if location is invalid
    :raises: RuntimeError if script cannot be fetched or prepared
    """
    if not location:
        raise ValueError('location cannot be empty')

    if not isinstance(location, str):
        raise ValueError('location must be a string')

    location = location.strip()
    script_path = None

    if location.startswith(HTTPS_SELFSIGNED_PREFIX):
        verify_ssl = False
        location = (
            HTTPS_PREFIX
            + location.removeprefix(HTTPS_SELFSIGNED_PREFIX))

    if location.startswith((HTTP_PREFIX, HTTPS_PREFIX)):
        LOG.info('Detected remote script URL: %s', location)

        session = requests.Session()
        session.max_redirects = max_redirects
        session.verify = verify_ssl

        allow_redirects = max_redirects > 0

        for attempt in range(max_retries):
            try:
                LOG.info('Downloading script from %s (attempt %d/%d)',
                         location, attempt + 1, max_retries)

                response = session.get(
                    location, timeout=timeout,
                    allow_redirects=allow_redirects)
                response.raise_for_status()

                fd, script_path = tempfile.mkstemp(prefix=temp_prefix)
                try:
                    os.write(fd, response.content)
                finally:
                    os.close(fd)

                LOG.info('Script downloaded and saved to: %s', script_path)
                break

            except (requests.RequestException, OSError) as e:
                LOG.info('Download attempt %d failed: %s', attempt + 1, e)
                if attempt < max_retries - 1:
                    time.sleep(
                        retry_delay_base
                        + random.uniform(0, retry_delay_jitter))
                else:
                    raise RuntimeError(
                        f'Failed to download script from {location} '
                        f'after {max_retries} attempts: {e}') from e

    else:
        location = location.removeprefix(FILE_PREFIX)
        LOG.info('Detected local script path: %s', location)
        script_path = os.path.abspath(os.path.expanduser(location))
        LOG.info('Local script prepared: %s', script_path)

    try:
        if not os.path.exists(script_path):
            raise RuntimeError(f'Script not found at path: {script_path}')

        if not os.path.isfile(script_path):
            raise RuntimeError(f'Path is not a file: {script_path}')

        current_mode = os.stat(script_path).st_mode
        if not current_mode & stat.S_IXUSR:
            LOG.info('Making script executable: %s', script_path)
            os.chmod(script_path, (current_mode
                                   | stat.S_IRWXU | stat.S_IRGRP
                                   | stat.S_IXGRP | stat.S_IROTH
                                   | stat.S_IXOTH))
    except OSError as e:
        raise RuntimeError(f'Failed to prepare script: {e}') from e

    return script_path


class CustomDeployHardwareManager(hardware.HardwareManager):
    """Hardware manager for executing custom deployment scripts."""

    HARDWARE_MANAGER_NAME = 'CustomDeployHardwareManager'
    HARDWARE_MANAGER_VERSION = '1.0'

    def evaluate_hardware_support(self):
        LOG.info('CustomDeployHardwareManager: '
                 'evaluate_hardware_support called')
        return hardware.HardwareSupport.SERVICE_PROVIDER

    def get_deploy_steps(self, node, ports):
        LOG.info('CustomDeployHardwareManager: get_deploy_steps called')

        return [
            {
                'step': 'custom_deploy',
                'priority': 0,
                'interface': 'deploy',
                'reboot_requested': False,
                'argsinfo': {}
            },
        ]

    def custom_deploy(self, node, ports):
        """Execute custom deployment script with node configuration.

        :param node: Node dictionary containing deployment configuration
        :param ports: List of port dictionaries for the node
        :raises: ValueError if configuration is invalid
        :raises: RuntimeError if script execution fails
        """
        LOG.info('CustomDeployHardwareManager: custom_deploy called')
        LOG.info('CustomDeployHardwareManager: node: %s', node)
        LOG.info('CustomDeployHardwareManager: ports: %s', ports)

        try:
            configdrive_data = get_configdrive_data(node)
            custom_deploy_value = get_custom_deploy_value(configdrive_data)
            metal3_name = get_metal3_name(configdrive_data)
            metal3_namespace = get_metal3_namespace(configdrive_data)
            root_device = get_root_device(node)
            boot_mode = get_boot_mode(node)
            secure_boot = get_secure_boot(node)
            pxe_mac = get_pxe_mac_address(ports)
            if pxe_mac is None:
                LOG.warning('CustomDeployHardwareManager: '
                            'PXE MAC address not available')
            root_device_path = resolve_root_device(root_device)

            LOG.info('CustomDeployHardwareManager: custom_deploy: %s',
                     custom_deploy_value)

            custom_deploy_url = append_url_params(
                custom_deploy_value, metal3_name, metal3_namespace)

            try:
                script_path = get_script(
                    custom_deploy_url,
                    DEFAULT_TIMEOUT,
                    DEFAULT_MAX_RETRIES,
                    DEFAULT_MAX_REDIRECTS,
                    DEFAULT_RETRY_DELAY_BASE,
                    DEFAULT_RETRY_DELAY_JITTER,
                    DEFAULT_SCRIPT_TEMP_PREFIX,
                    DEFAULT_VERIFY_SSL)
                LOG.info('CustomDeployHardwareManager: script prepared: %s',
                         script_path)
            except (ValueError, RuntimeError) as e:
                LOG.error('CustomDeployHardwareManager: failed to prepare '
                          'script: %s', e)
                raise

            try:
                temp_dir = dump_configs(
                    **{'node.json': node,
                       'ports.json': ports,
                       'configdrive.json': configdrive_data,
                       'root_device.json': root_device,
                       'root_device_path.json': root_device_path,
                       'boot_mode.json': boot_mode,
                       'secure_boot.json': secure_boot,
                       'pxe_mac.json': pxe_mac,
                       'metal3_name.json': metal3_name,
                       'metal3_namespace.json': metal3_namespace})
                LOG.info('CustomDeployHardwareManager: config directory: %s',
                         temp_dir)
            except (ValueError, RuntimeError) as e:
                LOG.error('CustomDeployHardwareManager: failed to dump '
                          'configs: %s', e)
                raise

            env = os.environ.copy()
            env['CUSTOM_DEPLOY_CONFIG_DIR'] = temp_dir

            LOG.info('CustomDeployHardwareManager: executing script: %s',
                     script_path)

            try:
                result = subprocess.run(
                    [script_path],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=True)
                LOG.info('CustomDeployHardwareManager: script executed '
                         'successfully')
                LOG.info('CustomDeployHardwareManager: script stdout: %s',
                         result.stdout)
                if result.stderr:
                    LOG.info('CustomDeployHardwareManager: script stderr: %s',
                             result.stderr)
            except subprocess.CalledProcessError as e:
                LOG.error('CustomDeployHardwareManager: script execution '
                          'failed with exit code %d', e.returncode)
                LOG.error('CustomDeployHardwareManager: script stdout: %s',
                          e.stdout)
                LOG.error('CustomDeployHardwareManager: script stderr: %s',
                          e.stderr)
                raise RuntimeError(
                    f'Script execution failed with exit code {e.returncode}: '
                    f'{e.stderr}') from e

            LOG.info('CustomDeployHardwareManager: custom_deploy completed')

        except Exception as e:
            LOG.error('CustomDeployHardwareManager: custom_deploy '
                      'failed: %s', e)
            raise
        finally:
            cmdline_duration = parse_cmdline_debug_sleep_duration()
            debug_sleep_duration = (
                cmdline_duration if cmdline_duration is not None
                else DEFAULT_DEBUG_SLEEP_DURATION)

            if debug_sleep_duration > 0:
                LOG.info('CustomDeployHardwareManager: debug sleep enabled, '
                         'sleeping for %d seconds', debug_sleep_duration)
                time.sleep(debug_sleep_duration)
                LOG.info('CustomDeployHardwareManager: debug sleep completed')

            # Wait for interactive users to logout
            if has_interactive_users():
                LOG.info('CustomDeployHardwareManager: interactive users '
                         'detected, waiting for logout')
                while has_interactive_users():
                    LOG.info('CustomDeployHardwareManager: users still logged '
                             'in, checking again in 60 seconds')
                    time.sleep(60)
                LOG.info('CustomDeployHardwareManager: all interactive users '
                         'logged out')
