# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 s3rj1k

"""Unit tests for custom deployment hardware manager."""

import os
import shutil
import tempfile
from unittest import mock

from ironic_python_agent import hardware
from ironic_python_agent.hardware_managers import custom_deploy
from ironic_python_agent.tests.unit import base


class TestGetConfigdriveData(base.IronicAgentTest):
    """Tests for get_configdrive_data function."""

    def test_get_configdrive_data_success(self):
        """Test successful extraction of configdrive data."""
        node = {
            'uuid': 'd37dbbd5-20fa-4450-b566-62a69ea34698',
            'instance_info': {
                'configdrive': {
                    'meta_data': {
                        'uuid': '406c843f-67c4-431f-9242-e5155ce5186a',
                        'metal3-namespace': 'kcm-system',
                        'metal3-name': 'vm1'
                    }
                }
            }
        }
        result = custom_deploy.get_configdrive_data(node)
        self.assertIsNotNone(result)
        self.assertEqual(result, node['instance_info']['configdrive'])

    def test_get_configdrive_data_no_configdrive(self):
        """Test error when configdrive is missing."""
        node = {'uuid': 'test-uuid', 'instance_info': {}}
        self.assertRaisesRegex(
            ValueError, 'configdrive not found in instance_info',
            custom_deploy.get_configdrive_data, node)

    def test_get_configdrive_data_instance_info_not_dict(self):
        """Test error when instance_info is not a dictionary."""
        node = {'uuid': 'test-uuid', 'instance_info': 'not-a-dict'}
        self.assertRaisesRegex(
            ValueError, 'instance_info must be a dictionary',
            custom_deploy.get_configdrive_data, node)

    def test_get_configdrive_data_configdrive_not_dict(self):
        """Test error when configdrive is not a dictionary."""
        node = {'uuid': 'test-uuid',
                'instance_info': {'configdrive': 'not-a-dict'}}
        self.assertRaisesRegex(
            ValueError, 'configdrive must be a dictionary',
            custom_deploy.get_configdrive_data, node)

    def test_get_configdrive_data_node_none(self):
        """Test error when node is None."""
        self.assertRaisesRegex(
            ValueError, 'Node cannot be None',
            custom_deploy.get_configdrive_data, None)


class TestGetRootDevice(base.IronicAgentTest):
    """Tests for get_root_device function."""

    def test_get_root_device_success(self):
        """Test successful extraction of root device."""
        node = {
            'uuid': 'd37dbbd5-20fa-4450-b566-62a69ea34698',
            'instance_info': {
                'root_device': {
                    'serial': 's== vm-disk-001'
                }
            }
        }
        result = custom_deploy.get_root_device(node)
        self.assertIsNotNone(result)
        self.assertEqual(result, {'serial': 's== vm-disk-001'})

    def test_get_root_device_node_none(self):
        """Test error when node is None."""
        self.assertRaisesRegex(
            ValueError, 'Node cannot be None',
            custom_deploy.get_root_device, None)

    def test_get_root_device_no_root_device(self):
        """Test error when root_device is missing."""
        node = {'uuid': 'test-uuid', 'instance_info': {}}
        self.assertRaisesRegex(
            ValueError, 'root_device not found in instance_info',
            custom_deploy.get_root_device, node)


class TestGetBootMode(base.IronicAgentTest):
    """Tests for get_boot_mode function."""

    def test_get_boot_mode_success(self):
        """Test successful extraction of boot mode."""
        node = {
            'uuid': 'd37dbbd5-20fa-4450-b566-62a69ea34698',
            'boot_mode': 'uefi'
        }
        result = custom_deploy.get_boot_mode(node)
        self.assertIsNotNone(result)
        self.assertEqual(result, 'uefi')

    def test_get_boot_mode_node_none(self):
        """Test error when node is None."""
        self.assertRaisesRegex(
            ValueError, 'Node cannot be None',
            custom_deploy.get_boot_mode, None)

    @mock.patch('os.path.exists', return_value=True, autospec=True)
    def test_get_boot_mode_no_boot_mode_uefi(self, mock_exists):
        """Test UEFI boot mode detection from /sys/firmware/efi."""
        node = {'uuid': 'test-uuid'}
        result = custom_deploy.get_boot_mode(node)
        self.assertEqual(result, 'uefi')
        mock_exists.assert_called_once_with('/sys/firmware/efi')

    @mock.patch('os.path.exists', return_value=False, autospec=True)
    def test_get_boot_mode_no_boot_mode_bios(self, mock_exists):
        """Test BIOS boot mode detection when /sys/firmware/efi is missing."""
        node = {'uuid': 'test-uuid'}
        result = custom_deploy.get_boot_mode(node)
        self.assertEqual(result, 'bios')
        mock_exists.assert_called_once_with('/sys/firmware/efi')


class TestGetSecureBoot(base.IronicAgentTest):
    """Tests for get_secure_boot function."""

    def test_get_secure_boot_success(self):
        """Test successful extraction of secure boot setting."""
        node = {
            'uuid': 'd37dbbd5-20fa-4450-b566-62a69ea34698',
            'secure_boot': True
        }
        result = custom_deploy.get_secure_boot(node)
        self.assertIsNotNone(result)
        self.assertEqual(result, True)

    def test_get_secure_boot_node_none(self):
        """Test error when node is None."""
        self.assertRaisesRegex(
            ValueError, 'Node cannot be None',
            custom_deploy.get_secure_boot, None)

    def test_get_secure_boot_no_secure_boot(self):
        """Test default False value when secure_boot is not specified."""
        node = {'uuid': 'test-uuid'}
        result = custom_deploy.get_secure_boot(node)
        self.assertEqual(result, False)


class TestGetPxeMacAddress(base.IronicAgentTest):
    """Tests for get_pxe_mac_address function."""

    def test_get_pxe_mac_address_success(self):
        """Test successful extraction of PXE MAC address."""
        ports = [
            {
                'uuid': '2e7aa9a3-9c16-4d46-8870-bc3907c9bab0',
                'address': '52:54:00:12:34:01',
                'pxe_enabled': True
            }
        ]
        result = custom_deploy.get_pxe_mac_address(ports)
        self.assertIsNotNone(result)
        self.assertEqual(result, '52:54:00:12:34:01')

    def test_get_pxe_mac_address_ports_none(self):
        """Test error when ports is None."""
        self.assertRaisesRegex(
            ValueError, 'Ports cannot be None',
            custom_deploy.get_pxe_mac_address, None)

    def test_get_pxe_mac_address_ports_empty(self):
        """Test returns None when ports list is empty."""
        result = custom_deploy.get_pxe_mac_address([])
        self.assertIsNone(result)

    def test_get_pxe_mac_address_no_pxe_enabled(self):
        """Test returns None when no PXE-enabled port is found."""
        ports = [
            {'address': '52:54:00:12:34:01', 'pxe_enabled': False}
        ]
        result = custom_deploy.get_pxe_mac_address(ports)
        self.assertIsNone(result)


class TestAppendUrlParams(base.IronicAgentTest):
    """Tests for append_url_params function."""

    def test_append_url_params_http(self):
        """Test appending parameters to HTTP URL."""
        url = 'http://example.com/script.sh'
        result = custom_deploy.append_url_params(url, 'vm1', 'kcm-system')
        self.assertIn('metal3_name=vm1', result)
        self.assertIn('metal3_namespace=kcm-system', result)
        self.assertTrue(result.startswith('http://example.com/script.sh?'))

    def test_append_url_params_https(self):
        """Test appending parameters to HTTPS URL."""
        url = 'https://example.com/script.sh'
        result = custom_deploy.append_url_params(url, 'vm1', 'kcm-system')
        self.assertIn('metal3_name=vm1', result)
        self.assertIn('metal3_namespace=kcm-system', result)

    def test_append_url_params_https_selfsigned(self):
        """Test appending parameters to HTTPS self-signed URL."""
        url = 'https+selfsigned://example.com/script.sh'
        result = custom_deploy.append_url_params(url, 'vm1', 'kcm-system')
        self.assertIn('metal3_name=vm1', result)
        self.assertIn('metal3_namespace=kcm-system', result)
        self.assertTrue(
            result.startswith('https+selfsigned://example.com/script.sh?'))

    def test_append_url_params_existing_params(self):
        """Test appending parameters to URL with existing query parameters."""
        url = 'http://example.com/script.sh?foo=bar'
        result = custom_deploy.append_url_params(url, 'vm1', 'kcm-system')
        self.assertIn('foo=bar', result)
        self.assertIn('metal3_name=vm1', result)
        self.assertIn('metal3_namespace=kcm-system', result)

    def test_append_url_params_local_path(self):
        """Test that local paths are returned unchanged."""
        url = '/path/to/script.sh'
        result = custom_deploy.append_url_params(url, 'vm1', 'kcm-system')
        self.assertEqual(result, '/path/to/script.sh')

    def test_append_url_params_file_url(self):
        """Test that file URLs are returned unchanged."""
        url = 'file:///path/to/script.sh'
        result = custom_deploy.append_url_params(url, 'vm1', 'kcm-system')
        self.assertEqual(result, 'file:///path/to/script.sh')

    def test_append_url_params_empty_url(self):
        """Test error when URL is empty."""
        self.assertRaisesRegex(
            ValueError, 'URL cannot be empty',
            custom_deploy.append_url_params, '', 'vm1', 'kcm-system')


class TestDumpConfigs(base.IronicAgentTest):
    """Tests for dump_configs function."""

    def test_dump_configs_success(self):
        """Test successful dumping of configuration files."""
        node = {
            'uuid': 'd37dbbd5-20fa-4450-b566-62a69ea34698',
            'instance_info': {'boot_mode': 'uefi'}
        }
        ports = [
            {'address': '52:54:00:12:34:01', 'pxe_enabled': True}
        ]
        configdrive_data = {
            'meta_data': {'metal3-name': 'vm1'}
        }
        root_device = {'serial': 's== vm-disk-001'}
        boot_mode = 'uefi'
        secure_boot = True
        pxe_mac = '52:54:00:12:34:01'

        temp_dir = custom_deploy.dump_configs(
            node=node,
            ports=ports,
            configdrive=configdrive_data,
            root_device=root_device,
            boot_mode=boot_mode,
            secure_boot=secure_boot,
            pxe_mac=pxe_mac)

        try:
            self.assertIsNotNone(temp_dir)
            self.assertTrue(os.path.exists(temp_dir))
            self.assertTrue(os.path.isdir(temp_dir))

            files = {
                'node': node,
                'ports': ports,
                'configdrive': configdrive_data,
                'root_device': root_device,
                'boot_mode': boot_mode,
                'secure_boot': secure_boot,
                'pxe_mac': pxe_mac,
            }

            for filename, expected_data in files.items():
                file_path = os.path.join(temp_dir, filename)
                self.assertTrue(os.path.exists(file_path))
                with open(file_path, 'r', encoding='utf-8') as f:
                    saved_data = custom_deploy.json.load(f)
                self.assertEqual(saved_data, expected_data)
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    def test_dump_configs_empty(self):
        """Test error when no data is provided."""
        self.assertRaisesRegex(
            ValueError, 'No data provided to dump',
            custom_deploy.dump_configs)


class TestGetCustomDeployValue(base.IronicAgentTest):
    """Tests for get_custom_deploy_value function."""

    def test_get_custom_deploy_value_success(self):
        """Test successful extraction of custom_deploy value."""
        configdrive_data = {
            'meta_data': {
                'custom_deploy': 'my-custom-value'
            }
        }
        result = custom_deploy.get_custom_deploy_value(configdrive_data)
        self.assertEqual(result, 'my-custom-value')

    def test_get_custom_deploy_value_none(self):
        """Test error when configdrive_data is None."""
        self.assertRaisesRegex(
            ValueError, 'configdrive_data cannot be None',
            custom_deploy.get_custom_deploy_value, None)

    def test_get_custom_deploy_value_not_dict(self):
        """Test error when configdrive_data is not a dictionary."""
        self.assertRaisesRegex(
            ValueError, 'configdrive_data must be a dictionary',
            custom_deploy.get_custom_deploy_value, 'not-a-dict')

    def test_get_custom_deploy_value_no_metadata(self):
        """Test error when meta_data is missing."""
        configdrive_data = {}
        self.assertRaisesRegex(
            ValueError, 'meta_data not found in configdrive',
            custom_deploy.get_custom_deploy_value, configdrive_data)

    def test_get_custom_deploy_value_metadata_not_dict(self):
        """Test error when meta_data is not a dictionary."""
        configdrive_data = {'meta_data': 'not-a-dict'}
        self.assertRaisesRegex(
            ValueError, 'meta_data must be a dictionary',
            custom_deploy.get_custom_deploy_value, configdrive_data)

    def test_get_custom_deploy_value_key_not_present(self):
        """Test error when custom_deploy key is not present."""
        configdrive_data = {'meta_data': {}}
        self.assertRaisesRegex(
            ValueError, 'custom_deploy not found in meta_data',
            custom_deploy.get_custom_deploy_value, configdrive_data)


class TestGetMetal3Name(base.IronicAgentTest):
    """Tests for get_metal3_name function."""

    def test_get_metal3_name_success(self):
        """Test successful extraction of metal3-name."""
        configdrive_data = {
            'meta_data': {
                'metal3-name': 'vm1'
            }
        }
        result = custom_deploy.get_metal3_name(configdrive_data)
        self.assertIsNotNone(result)
        self.assertEqual(result, 'vm1')

    def test_get_metal3_name_none(self):
        """Test error when configdrive_data is None."""
        self.assertRaisesRegex(
            ValueError, 'configdrive_data cannot be None',
            custom_deploy.get_metal3_name, None)

    def test_get_metal3_name_no_metal3_name(self):
        """Test error when metal3-name is missing."""
        configdrive_data = {'meta_data': {}}
        self.assertRaisesRegex(
            ValueError, 'metal3-name not found in meta_data',
            custom_deploy.get_metal3_name, configdrive_data)


class TestGetMetal3Namespace(base.IronicAgentTest):
    """Tests for get_metal3_namespace function."""

    def test_get_metal3_namespace_success(self):
        """Test successful extraction of metal3-namespace."""
        configdrive_data = {
            'meta_data': {
                'metal3-namespace': 'kcm-system'
            }
        }
        result = custom_deploy.get_metal3_namespace(configdrive_data)
        self.assertIsNotNone(result)
        self.assertEqual(result, 'kcm-system')

    def test_get_metal3_namespace_none(self):
        """Test error when configdrive_data is None."""
        self.assertRaisesRegex(
            ValueError, 'configdrive_data cannot be None',
            custom_deploy.get_metal3_namespace, None)

    def test_get_metal3_namespace_no_metal3_namespace(self):
        """Test error when metal3-namespace is missing."""
        configdrive_data = {'meta_data': {}}
        self.assertRaisesRegex(
            ValueError, 'metal3-namespace not found in meta_data',
            custom_deploy.get_metal3_namespace, configdrive_data)


class TestResolveRootDevice(base.IronicAgentTest):
    """Tests for resolve_root_device function."""

    @mock.patch.object(custom_deploy.hardware, 'list_all_block_devices',
                       autospec=True)
    @mock.patch.object(custom_deploy.device_hints, 'find_devices_by_hints',
                       autospec=True)
    def test_resolve_root_device_success(self, mock_find, mock_list):
        """Test successful resolution of root device."""
        mock_device = mock.Mock()
        mock_device.serialize.return_value = {
            'name': '/dev/sda',
            'size': 100000000000,
            'serial': 'ABC123'
        }
        mock_list.return_value = [mock_device]
        mock_find.return_value = [{'name': '/dev/sda'}]

        hints = {'serial': 'ABC123'}
        result = custom_deploy.resolve_root_device(hints)

        self.assertEqual('/dev/sda', result)
        mock_list.assert_called_once()
        mock_find.assert_called_once()

    @mock.patch.object(custom_deploy.hardware, 'list_all_block_devices',
                       autospec=True)
    @mock.patch.object(custom_deploy.device_hints, 'find_devices_by_hints',
                       autospec=True)
    def test_resolve_root_device_generator(self, mock_find, mock_list):
        """Test that resolve_root_device handles generator from hints.

        This test simulates the real behavior where find_devices_by_hints
        returns a generator instead of a list.
        """
        mock_device = mock.Mock()
        mock_device.serialize.return_value = {
            'name': '/dev/sda',
            'size': 100000000000,
            'serial': 'ABC123'
        }

        def match_generator():
            yield {'name': '/dev/sda'}

        mock_list.return_value = [mock_device]
        mock_find.return_value = match_generator()

        hints = {'serial': 'ABC123'}
        result = custom_deploy.resolve_root_device(hints)

        self.assertEqual('/dev/sda', result)
        mock_list.assert_called_once()
        mock_find.assert_called_once()

    @mock.patch.object(custom_deploy.hardware, 'list_all_block_devices',
                       autospec=True)
    @mock.patch.object(custom_deploy.device_hints, 'find_devices_by_hints',
                       autospec=True)
    def test_resolve_root_device_multiple_matches(self, mock_find, mock_list):
        """Test error when multiple devices match hints."""
        mock_device = mock.Mock()
        mock_device.serialize.return_value = {'name': '/dev/sda'}
        mock_list.return_value = [mock_device]
        mock_find.return_value = [
            {'name': '/dev/sda'},
            {'name': '/dev/sdb'}
        ]

        hints = {'size': 100}
        self.assertRaisesRegex(
            ValueError, 'Multiple devices match hints.*must match exactly one',
            custom_deploy.resolve_root_device, hints)

    @mock.patch.object(custom_deploy.hardware, 'list_all_block_devices',
                       autospec=True)
    @mock.patch.object(custom_deploy.device_hints, 'find_devices_by_hints',
                       autospec=True)
    def test_resolve_root_device_no_match(self, mock_find, mock_list):
        """Test error when no device matches hints."""
        mock_device = mock.Mock()
        mock_device.serialize.return_value = {'name': '/dev/sda'}
        mock_list.return_value = [mock_device]
        mock_find.return_value = []

        hints = {'serial': 'NOTFOUND'}
        self.assertRaisesRegex(
            ValueError, 'No device found matching hints',
            custom_deploy.resolve_root_device, hints)

    def test_resolve_root_device_none(self):
        """Test error when root_device_hints is None."""
        self.assertRaisesRegex(
            ValueError, 'root_device_hints cannot be None',
            custom_deploy.resolve_root_device, None)

    def test_resolve_root_device_not_dict(self):
        """Test error when root_device_hints is not a dictionary."""
        self.assertRaisesRegex(
            ValueError, 'root_device_hints must be a dictionary',
            custom_deploy.resolve_root_device, 'not-a-dict')


class TestGetScript(base.IronicAgentTest):
    """Tests for get_script function."""

    def test_get_script_empty(self):
        """Test error when location is empty."""
        self.assertRaisesRegex(
            ValueError, 'location cannot be empty',
            custom_deploy.get_script, '',
            custom_deploy.DEFAULT_TIMEOUT,
            custom_deploy.DEFAULT_MAX_RETRIES,
            custom_deploy.DEFAULT_MAX_REDIRECTS,
            custom_deploy.DEFAULT_RETRY_DELAY_BASE,
            custom_deploy.DEFAULT_RETRY_DELAY_JITTER,
            custom_deploy.DEFAULT_SCRIPT_TEMP_PREFIX,
            custom_deploy.DEFAULT_VERIFY_SSL)

    def test_get_script_not_string(self):
        """Test error when location is not a string."""
        self.assertRaisesRegex(
            ValueError, 'location must be a string',
            custom_deploy.get_script, 123,
            custom_deploy.DEFAULT_TIMEOUT,
            custom_deploy.DEFAULT_MAX_RETRIES,
            custom_deploy.DEFAULT_MAX_REDIRECTS,
            custom_deploy.DEFAULT_RETRY_DELAY_BASE,
            custom_deploy.DEFAULT_RETRY_DELAY_JITTER,
            custom_deploy.DEFAULT_SCRIPT_TEMP_PREFIX,
            custom_deploy.DEFAULT_VERIFY_SSL)

    def test_get_script_local_path(self):
        """Test fetching script from local absolute path."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False,
                                         suffix='.sh') as f:
            f.write('#!/bin/bash\necho "test"\n')
            temp_script = f.name

        try:
            result = custom_deploy.get_script(
                temp_script,
                custom_deploy.DEFAULT_TIMEOUT,
                custom_deploy.DEFAULT_MAX_RETRIES,
                custom_deploy.DEFAULT_MAX_REDIRECTS,
                custom_deploy.DEFAULT_RETRY_DELAY_BASE,
                custom_deploy.DEFAULT_RETRY_DELAY_JITTER,
                custom_deploy.DEFAULT_SCRIPT_TEMP_PREFIX,
                custom_deploy.DEFAULT_VERIFY_SSL)
            self.assertEqual(result, os.path.abspath(temp_script))
            self.assertTrue(os.access(result, os.X_OK))
        finally:
            os.unlink(temp_script)

    def test_get_script_relative_path(self):
        """Test fetching script from relative path."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False,
                                         suffix='.sh', dir='.') as f:
            f.write('#!/bin/bash\necho "test"\n')
            temp_script = f.name

        try:
            basename = os.path.basename(temp_script)
            result = custom_deploy.get_script(
                basename,
                custom_deploy.DEFAULT_TIMEOUT,
                custom_deploy.DEFAULT_MAX_RETRIES,
                custom_deploy.DEFAULT_MAX_REDIRECTS,
                custom_deploy.DEFAULT_RETRY_DELAY_BASE,
                custom_deploy.DEFAULT_RETRY_DELAY_JITTER,
                custom_deploy.DEFAULT_SCRIPT_TEMP_PREFIX,
                custom_deploy.DEFAULT_VERIFY_SSL)
            self.assertEqual(result, os.path.abspath(basename))
            self.assertTrue(os.access(result, os.X_OK))
        finally:
            os.unlink(temp_script)

    def test_get_script_nonexistent(self):
        """Test error when script file does not exist."""
        self.assertRaisesRegex(
            RuntimeError, 'Script not found at path',
            custom_deploy.get_script, '/nonexistent/script.sh',
            custom_deploy.DEFAULT_TIMEOUT,
            custom_deploy.DEFAULT_MAX_RETRIES,
            custom_deploy.DEFAULT_MAX_REDIRECTS,
            custom_deploy.DEFAULT_RETRY_DELAY_BASE,
            custom_deploy.DEFAULT_RETRY_DELAY_JITTER,
            custom_deploy.DEFAULT_SCRIPT_TEMP_PREFIX,
            custom_deploy.DEFAULT_VERIFY_SSL)

    @mock.patch('requests.Session', autospec=True)
    def test_get_script_http_url(self, mock_session_class):
        """Test downloading script from HTTP URL."""
        mock_session = mock.Mock()
        mock_session_class.return_value = mock_session
        mock_response = mock.Mock()
        mock_response.content = b'#!/bin/bash\necho "test"\n'
        mock_session.get.return_value = mock_response

        result = custom_deploy.get_script(
            'http://example.com/script.sh',
            custom_deploy.DEFAULT_TIMEOUT,
            custom_deploy.DEFAULT_MAX_RETRIES,
            custom_deploy.DEFAULT_MAX_REDIRECTS,
            custom_deploy.DEFAULT_RETRY_DELAY_BASE,
            custom_deploy.DEFAULT_RETRY_DELAY_JITTER,
            custom_deploy.DEFAULT_SCRIPT_TEMP_PREFIX,
            custom_deploy.DEFAULT_VERIFY_SSL)

        self.assertTrue(result.startswith('/tmp/'))
        self.assertTrue(os.path.exists(result))
        self.assertTrue(os.access(result, os.X_OK))
        os.unlink(result)

    @mock.patch('requests.Session', autospec=True)
    def test_get_script_https_url(self, mock_session_class):
        """Test downloading script from HTTPS URL."""
        mock_session = mock.Mock()
        mock_session_class.return_value = mock_session
        mock_response = mock.Mock()
        mock_response.content = b'#!/bin/bash\necho "test"\n'
        mock_session.get.return_value = mock_response

        result = custom_deploy.get_script(
            'https://example.com/script.sh',
            custom_deploy.DEFAULT_TIMEOUT,
            custom_deploy.DEFAULT_MAX_RETRIES,
            custom_deploy.DEFAULT_MAX_REDIRECTS,
            custom_deploy.DEFAULT_RETRY_DELAY_BASE,
            custom_deploy.DEFAULT_RETRY_DELAY_JITTER,
            custom_deploy.DEFAULT_SCRIPT_TEMP_PREFIX,
            custom_deploy.DEFAULT_VERIFY_SSL)

        self.assertTrue(result.startswith('/tmp/'))
        self.assertTrue(os.path.exists(result))
        self.assertTrue(os.access(result, os.X_OK))
        os.unlink(result)

    @mock.patch('requests.Session', autospec=True)
    def test_get_script_https_selfsigned_url(self, mock_session_class):
        """Test downloading script from HTTPS self-signed URL."""
        mock_session = mock.Mock()
        mock_session_class.return_value = mock_session
        mock_response = mock.Mock()
        mock_response.content = b'#!/bin/bash\necho "test"\n'
        mock_session.get.return_value = mock_response

        result = custom_deploy.get_script(
            'https+selfsigned://example.com/script.sh',
            custom_deploy.DEFAULT_TIMEOUT,
            custom_deploy.DEFAULT_MAX_RETRIES,
            custom_deploy.DEFAULT_MAX_REDIRECTS,
            custom_deploy.DEFAULT_RETRY_DELAY_BASE,
            custom_deploy.DEFAULT_RETRY_DELAY_JITTER,
            custom_deploy.DEFAULT_SCRIPT_TEMP_PREFIX,
            custom_deploy.DEFAULT_VERIFY_SSL)

        self.assertTrue(result.startswith('/tmp/'))
        self.assertTrue(os.path.exists(result))
        self.assertTrue(os.access(result, os.X_OK))
        self.assertEqual(mock_session.verify, False)
        os.unlink(result)

    def test_get_script_file_url(self):
        """Test fetching script from file:// URL."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False,
                                         suffix='.sh') as f:
            f.write('#!/bin/bash\necho "test"\n')
            temp_script = f.name

        try:
            file_url = f'file://{temp_script}'
            result = custom_deploy.get_script(
                file_url,
                custom_deploy.DEFAULT_TIMEOUT,
                custom_deploy.DEFAULT_MAX_RETRIES,
                custom_deploy.DEFAULT_MAX_REDIRECTS,
                custom_deploy.DEFAULT_RETRY_DELAY_BASE,
                custom_deploy.DEFAULT_RETRY_DELAY_JITTER,
                custom_deploy.DEFAULT_SCRIPT_TEMP_PREFIX,
                custom_deploy.DEFAULT_VERIFY_SSL)
            self.assertEqual(result, os.path.abspath(temp_script))
            self.assertTrue(os.access(result, os.X_OK))
        finally:
            os.unlink(temp_script)


class TestParseCmdlineDebugSleepDuration(base.IronicAgentTest):
    """Tests for parse_cmdline_debug_sleep_duration function."""

    @mock.patch('builtins.open', new_callable=mock.mock_open,
                read_data='console=ttyS0 ipa.debug_sleep_duration=600')
    def test_parse_cmdline_duration(self, _mock_open):
        """Test parsing valid debug sleep duration."""
        duration = custom_deploy.parse_cmdline_debug_sleep_duration()
        self.assertEqual(600, duration)

    @mock.patch('builtins.open', new_callable=mock.mock_open,
                read_data='console=ttyS0 ipa.debug_sleep_duration=0')
    def test_parse_cmdline_duration_zero(self, _mock_open):
        """Test parsing zero debug sleep duration."""
        duration = custom_deploy.parse_cmdline_debug_sleep_duration()
        self.assertEqual(0, duration)

    @mock.patch('builtins.open', new_callable=mock.mock_open,
                read_data='console=ttyS0')
    def test_parse_cmdline_no_params(self, _mock_open):
        """Test when debug sleep duration parameter is not present."""
        duration = custom_deploy.parse_cmdline_debug_sleep_duration()
        self.assertIsNone(duration)

    @mock.patch('builtins.open', new_callable=mock.mock_open,
                read_data='console=ttyS0 ipa.debug_sleep_duration=abc')
    def test_parse_cmdline_invalid_duration(self, _mock_open):
        """Test when debug sleep duration value is not a valid integer."""
        duration = custom_deploy.parse_cmdline_debug_sleep_duration()
        self.assertIsNone(duration)

    @mock.patch('builtins.open', new_callable=mock.mock_open,
                read_data='console=ttyS0 ipa.debug_sleep_duration=-100')
    def test_parse_cmdline_negative_duration(self, _mock_open):
        """Test when debug sleep duration is negative."""
        duration = custom_deploy.parse_cmdline_debug_sleep_duration()
        self.assertIsNone(duration)

    @mock.patch('builtins.open', side_effect=OSError('File not found'),
                autospec=True)
    def test_parse_cmdline_read_error(self, _mock_open):
        """Test error handling when /proc/cmdline cannot be read."""
        duration = custom_deploy.parse_cmdline_debug_sleep_duration()
        self.assertIsNone(duration)


class TestHasInteractiveUsers(base.IronicAgentTest):
    """Tests for has_interactive_users function."""

    @mock.patch.object(custom_deploy.subprocess, 'run', autospec=True)
    def test_has_interactive_users_with_users(self, mock_run):
        """Test when interactive users are logged in."""
        mock_result = mock.Mock()
        mock_result.stdout = 'user1    pts/0        2025-11-04 10:30\n'
        mock_run.return_value = mock_result

        result = custom_deploy.has_interactive_users()
        self.assertTrue(result)
        mock_run.assert_called_once()

    @mock.patch.object(custom_deploy.subprocess, 'run', autospec=True)
    def test_has_interactive_users_no_users(self, mock_run):
        """Test when no interactive users are logged in."""
        mock_result = mock.Mock()
        mock_result.stdout = ''
        mock_run.return_value = mock_result

        result = custom_deploy.has_interactive_users()
        self.assertFalse(result)
        mock_run.assert_called_once()

    @mock.patch.object(custom_deploy.subprocess, 'run', autospec=True)
    def test_has_interactive_users_command_error(self, mock_run):
        """Test error handling when 'who' command fails."""
        mock_run.side_effect = custom_deploy.subprocess.CalledProcessError(
            1, 'who')

        result = custom_deploy.has_interactive_users()
        self.assertFalse(result)

    @mock.patch.object(custom_deploy.subprocess, 'run', autospec=True)
    def test_has_interactive_users_timeout(self, mock_run):
        """Test error handling when 'who' command times out."""
        mock_run.side_effect = custom_deploy.subprocess.TimeoutExpired(
            'who', 5)

        result = custom_deploy.has_interactive_users()
        self.assertFalse(result)


class TestCustomDeployHardwareManager(base.IronicAgentTest):
    """Tests for CustomDeployHardwareManager class."""

    def setUp(self):
        """Set up test fixtures."""
        super(TestCustomDeployHardwareManager, self).setUp()
        self.hardware = custom_deploy.CustomDeployHardwareManager()
        self.node = {'uuid': 'test-node-uuid'}
        self.ports = [{'address': '00:11:22:33:44:55'}]

    def test_evaluate_hardware_support(self):
        """Test hardware support evaluation."""
        self.assertEqual(
            hardware.HardwareSupport.SERVICE_PROVIDER,
            self.hardware.evaluate_hardware_support())

    def test_get_deploy_steps(self):
        """Test get_deploy_steps returns custom_deploy step."""
        steps = self.hardware.get_deploy_steps(self.node, self.ports)

        self.assertEqual(1, len(steps))
        self.assertEqual('custom_deploy', steps[0]['step'])
        self.assertEqual(0, steps[0]['priority'])
        self.assertEqual('deploy', steps[0]['interface'])

    @mock.patch.object(custom_deploy, 'has_interactive_users',
                       autospec=True)
    @mock.patch.object(custom_deploy, 'parse_cmdline_debug_sleep_duration',
                       autospec=True)
    @mock.patch.object(custom_deploy, 'time', autospec=True)
    @mock.patch.object(custom_deploy, 'subprocess', autospec=True)
    @mock.patch.object(custom_deploy, 'dump_configs', autospec=True)
    @mock.patch.object(custom_deploy, 'get_pxe_mac_address', autospec=True)
    @mock.patch.object(custom_deploy, 'get_secure_boot', autospec=True)
    @mock.patch.object(custom_deploy, 'get_boot_mode', autospec=True)
    @mock.patch.object(custom_deploy, 'resolve_root_device', autospec=True)
    @mock.patch.object(custom_deploy, 'get_root_device', autospec=True)
    @mock.patch.object(custom_deploy, 'get_script', autospec=True)
    @mock.patch.object(custom_deploy, 'append_url_params', autospec=True)
    @mock.patch.object(custom_deploy, 'get_metal3_namespace', autospec=True)
    @mock.patch.object(custom_deploy, 'get_metal3_name', autospec=True)
    @mock.patch.object(custom_deploy, 'get_custom_deploy_value',
                       autospec=True)
    @mock.patch.object(custom_deploy, 'get_configdrive_data', autospec=True)
    @mock.patch.object(custom_deploy, 'LOG', autospec=True)
    def test_custom_deploy(self, mock_log, mock_get_cd, mock_get_cdv,
                           mock_get_m3name, mock_get_m3ns, mock_append_url,
                           mock_get_script, mock_get_root, mock_resolve_root,
                           mock_get_boot, mock_get_secure, mock_get_mac,
                           mock_dump, mock_subprocess, mock_time,
                           mock_parse_cmdline, mock_has_users):
        """Test successful custom deployment execution."""
        configdrive_data = {
            'meta_data': {
                'custom_deploy': '/path/to/script.sh'
            }
        }
        mock_get_cd.return_value = configdrive_data
        mock_get_cdv.return_value = '/path/to/script.sh'
        mock_get_m3name.return_value = 'vm1'
        mock_get_m3ns.return_value = 'kcm-system'
        mock_append_url.return_value = '/path/to/script.sh'
        mock_get_script.return_value = '/abs/path/to/script.sh'
        mock_get_root.return_value = {'serial': 's== vm-disk-001'}
        mock_resolve_root.return_value = '/dev/sda'
        mock_get_boot.return_value = 'uefi'
        mock_get_secure.return_value = True
        mock_get_mac.return_value = '52:54:00:12:34:01'
        mock_dump.return_value = '/tmp/custom_deploy_xyz123'
        mock_parse_cmdline.return_value = None
        mock_has_users.return_value = False

        mock_result = mock.Mock()
        mock_result.stdout = 'success'
        mock_result.stderr = ''
        mock_subprocess.run.return_value = mock_result

        self.hardware.custom_deploy(self.node, self.ports)

        mock_log.info.assert_called()
        mock_get_cdv.assert_called_once_with(configdrive_data)
        mock_get_m3name.assert_called_once_with(configdrive_data)
        mock_get_m3ns.assert_called_once_with(configdrive_data)
        mock_append_url.assert_called_once_with(
            '/path/to/script.sh', 'vm1', 'kcm-system')
        mock_dump.assert_called_once_with(
            **{'node.json': self.node,
               'ports.json': self.ports,
               'configdrive.json': configdrive_data,
               'root_device.json': {'serial': 's== vm-disk-001'},
               'root_device_path.json': '/dev/sda',
               'boot_mode.json': 'uefi',
               'secure_boot.json': True,
               'pxe_mac.json': '52:54:00:12:34:01',
               'metal3_name.json': 'vm1',
               'metal3_namespace.json': 'kcm-system'})
        mock_get_script.assert_called_once_with(
            '/path/to/script.sh',
            custom_deploy.DEFAULT_TIMEOUT,
            custom_deploy.DEFAULT_MAX_RETRIES,
            custom_deploy.DEFAULT_MAX_REDIRECTS,
            custom_deploy.DEFAULT_RETRY_DELAY_BASE,
            custom_deploy.DEFAULT_RETRY_DELAY_JITTER,
            custom_deploy.DEFAULT_SCRIPT_TEMP_PREFIX,
            custom_deploy.DEFAULT_VERIFY_SSL)
        mock_get_root.assert_called_once_with(self.node)
        mock_resolve_root.assert_called_once_with(
            {'serial': 's== vm-disk-001'})
        mock_get_boot.assert_called_once_with(self.node)
        mock_get_secure.assert_called_once_with(self.node)
        mock_get_mac.assert_called_once_with(self.ports)
        mock_subprocess.run.assert_called_once()
        if custom_deploy.DEFAULT_DEBUG_SLEEP_DURATION > 0:
            mock_time.sleep.assert_called_once_with(
                custom_deploy.DEFAULT_DEBUG_SLEEP_DURATION)
        else:
            mock_time.sleep.assert_not_called()

    @mock.patch.object(custom_deploy, 'has_interactive_users',
                       autospec=True)
    @mock.patch.object(custom_deploy, 'parse_cmdline_debug_sleep_duration',
                       autospec=True)
    @mock.patch.object(custom_deploy, 'time', autospec=True)
    @mock.patch.object(custom_deploy, 'get_configdrive_data', autospec=True)
    def test_custom_deploy_missing_value(self, mock_get_cd, mock_time,
                                         mock_parse_cmdline, mock_has_users):
        """Test error when custom_deploy value is missing."""
        configdrive_data = {'meta_data': {}}
        mock_get_cd.return_value = configdrive_data
        mock_parse_cmdline.return_value = None
        mock_has_users.return_value = False

        self.assertRaisesRegex(
            ValueError,
            'custom_deploy not found in meta_data',
            self.hardware.custom_deploy, self.node, self.ports)

        if custom_deploy.DEFAULT_DEBUG_SLEEP_DURATION > 0:
            mock_time.sleep.assert_called_once_with(
                custom_deploy.DEFAULT_DEBUG_SLEEP_DURATION)
        else:
            mock_time.sleep.assert_not_called()
