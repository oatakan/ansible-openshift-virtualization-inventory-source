# Copyright (c) 2018 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

import os
import socket

__metaclass__ = type

DOCUMENTATION = '''
    name: kubevirt
    plugin_type: inventory
    author:
      - KubeVirt Team (@kubevirt)

    version_added: "2.8"
    short_description: KubeVirt inventory source
    extends_documentation_fragment:
        - inventory_cache
        - constructed
    description:
      - Fetch running VirtualMachines for one or more namespaces.
      - Groups by namespace, namespace_vms  and labels.
      - Uses kubevirt.(yml|yaml) YAML configuration file to set parameter values.

    options:
      plugin:
        description: token that ensures this is a source file for the 'kubevirt' plugin.
        required: True
        choices: ['kubevirt']
        type: str
      host_format:
        description:
          - Specify the format of the host in the inventory group.
        default: "{namespace}-{name}-{uid}"
      connections:
          type: list
          description:
            - Optional list of cluster connection settings. If no connections are provided, the default
              I(~/.kube/config) and active context will be used, and objects will be returned for all namespaces
              the active user is authorized to access.
          suboptions:
            name:
                description:
                - Optional name to assign to the cluster. If not provided, a name is constructed from the server
                    and port.
                type: str
            kubeconfig:
                description:
                - Path to an existing Kubernetes config file. If not provided, and no other connection
                    options are provided, the OpenShift client will attempt to load the default
                    configuration file from I(~/.kube/config.json). Can also be specified via K8S_AUTH_KUBECONFIG
                    environment variable.
                type: str
            context:
                description:
                - The name of a context found in the config file. Can also be specified via K8S_AUTH_CONTEXT environment
                    variable.
                type: str
            host:
                description:
                - Provide a URL for accessing the API. Can also be specified via K8S_AUTH_HOST environment variable.
                type: str
            api_key:
                description:
                - Token used to authenticate with the API. Can also be specified via K8S_AUTH_API_KEY environment
                    variable.
                type: str
            username:
                description:
                - Provide a username for authenticating with the API. Can also be specified via K8S_AUTH_USERNAME
                    environment variable.
                type: str
            password:
                description:
                - Provide a password for authenticating with the API. Can also be specified via K8S_AUTH_PASSWORD
                    environment variable.
                type: str
            cert_file:
                description:
                - Path to a certificate used to authenticate with the API. Can also be specified via K8S_AUTH_CERT_FILE
                    environment variable.
                type: str
            key_file:
                description:
                - Path to a key file used to authenticate with the API. Can also be specified via K8S_AUTH_HOST
                    environment variable.
                type: str
            ssl_ca_cert:
                description:
                - Path to a CA certificate used to authenticate with the API. Can also be specified via
                    K8S_AUTH_SSL_CA_CERT environment variable.
                type: str
            verify_ssl:
                description:
                - "Whether or not to verify the API server's SSL certificates. Can also be specified via
                    K8S_AUTH_VERIFY_SSL environment variable."
                type: bool
            namespaces:
                description:
                - List of namespaces. If not specified, will fetch all virtual machines for all namespaces user is authorized
                    to access.
                type: list
            network_name:
                description:
                - In case of multiple network attached to virtual machine, define which interface should be returned as primary IP
                    address.
                type: str
            api_version:
                description:
                - "Specify the KubeVirt API version."
                type: str
            annotation_variable:
                description:
                - "Specify the name of the annotation which provides data, which should be used as inventory host variables."
                - "Note, that the value in ansible annotations should be json."
                type: str
                default: 'ansible'
    requirements:
    - "openshift >= 0.6"
    - "PyYAML >= 3.11"
'''

EXAMPLES = '''
# File must be named kubevirt.yaml or kubevirt.yml

# Authenticate with token, and return all virtual machines for all namespaces
plugin: kubevirt
connections:
 - host: https://kubevirt.io
   token: xxxxxxxxxxxxxxxx
   ssl_verify: false

# Use default config (~/.kube/config) file and active context, and return vms with interfaces
# connected to network myovsnetwork and from namespace vms
plugin: kubevirt
connections:
  - namespaces:
      - vms
    network_name: myovsnetwork
'''

import json

import traceback

#from ansible.plugins.inventory.k8s import K8sInventoryException, InventoryModule as K8sInventoryModule, format_dynamic_api_exc
from ansible_collections.kubernetes.core.plugins.module_utils.common import K8sAnsibleMixin, HAS_K8S_MODULE_HELPER, k8s_import_exception, get_api_client
from ansible_collections.kubernetes.core.plugins.inventory.k8s import K8sInventoryException, InventoryModule as K8sInventoryModule, format_dynamic_api_exc

from ansible.module_utils.six.moves.urllib_parse import urlparse, parse_qs, urlencode

try:
    from openshift.dynamic.exceptions import DynamicApiError
except ImportError:
    pass

# 3rd party imports
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from requests_oauthlib import OAuth2Session
    HAS_REQUESTS_OAUTH = True
except ImportError:
    HAS_REQUESTS_OAUTH = False

try:
    from urllib3.util import make_headers
    HAS_URLLIB3 = True
except ImportError:
    HAS_URLLIB3 = False


API_VERSION = 'kubevirt.io/v1'


class InventoryModule(K8sInventoryModule):
    NAME = 'kubevirt'

    def setup(self, config_data, cache, cache_key):
        self.config_data = config_data
        super(InventoryModule, self).setup(config_data, cache, cache_key)

    def fetch_objects(self, connections):
        vm_format = self.config_data.get('host_format', '{namespace}-{name}-{uid}')

        if connections:
            for connection in connections:
                # on OpenShift, authentication needs to be done when using username and password
                if (connection.get('host', None) or os.getenv('K8S_AUTH_HOST', None)) \
                        and (connection.get('username', None) or os.getenv('K8S_AUTH_USERNAME', None)) \
                        and (connection.get('password', None) or os.getenv('K8S_AUTH_PASSWORD', None)):

                    verify_ssl = eval(os.getenv('K8S_AUTH_VERIFY_SSL', connection.get('verify_ssl', None)))
                    ssl_ca_cert = os.getenv('K8S_AUTH_SSL_CA_CERT', connection.get('ssl_ca_cert', None))

                    self.auth_username = os.getenv('K8S_AUTH_USERNAME', connection.get('username', None))
                    self.auth_password = os.getenv('K8S_AUTH_PASSWORD', connection.get('password', None))
                    self.con_host = os.getenv('K8S_AUTH_HOST', connection.get('host', None))

                    # python-requests takes either a bool or a path to a ca file as the 'verify' param
                    if verify_ssl and ssl_ca_cert:
                        self.con_verify_ca = ssl_ca_cert  # path
                    else:
                        self.con_verify_ca = verify_ssl  # bool

                    self.openshift_discover()
                    self.auth_api_key = self.openshift_login()
                    connection['api_key'] = self.auth_api_key
                    connection['validate_certs'] = self.con_verify_ca

                client = get_api_client(**connection)
                name = connection.get('name', self.get_default_host_name(client.configuration.host))
                if connection.get('namespaces'):
                    namespaces = connection['namespaces']
                else:
                    namespaces = self.get_available_namespaces(client)
                interface_name = connection.get('network_name')
                api_version = connection.get('api_version', API_VERSION)
                annotation_variable = connection.get('annotation_variable', 'ansible')
                for namespace in namespaces:
                    self.get_vms_for_namespace(client, name, namespace, vm_format, interface_name, api_version, annotation_variable)

                if self.auth_api_key:
                    self.openshift_logout()

        else:
            client = get_api_client()
            name = self.get_default_host_name(client.configuration.host)
            namespaces = self.get_available_namespaces(client)
            for namespace in namespaces:
                self.get_vms_for_namespace(client, name, namespace, vm_format, None, api_version, annotation_variable)

    def get_vms_for_namespace(self, client, name, namespace, name_format, interface_name=None, api_version=None, annotation_variable=None):
        v1_vm = client.resources.get(api_version=api_version, kind='VirtualMachineInstance')
        try:
            obj = v1_vm.get(namespace=namespace)
        except DynamicApiError as exc:
            self.display.debug(exc)
            raise K8sInventoryException('Error fetching Virtual Machines list: %s' % format_dynamic_api_exc(exc))

        namespace_group = 'namespace_{0}'.format(namespace)
        namespace_vms_group = '{0}_vms'.format(namespace_group)

        name = self._sanitize_group_name(name)
        namespace_group = self._sanitize_group_name(namespace_group)
        namespace_vms_group = self._sanitize_group_name(namespace_vms_group)
        self.inventory.add_group(name)
        self.inventory.add_group(namespace_group)
        self.inventory.add_child(name, namespace_group)
        self.inventory.add_group(namespace_vms_group)
        self.inventory.add_child(namespace_group, namespace_vms_group)
        for vm in obj.items:
            if not (vm.status and vm.status.interfaces):
                continue

            # Find interface by its name:
            if interface_name is None:
                interface = vm.status.interfaces[0]
            else:
                interface = next(
                    (i for i in vm.status.interfaces if i.name == interface_name),
                    None
                )

            # If interface is not found or IP address is not reported skip this VM:
            if interface is None or interface.ipAddress is None:
                continue

            named_interface = False
            # check to see if we used a named interface
            if interface.name is not None:
                for net in vm.spec.networks:
                    if net.name == interface.name:
                        if net.get('multus', None):
                            named_interface = True
                            continue

            vm_name = name_format.format(namespace=vm.metadata.namespace, name=vm.metadata.name, uid=vm.metadata.uid)
            vm_ip = interface.ipAddress.split('/')[0]
            vm_annotations = {} if not vm.metadata.annotations else dict(vm.metadata.annotations)

            # if using default networking, we'll try to utilize service definition for remote connection
            if not named_interface:
                v1_svc = client.resources.get(api_version='v1', kind='Service')

                try:
                    svc_obj = v1_svc.get(namespace=namespace)
                except DynamicApiError as exc:
                    self.display.debug(exc)
                    pass

                vm_svc_ports = {}
                svc = next((x for x in svc_obj.items if x['metadata']['name'] == str(vm.metadata.name) + '-remote'), None)
                if svc:
                    vm_remote_port = svc.spec.ports[0].nodePort
                    for port in svc.spec.ports:
                        vm_svc_ports[port.name] = port.nodePort
                else:
                    vm_remote_port = ''

            if not named_interface:
                v1_route = client.resources.get(api_version='route.openshift.io/v1', kind='Route')

                try:
                    route_obj = v1_route.get(namespace=namespace)
                except DynamicApiError as exc:
                    self.display.debug(exc)
                    pass

                vm_routes = {}
                for route in route_obj.items:
                    if route.get('metadata', {}).get('ownerReferences', {}):
                        if route['metadata']['ownerReferences'][0].get('uid', {}) == str(vm['metadata']['ownerReferences'][0]['uid']):
                            if route.spec.tls:
                                route_protocol = 'https'
                            else:
                                route_protocol = 'http'
                            vm_routes[route.spec.port.targetPort] = route_protocol + '://' + route.spec.host

            self.inventory.add_host(vm_name)

            if vm.metadata.labels:
                # create a group for each label_value
                for key, value in vm.metadata.labels:
                    group_name = 'label_{0}_{1}'.format(key, value)
                    group_name = self._sanitize_group_name(group_name)
                    self.inventory.add_group(group_name)
                    self.inventory.add_child(group_name, vm_name)
                vm_labels = dict(vm.metadata.labels)
            else:
                vm_labels = {}

            self.inventory.add_child(namespace_vms_group, vm_name)

            # add hostvars
            if not named_interface and vm_remote_port:
                #self.inventory.set_variable(vm_name, 'ansible_host', socket.gethostbyname(vm_labels['kubevirt.io/nodeName']))
                self.inventory.set_variable(vm_name, 'ansible_host', vm_labels['kubevirt.io/nodeName'])
                self.inventory.set_variable(vm_name, 'ansible_port', vm_remote_port)
                self.inventory.set_variable(vm_name, 'ansible_private_ip', vm_ip)
                self.inventory.set_variable(vm_name, 'kube_service_ports', vm_svc_ports)
                self.inventory.set_variable(vm_name, 'kube_routes', vm_routes)
            else:
                self.inventory.set_variable(vm_name, 'ansible_host', vm_ip)

            self.inventory.set_variable(vm_name, 'labels', vm_labels)
            self.inventory.set_variable(vm_name, 'annotations', vm_annotations)
            self.inventory.set_variable(vm_name, 'object_type', 'vm')
            self.inventory.set_variable(vm_name, 'resource_version', vm.metadata.resourceVersion)
            self.inventory.set_variable(vm_name, 'uid', vm.metadata.uid)

            # Add all variables which are listed in 'ansible' annotation:
            annotations_data = json.loads(vm_annotations.get(annotation_variable, "{}"))
            for k, v in annotations_data.items():
                self.inventory.set_variable(vm_name, k, v)

    def openshift_discover(self):
        url = '{0}/.well-known/oauth-authorization-server'.format(self.con_host)
        ret = requests.get(url, verify=self.con_verify_ca)

        if ret.status_code != 200:
            self.fail_request("Couldn't find OpenShift's OAuth API", method='GET', url=url,
                              reason=ret.reason, status_code=ret.status_code)

        try:
            oauth_info = ret.json()

            self.openshift_auth_endpoint = oauth_info['authorization_endpoint']
            self.openshift_token_endpoint = oauth_info['token_endpoint']
        except Exception as e:
            self.fail_json(msg="Something went wrong discovering OpenShift OAuth details.",
                           exception=traceback.format_exc())

    def openshift_login(self):
        os_oauth = OAuth2Session(client_id='openshift-challenging-client')
        authorization_url, state = os_oauth.authorization_url(self.openshift_auth_endpoint,
                                                              state="1", code_challenge_method='S256')
        auth_headers = make_headers(basic_auth='{0}:{1}'.format(self.auth_username, self.auth_password))

        # Request authorization code using basic auth credentials
        ret = os_oauth.get(
            authorization_url,
            headers={'X-Csrf-Token': state, 'authorization': auth_headers.get('authorization')},
            verify=self.con_verify_ca,
            allow_redirects=False
        )

        if ret.status_code != 302:
            self.fail_request("Authorization failed.", method='GET', url=authorization_url,
                              reason=ret.reason, status_code=ret.status_code)

        # In here we have `code` and `state`, I think `code` is the important one
        qwargs = {}
        for k, v in parse_qs(urlparse(ret.headers['Location']).query).items():
            qwargs[k] = v[0]
        qwargs['grant_type'] = 'authorization_code'

        # Using authorization code given to us in the Location header of the previous request, request a token
        ret = os_oauth.post(
            self.openshift_token_endpoint,
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                # This is just base64 encoded 'openshift-challenging-client:'
                'Authorization': 'Basic b3BlbnNoaWZ0LWNoYWxsZW5naW5nLWNsaWVudDo='
            },
            data=urlencode(qwargs),
            verify=self.con_verify_ca
        )

        if ret.status_code != 200:
            self.fail_request("Failed to obtain an authorization token.", method='POST',
                              url=self.openshift_token_endpoint,
                              reason=ret.reason, status_code=ret.status_code)

        return ret.json()['access_token']

    def openshift_logout(self):
        url = '{0}/apis/oauth.openshift.io/v1/oauthaccesstokens/{1}'.format(self.con_host, self.auth_api_key)
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {0}'.format(self.auth_api_key)
        }
        json = {
            "apiVersion": "oauth.openshift.io/v1",
            "kind": "DeleteOptions"
        }

        ret = requests.delete(url, headers=headers, json=json, verify=self.con_verify_ca)
        # Ignore errors, the token will time out eventually anyway

    def fail(self, msg=None):
        self.fail_json(msg=msg)

    def fail_request(self, msg, **kwargs):
        req_info = {}
        for k, v in kwargs.items():
            req_info['req_' + k] = v
        self.fail_json(msg=msg, **req_info)

    def verify_file(self, path):
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(('kubevirt.yml', 'kubevirt.yaml')):
                return True
        return False
