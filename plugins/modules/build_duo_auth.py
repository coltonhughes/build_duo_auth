#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Copyright 2020 Colton Hughes <colton.hughes@firemon.com>

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


ANSIBLE_METADATA = {'status': ['stableinterface'],
                    'supported_by': 'community',
                    'version': '1.0'
                    }

DOCUMENTATION = '''
---
module: build_duo_auth
short_description: Module to build a DUO Authorization and Date header
version_added: "2.9"
description:
  - "This module generates the Authorization/Date header for the Duo Admin API"
  - "Due to the complexity of their api you cannot use the standard URI module to do this."
options:
  integration_key:
    description:
      - The integration key generated from your DUO Security Registered App.
    required: true
  api_host:
    description:
      - The URL endpoint for your DUO instance. You can retrieve this from your DUO Security Registered App.
    required: true
  secret:
    description:
      - The secret key generated from your DUO Security Registered App.
    required: true
  method:
    description:
      - The HTTP Rest method to be used in a future API call.
    required: true
  path:
    description:
      - The resources you wish to access. This sould be everything AFTER https://api-xxxxxxx.duosecurity.com
    required: true
  params:
    description:
      - The query parametersto be used in a future API call.
    required: true
'''

EXAMPLES = '''
# Generate a DUO API Authorizatoin/Date Header
- name: Generate Authorization/Date Headers
  build_duo_auth::
    integration_key: <integration_key_from_duo_app>
    api_host: api-xxxxxxxx.duosecurity.com
    secret: <secret_from_duo_app>
    method: "GET"
    path: "/admin/v1/users"
    params:
      username: johndoe
'''

RETURN = '''
api_host:
  descriptoin: API base URL
  type: str
  returned: always
date:
  description: RFC2822 formatted date
  type: str
  returned: changed
integration_key:
  description: DUO App integration key
  type: str
  returned: always
method:
  description: HTTP Rest method to be used
  type: str
  returned: always
params:
  description: Query parameters to be used
  type: dict
  returned: always
path:
  description: URL endpoint
  type: str
  returned: always
token:
  description: Authorization formatted header for DUO API
  type: str
  returned: changed
'''
import traceback

try:
  import datetime
  import time
  from email import utils
  import urllib
  import hashlib
  import hmac
  import base64
  HAS_LIB = True
except:
  HAS_LIB = False
  LIB_IMP_ERR = traceback.format_exc()

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import missing_required_lib
from collections import OrderedDict

def run_module():
  module_args = dict(
    integration_key=dict(type='str', required=True),
    api_host=dict(type='str', required=True),
    secret=dict(type='str', required=True, no_log=True),
    method=dict(type='str', choices=['GET','POST','DELETE' ],required=True),
    path=dict(type='str', required=True),
    params=dict(type='dict'),
    body=dict(type='dict')
  )

  module = AnsibleModule(
    argument_spec=module_args,
    supports_check_mode=False,
    mutually_exclusive=[['params', 'body']]
  )

  if not HAS_LIB:
    module.fail_json(msg=missing_required_lib("email"), exception=LIB_IMP_ERR)

  integration_key = module.params['integration_key']
  api_host = module.params['api_host']
  secret = module.params['secret']
  method = module.params['method']
  path = module.params['path']
  params = module.params['params']
  
  params = sorted(params.items())

  result = dict(
    changed=False,
    integration_key=integration_key,
    api_host=api_host,
    method=method,
    path=path,
    params=params,
    token='',
    date='',
    urlencoded_params=''
  )
  try:
    result['token'] = buildHeaders(genDate(), method, api_host, path, params, secret, integration_key)['Authorization']
    result['date'] = buildHeaders(genDate(), method, api_host, path, params, secret, integration_key)['Date']
    result['urlencoded_params'] = buildHeaders(genDate(), method, api_host, path, params, secret, integration_key)['url_encoded_params']
    result['changed'] = True
    module.exit_json(**result)
  except Exception as error:
    module.fail_json(msg=error, **result)


def genDate():
  now = datetime.datetime.now()
  nowTuple = now.timetuple()
  timestamp = time.mktime(nowTuple)

  date_rfc2822 = utils.formatdate(timestamp)

  return(date_rfc2822)

def buildHeaders(date, method, host, path, params, secret, integration_key):
  urlencoded_params = urllib.parse.urlencode(params)
  msg = '{}\n{}\n{}\n{}\n{}'.format(date, method.upper(), host.lower(), path, urlencoded_params)
  signature = hmac.new(bytes(secret, 'latin-1'), msg=bytes(msg, 'latin-1'), digestmod=hashlib.sha1)

  auth = '{}:{}'.format(integration_key, signature.hexdigest())
  auth_bytes = auth.encode("utf-8")

  return {'Date': date, 'Authorization': 'Basic {}'.format((base64.b64encode(auth_bytes)).decode("utf-8")), "url_encoded_params": urlencoded_params}


def main():
  run_module()

if __name__ == '__main__':
  main()