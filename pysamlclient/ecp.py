
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""SAML2 Enhanced Client or Proxy implementation"""

import os
import sys

from lxml import etree
from copy import deepcopy
import pdb
import requests

import pysamlclient

class ECPClient(object):

    def __init__(self, credentials):
        self.user = credentials['user']
        self.password = credentials['password']
        self.sp_url = credentials['sp']
        self.idp_url = credentials['idp']

        self.session = requests.Session()

    def _initial_sp_request(self):
        response = self.session.get(self.sp_url,
                                    headers=pysamlclient.ECP_SP_REQ_HEADERS,
                                    verify=False)

        self.saml2_authn_req = {
            'text': deepcopy(response.text),
            'xml': etree.XML(response.text)
        }

    def _idp_saml2_request(self):
        sp_response = self.saml2_authn_req['xml']
        relay_state = sp_response.xpath(pysamlclient.ECP_RELAY_STATE,
            namespaces=pysamlclient.ECP_SAML2_NAMESPACES)

        try:
            self.relay_state = relay_state[0]
        except IndexError:
            print "relay_state is empty"

        response_consumer_url = sp_response.xpath(
            pysamlclient.ECP_RESPONSE_CONSUMER_URL,
            namespaces=pysamlclient.ECP_SAML2_NAMESPACES)

        try:
            response_consumer_url = response_consumer_url[0]
        except IndexError:
            print "response_consumer_url is empty"


        self.saml2_idp_authn_req = deepcopy(self.saml2_authn_req['xml'])
        header = self.saml2_idp_authn_req[0]
        self.saml2_idp_authn_req.remove(header)

        response = self.session.post(self.idp_url,
            headers=pysamlclient.TEXT_HTML_CONTENT_TYPE,
            data=etree.tostring(self.saml2_idp_authn_req),
            auth=(self.user, self.password), verify=False)

        self.saml2_authn_response = {
            'text': deepcopy(response.text),
            'xml': etree.XML(str(response.text))
        }

        idp_response = self.saml2_authn_response['xml']
        assertion_response_url = idp_response.xpath(
            pysamlclient.ECP_ASSERTION_CONSUMER_URL,
            namespaces=pysamlclient.ECP_SAML2_NAMESPACES)

        try:
            self.assertion_response_url = assertion_response_url[0]
        except IndexError:
            print "assertion_response_url is empty"

    def _sp_saml2_response(self):
        saml2_authn_response = deepcopy(self.saml2_authn_response['xml'])
        saml2_authn_response[0][0] = self.relay_state
        saml2_authn_response = etree.tostring(saml2_authn_response)

        response = self.session.post(self.assertion_response_url,
            headers={'Content-Type' : 'application/vnd.paos+xml'},
            data=saml2_authn_response, verify=False)

        self.x_subject_token = response.headers.get('x-subject-token')
        self.token = response.json()



    def _re_request_token(self):
        response = self.session.get(self.sp_url,
                                headers=pysamlclient.ECP_SP_REQ_HEADERS,
                                verify=False)

        pdb.set_trace()

    def authenticate(self):
        self._initial_sp_request()
        self._idp_saml2_request()
        self._sp_saml2_response()
        self._re_request_token()