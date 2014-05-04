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

TEXT_HTML_CONTENT_TYPE = {
    'Content-type': 'text/html'
}

ECP_SP_REQ_HEADERS = {
    'Accept': 'text/html; application/vnd.paos+xml',
    'PAOS': ('ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:'
             'SAML:2.0:profiles:SSO:ecp"')
}

ECP_SP_RESPONSE_HEADERS = {
    'Content-Type' : 'application/vnd.paos+xml'
}

ECP_SAML2_NAMESPACES = {
        'ecp' : 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S'   : 'http://schemas.xmlsoap.org/soap/envelope/',
        'paos': 'urn:liberty:paos:2003-08'
}

ECP_RELAY_STATE = '//ecp:RelayState'
ECP_RESPONSE_CONSUMER_URL = ('/S:Envelope/S:Header/paos:Request/'
                             '@responseConsumerURL')
ECP_ASSERTION_CONSUMER_URL = ('/S:Envelope/S:Header/ecp:Response/'
                              '@AssertionConsumerServiceURL')
