#!/usr/bin/python
# -*- coding: -utf-8 -*-

'''
  file:kms_client.py
  author:yorkxyzhang
  function:
  history:
      date   author  description
'''

import urllib
import copy
import random
import json
import time
import sys
from kms.kms_exception import *
from kms.kms_log import KMSLogger
from kms.kms_http import *
from sign import Sign


PATH = '/v2/index.php'

class KMSClient:
    def __init__(self, host, secretId, secretKey, version="SDK_Python_1.0", logger=None):
        self.host, self.is_https = self.process_host(host)
        self.secretId = secretId
        self.secretKey = secretKey
        self.version = version
        self.logger = KMSLogger.get_logger() if logger is None else logger
        self.http = KMSHttp(self.host, logger=logger, is_https=self.is_https)
        if self.logger:
            self.logger.debug("InitClient Host:%s Version:%s" % (host, version))
        self.method = 'POST'
        self.signMethod = 'sha1'

    def set_method(self, method='POST'):
        """
        method: POST OR GET
        """
        self.method = method.upper()
    def set_sign_method(self, sign_method='sha1'):
        if sign_method != 'sha1' and sign_method != 'sha256':
            raise KMSClientException("Only support sha1 or sha256")
        else:
            self.signMethod = sign_method
    def set_log_level(self, log_level):
        if self.logger:
            KMSLogger.validate_loglevel(log_level)
            self.logger.setLevel(log_level)
            self.http.set_log_level(log_level)

    def close_log(self):
        self.logger = None
        self.http.close_log()

    def set_connection_timeout(self, connection_timeout):
        self.http.set_connection_timeout(connection_timeout)

    def set_keep_alive(self, keep_alive):
        self.http.set_keep_alive(keep_alive)

    def close_connection(self):
        self.http.conn.close()

    def process_host(self, host):
        if host.startswith("https://"):
            if host.endswith("/"):
                host = host[:-1]
            host = host[len("https://"):]
            return host, True
        else:
            raise KMSClientParameterException("Only support https prototol. Invalid host:%s" % host)

    def build_req_inter(self, action, params, req_inter):
        _params = copy.deepcopy(params)
        _params['Action'] = action[0].upper() + action[1:]
        _params['RequestClient'] = self.version

        if (_params.has_key('SecretId') != True):
            _params['SecretId'] = self.secretId

        if (_params.has_key('Nonce') != True):
            _params['Nonce'] = random.randint(1, sys.maxint)

        if (_params.has_key('Timestamp') != True):
            _params['Timestamp'] = int(time.time())
        if (_params.has_key('SignatureMethod') != True):       
            if self.signMethod == 'sha256':
                _params['SignatureMethod'] = 'HmacSHA256'
            else :
                _params['SignatureMethod'] = 'HmacSHA1'
        sign = Sign(self.secretId, self.secretKey)
        _params['Signature'] = sign.make(self.host, req_inter.uri, _params, req_inter.method, self.signMethod)

        req_inter.data = urllib.urlencode(_params)

        self.build_header(req_inter)

    def build_header(self, req_inter):
        if self.http.is_keep_alive():
            req_inter.header["Connection"] = "Keep-Alive"

    def check_status(self, resp_inter):
        if resp_inter.status != 200:
            raise KMSServerNetworkException(resp_inter.status, resp_inter.header, resp_inter.data)

        resp = json.loads(resp_inter.data)
        code, message, requestId = resp['code'], resp['message'], resp.get('requestId', '')

        if code != 0:
            raise KMSServerException(message=message, request_id=requestId, code=code, data=resp)

    def request(self, action, params):
        # make request internal
        UserTimeout = '0'
        req_inter = RequestInternal(self.method, PATH)
        self.build_req_inter(action, params, req_inter)
        resp_inter = self.http.send_request(req_inter)

        # handle result, make response
        # self.check_status(resp_inter)
        return resp_inter
    
    
    
    #------------------------------account operation-----------------------------------------#
    def create_key(self, params):
        resp_inter = self.request("CreateKey", params)
        self.check_status(resp_inter)
        ret = json.loads(resp_inter.data)    
        return ret['keyMetadata'] 
        
    def generate_data_key(self, params):
        resp_inter = self.request("GenerateDataKey", params)
        self.check_status(resp_inter)
        ret = json.loads(resp_inter.data)  
        return ret 
    def encrypt(self, params):
        resp_inter = self.request("Encrypt", params)
        self.check_status(resp_inter)
        ret = json.loads(resp_inter.data)  
        return ret
    def decrypt(self, params):
        resp_inter = self.request("Decrypt", params)
        self.check_status(resp_inter)
        ret = json.loads(resp_inter.data)
        return ret
          
    def set_key_attributes(self, params):
        resp_inter = self.request("SetKeyAttributes", params)
        self.check_status(resp_inter)
        ret = json.loads(resp_inter.data)        
           
    def get_key_attributes(self, params):
        resp_inter = self.request("GetKeyAttributes", params)
        self.check_status(resp_inter)
        ret = json.loads(resp_inter.data)  
        return ret['keyMetadata']
    
    def enable_key(self, params):
        resp_inter = self.request("EnableKey", params)
        self.check_status(resp_inter)
        ret = json.loads(resp_inter.data)  
        return ret 
    def disable_key(self, params):
        resp_inter = self.request("DisableKey", params)
        self.check_status(resp_inter)
        ret = json.loads(resp_inter.data)  
        return ret 
    def list_key(self, params):
        resp_inter = self.request("ListKey", params)
        self.check_status(resp_inter)
        ret = json.loads(resp_inter.data) 
        return ret 

    
    
    
    
    
