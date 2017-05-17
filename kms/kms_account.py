#!/usr/bin/python
# -*- coding: -utf-8 -*-

'''
  file:kms_account.py
  author:yorkxyzhang
  description :kms account class 
  date:2017-2-14
  history:
      date   author  description
'''

from Crypto.Cipher import AES
from kms.kms_client import KMSClient
from kms.kms_log import KMSLogger

import time 
import base64



class KeyMetadata:
    '''
    '''
    def __init__(self):
        '''
            @attribute              @description                                 @value  
            KeyId                  key id
            CreateTime             create time of the key                        unis time stamp
            Description            the description of the key
            KeyState               the state of the key                          Enabled|Disabled  
            KeyUsage               the usage of the key                          ENCRYPT|DECRYPT
            creator                creator                                       creator id     
        '''
        
        self.KeyId = ""
        self.CreateTime = -1
        self.Description = ""
        self.KeyState = ""
        self.KeyUsage = ""
        self.Alias = ""
        
    def __str__(self):
        
        meta_info = {"KeyId":self.KeyId,
                   "CreateTime":time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(self.CreateTime)),
                   "Description":self.Description,
                   "KeyState":self.KeyState,
                   "KeyUsage":self.KeyUsage,
                   "Alias" : self.Alias}
        
        return "\n".join(["%s: %s" % (k.ljust(30), v) for k, v in meta_info.items()])
        
        
class KMSAccount:
    '''
    
    '''
    def __init__(self, host, secretId, secretKey, debug=False):
        self.secretId = secretId
        self.secretKey = secretKey
        self.debug = debug
        self.logger = KMSLogger.get_logger()
        self.kms_client = KMSClient(host, secretId, secretKey, logger=self.logger)
    
    def set_debug(self, debug):
        self.debug = debug
    
    def set_sign_method(self, sign_method):
        '''
        here set the sign method and now we are support sha1 or sha256
        '''
        self.kms_client.set_sign_method(sign_method)
         
    def set_log_level(self, log_level):
        ''' 设置logger的日志级别
            @type log_level: int
            @param log_level: one of logging.DEBUG,logging.INFO,logging.WARNING,logging.ERROR,logging.CRITICAL
        '''
        KMSLogger.validate_loglevel(log_level)
        self.logger.setLevel(log_level)
        self.kms_client.set_log_level(log_level)

    def close_log(self):
        """ 关闭日志打印
        """
        self.kms_client.close_log()


    def set_client(self, host, secretId=None, secretKey=None):
        if secretId is None:
            secretId = self.secretId
        if secretKey is None:
            secretKey = self.secretKey
        self.kms_client = KMSClient(host, secretId, secretKey, logger=self.logger)
        
    def get_client(self):
        return self.kms_client
    def __resp2meta(self, key_meta, resp):
        if 'keyId' in resp.keys():
            key_meta.KeyId = resp['keyId']
        if 'createTime' in resp.keys():
            key_meta.CreateTime = resp['createTime']
        if 'description' in resp.keys():
            key_meta.Description = resp['description']
        if 'keyState' in resp.keys():
            key_meta.KeyState = resp['keyState']
        if 'keyUsage' in resp.keys():
            key_meta.KeyUsage = resp['keyUsage']
        if 'alias' in resp.keys():
            key_meta.Alias = resp['alias']
                   
    def create_key(self, Description=None, Alias="", KeyUsage='ENCRYPT/DECRYPT'):
        ''' create master key 
            @params            @description                       @type            @default  
            input:
            Description       the description of the key          string           ""
            KeyUsage          the usage of the key                string           "ENCRYPT/DECRYPT"
            Alias             Alias                               string           "" 0-32 Bytes
            
            return: 
            KeyMeta           the key information                 KeyMeta class     
            KMSExceptionBase  exception                           KMSException            
        '''
        
        params = {}
        if Description != None:
            params['description'] = Description
        params["alias"] = Alias
        params['keyUsage'] = KeyUsage     
        
        ret_pkg = self.kms_client.create_key(params) 
        key_meta = KeyMetadata()
        self.__resp2meta(key_meta, ret_pkg)
        return key_meta
      
    def generate_data_key(self, KeyId=None, KeySpec=None, NumberOfBytes=None, EncryptionContext=None):
        ''' create data key for  encryption or decryption
            @params            @description                       @type            @default     @value
            input:
            KeyId             the key id                          string              
            KeySpace          The encryption algorithm            string                        AES_128 |AES_256
            NumberOfBytes     the length of the data key          int                           1-1024
            EncryptionContext for encryption context              json string
            return: 
            KeyId             the key id                          string
            Plaintext         
            CiphertextBlob    
            KMSExceptionBase  exception                           KMSException            
        '''
        params = {}
        params['keyId'] = KeyId
        if KeySpec != None:
            params['keySpec'] = KeySpec
        if NumberOfBytes != None:
            params['numberOfBytes'] = NumberOfBytes
        if EncryptionContext != None:
            params['encryptionContext'] = EncryptionContext  
        ret_pkg = self.kms_client.generate_data_key(params) 
        return (base64.b64decode(ret_pkg['plaintext']) , ret_pkg['ciphertextBlob'])
        
    def encrypt(self, KeyId=None, Plaintext="", EncryptionContext=None):
        ''' encryption 
            @params            @description                       @type            @default     @value
            input:
            KeyId             the key id                          string              
            Plaintext         the data needs encrpt               string 
            EncryptionContext for encryption context              json string 
            return: 
            KeyId             the key id                          string      
            CiphertextBlob    
            KMSExceptionBase  exception                           KMSException            
        '''
        params = {}
        params['keyId'] = KeyId
        params['plaintext'] = base64.b64encode(Plaintext)
        if EncryptionContext != None:
            params['encryptionContext'] = EncryptionContext
        ret_pkg = self.kms_client.encrypt(params)
        return ret_pkg['ciphertextBlob']

    def decrypt(self, CiphertextBlob="", EncryptionContext=None):
        ''' decryption
            @params            @description                       @type            @default     @value
            input:
            CiphertextBlob                       
            EncryptionContext for encryption context              json string  
            return:   
            CiphertextBlob    
            KMSExceptionBase  exception                           KMSException            
        '''
        params = {}
        params['ciphertextBlob'] = CiphertextBlob
        if EncryptionContext != None :
            params['encryptionContext'] = EncryptionContext
        
        ret_pkg = self.kms_client.decrypt(params)
        return base64.b64decode(ret_pkg['plaintext'])
    
    def set_key_attributes(self, KeyId=None, Alias=None):
        '''set  key attributes
            @params            @description                       @type            @default     @value
            input:
            KeyId             the key id
            Alias             the key alias                       string           not null      1-32Bytes                        
            return: 
            KMSExceptionBase  exception                           KMSException           
        '''
        params = {}
        if KeyId != None :
            params['keyId'] = KeyId
        if Alias != None :
            params['alias'] = Alias
        ret_pkg = self.kms_client.set_key_attributes(params)
       
    def get_key_attributes(self, KeyId=None):
        ''' get data key attributes
            @params            @description                       @type            @default     @value
            input:
            KeyId             the key id                        
            return: 
            KeyMeta           the key information                 KeyMeta 
            KMSExceptionBase  exception                           KMSException           
        '''
        params = {}
        params['keyId'] = KeyId
        ret_pkg = self.kms_client.get_key_attributes(params)
        key_meta = KeyMetadata()
        self.__resp2meta(key_meta, ret_pkg)
        return key_meta
        
    def enable_key(self, KeyId=None):
        ''' enable a data key 
            @params            @description                       @type            @default     @value
            input:
            KeyId             the key id                        
            return: 
            KMSExceptionBase  exception                           KMSException           
        '''
        params = {}
        params['keyId'] = KeyId
        self.kms_client.enable_key(params)
        
    def disable_key(self, KeyId=None):
        ''' disable a data key 
            @params            @description                       @type            @default     @value
            input:
            KeyId             the key id                        
            return: 
            KMSExceptionBase  exception                           KMSException            
        '''
        params = {}
        params['keyId'] = KeyId
        self.kms_client.disable_key(params)
        
    def list_key(self, offset=0, limit=10):
        ''' list the data keys 
            @params            @description                       @type            @default     @value
            input:
            Offset                                                int                0
            Limit             limit of the number of the keys     int               10                     
            return:
            Keys              the keys array                      array
            TotalCount        the number of the keys              int
            Offset                                                int
            Limit                                                 int
            KMSExceptionBase  exception                           KMSException            
        '''
        params = {}
        if offset > 0 :
            params['offset'] = offset
        if limit > 0:
            params['limit'] = limit
        ret_pkg = self.kms_client.list_key(params)
        return (ret_pkg['totalCount'], ret_pkg['keys'])
    
    
    def schedule_key_deletion(self, KeyId, pendingWindowInDays):
        
        params = {
            'keyId':KeyId,
            'pendingWindowInDays':pendingWindowInDays
            }
        self.kms_client.schedule_key_deletion(params)
    
    def cancel_key_deletion(self, KeyId):
        
        params = {
            'keyId':KeyId,
            }
        self.kms_client.cancel_key_deletion(params)
    def encryptLocalAES(self, key, text):
        crypto = AES.new(key, AES.MODE_CBC, iv=key)
        length = 16
        count = len(text)
        add = count % length
        if add:
            text = text = ('\0' * (length - add))
        return base64.b64encode(crypto.encrypt(text))
        
    def decryptLocalAES(self, key, text):
        crypto = AES.new(key, AES.MODE_CBC, iv=key)
        return crypto.decrypt(base64.b64decode(text)).rstrip('\0')
    
        
        
        
