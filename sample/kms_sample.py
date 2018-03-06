#!/usr/bin/env python
# coding=utf8

'''
    @file:kms_sample.py
    @description: kms sample
    @author:yorkxyzhang
    @date:2017-3-2

'''

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from kms.kms_account import KMSAccount
from kms.kms_exception import *

if __name__ == "__main__":
    try:
        secretId = "your secret id"
        secretKey = "your secret key"
        endpoint = "your endpoint "
        kms_account = KMSAccount(endpoint, secretId, secretKey)

        # create a custom master key
        Description = "test"
        Alias = "test"
        KeyUsage = "ENCRYPT/DECRYPT"
        kms_meta = kms_account.create_key(Description, Alias, KeyUsage)
        print kms_meta

        # create a data key
        KeySpec = "AES_128"
        Plaintext , CiphertextBlob = kms_account.generate_data_key(kms_meta.KeyId, KeySpec)
        print "the data key : %s \n  the encrypted data key :%s\n" % (Plaintext, CiphertextBlob)

        # encrypt the data string
        Plaintest = "test message data"
        CiphertextBlob = kms_account.encrypt(kms_meta.KeyId, Plaintest)
        print "the encrypted data is :%s \n" % CiphertextBlob

        # decrypt the encrypted data string
        Plaintest = kms_account.decrypt(CiphertextBlob)
        print "the decrypted data is :%s\n" % Plaintest

        # get key attributes
        key_meta = kms_account.get_key_attributes(kms_meta.KeyId)
        print key_meta

        # set key attributes
        Alias = "ForTest"
        kms_account.set_key_attributes(key_meta.KeyId, Alias)
        
        # disabke a custom key
        kms_account.disable_key(key_meta.KeyId)
        # enable a custom key
        kms_account.enable_key(key_meta.KeyId)

        # schedule deletion a custom key 
        kms_account.schedule_key_deletion(key_meta.KeyId, 7)
        
        # cancel a custom key deletion 
        kms_account.cancel_key_deletion(key_meta.KeyId)

        # list key
        totalCount, keys = kms_account.list_key()
        print keys

    except KMSExceptionBase, e:
        print "Exception:%s\n" % e
