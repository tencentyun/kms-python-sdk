#!/usr/bin/python
# -*- coding: -utf-8 -*-

'''
  file:kms_log.py
  author:yorkxyzhang
  function:
  history:
      date   author  description
'''


import sys
import string
import types
import logging
import logging.handlers
from kms.kms_exception import *

METHODS = ["POST", "GET"]
class KMSLogger:
    @staticmethod
    def get_logger(log_name="KMS_python_sdk", log_file="KMS_python_sdk.log", log_level=logging.INFO):
        logger = logging.getLogger(log_name)
        if logger.handlers == []:
            fileHandler = logging.handlers.RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024)
            formatter = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] [%(filename)s:%(lineno)d] [%(thread)d] %(message)s', '%Y-%m-%d %H:%M:%S')
            fileHandler.setFormatter(formatter)
            logger.addHandler(fileHandler)
        KMSLogger.validate_loglevel(log_level)
        logger.setLevel(log_level)
        return logger

    @staticmethod
    def validate_loglevel(log_level):
        log_levels = [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL]
        if log_level not in log_levels:
            raise KMSClientParameterException("LogLevelInvalid", "Bad value: '%s', expect levels: '%s'." % \
                (log_level, ','.join([str(item) for item in log_levels])))
