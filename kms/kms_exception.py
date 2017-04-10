#!/usr/bin/python
# -*- coding: -utf-8 -*-


class KMSExceptionBase(Exception):
    '''
    
    '''
    def __init__(self, message, code=-1, data={}):
        self.code = code 
        self.message = message,
        self.data = data
    def get_info(self):
        return 'Code:%s, Message:%s, Data:%s\n' % (self.code, self.message, self.data)

    def __str__(self):
        return "KMSExceptionBase  %s" % (self.get_info())
       
class KMSClientException(KMSExceptionBase):
    def __init__(self, message, code=-1, data={}):
        KMSExceptionBase.__init__(self, message, code, data)

    def __str__(self):
        return "KMSClientException  %s" % (self.get_info())
    
class KMSClientNetworkException(KMSClientException):
    """ 网络异常

        @note: 检查endpoint是否正确、本机网络是否正常等;
    """
    def __init__(self, message, code=-1, data={}):
        KMSClientException.__init__(self, message, code, data)

    def __str__(self):
        return "KMSClientNetworkException  %s" % (self.get_info())

class KMSClientParameterException(KMSClientException):
    """ 参数格式错误

        @note: 请根据提示修改对应参数;
    """
    def __init__(self, message, code=-1, data={}):
        KMSClientException.__init__(self, message, code, data)

    def __str__(self):
        return "KMSClientParameterException  %s" % (self.get_info())

class KMSServerNetworkException(KMSExceptionBase):
    """ 服务器网络异常
    """
    def __init__(self, status=200, header=None, data=""):
        if header == None:
            header = {}
        self.status = status
        self.header = header
        self.data = data

    def __str__(self):
        return "KMSServerNetworkException Status: %s\nHeader: %s\nData: %s\n" % \
            (self.status, "\n".join(["%s: %s" % (k, v) for k, v in self.header.items()]), self.data)

class KMSServerException(KMSExceptionBase):
    """ KMS处理异常

        @note: 
    """
    def __init__(self, message, request_id, code=-1, data={}):
        KMSExceptionBase.__init__(self, message, code, data)
        self.request_id = request_id

    def __str__(self):
        return "KMSServerException  %s\nRequestID:%s" % (self.get_info(), self.request_id)
