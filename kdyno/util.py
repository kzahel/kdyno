from email.utils import formatdate
from hashlib import sha256
class HmacKeys(object):
    """Key based Auth handler helper."""

    def __init__(self, host, config, secret_key):
        self.host = host
        self.update_secret(secret_key)

    def update_secret(self, secret_key):
        self._hmac_256 = hmac.new(secret_key,
                                  digestmod=sha256)

    def algorithm(self):
        return 'HmacSHA256'

    def sign_string(self, string_to_sign):
        if self._hmac_256:
            hmac = self._hmac_256.copy()
        else:
            hmac = self._hmac.copy()
        hmac.update(string_to_sign)
        return base64.encodestring(hmac.digest()).strip()


#class HmacAuthV3HTTPHandler(AuthHandler, HmacKeys):
class HmacAuthV3HTTPHandler(HmacKeys):
    """
    Implements the new Version 3 HMAC authorization used by DynamoDB.
    """
    
    capability = ['hmac-v3-http']
    
    def __init__(self, host, config, provider):
        #AuthHandler.__init__(self, host, config, provider)
        HmacKeys.__init__(self, host, config, provider)

    def headers_to_sign(self, http_request):
        """
        Select the headers from the request that need to be included
        in the StringToSign.
        """
        headers_to_sign = {}
        headers_to_sign = {'Host' : self.host}
        for name, value in http_request.headers.items():
            lname = name.lower()
            if lname.startswith('x-amz'):
                headers_to_sign[name] = value
        return headers_to_sign

    def canonical_headers(self, headers_to_sign):
        """
        Return the headers that need to be included in the StringToSign
        in their canonical form by converting all header keys to lower
        case, sorting them in alphabetical order and then joining
        them into a string, separated by newlines.
        """
        l = ['%s:%s'%(n.lower().strip(),
                      headers_to_sign[n].strip()) for n in headers_to_sign]
        l.sort()
        return '\n'.join(l)
        
    def string_to_sign(self, http_request):
        """
        Return the canonical StringToSign as well as a dict
        containing the original version of all headers that
        were included in the StringToSign.
        """
        headers_to_sign = self.headers_to_sign(http_request)
        canonical_headers = self.canonical_headers(headers_to_sign)
        string_to_sign = '\n'.join([http_request.method,
                                    http_request.path,
                                    '',
                                    canonical_headers,
                                    '',
                                    http_request.body])
        return string_to_sign, headers_to_sign
        
    def add_auth(self, req, security_token=None, access_key=None):
        """
        Add AWS3 authentication to a request.

        :type req: :class`boto.connection.HTTPRequest`
        :param req: The HTTPRequest object.
        """
        # This could be a retry.  Make sure the previous
        # authorization header is removed first.
        if 'X-Amzn-Authorization' in req.headers:
            del req.headers['X-Amzn-Authorization']
        req.headers['X-Amz-Date'] = formatdate(usegmt=True)
        req.headers['X-Amz-Security-Token'] = security_token
        string_to_sign, headers_to_sign = self.string_to_sign(req)
        hash_value = sha256(string_to_sign).digest()
        b64_hmac = self.sign_string(hash_value)
        s = "AWS3 AWSAccessKeyId=%s," % access_key
        s += "Algorithm=%s," % self.algorithm()
        s += "SignedHeaders=%s," % ';'.join(headers_to_sign)
        s += "Signature=%s" % b64_hmac
        req.headers['X-Amzn-Authorization'] = s


import hmac
import hashlib
import base64
#sixapart signing stuff
class SignatureMethod(object):
    def build_signature_base_string(self, request):
        sig = '\n'.join( (
            request.get_normalized_http_method(),
            request.get_normalized_http_host(),
            request.get_normalized_http_path(),
            request.get_normalized_parameters(),
            ) )
        return sig


class SignatureMethod_HMAC_SHA256(SignatureMethod):
    name = 'HmacSHA256'
    version = '2'

    def build_signature(self, request, aws_secret):
        base = self.build_signature_base_string(request)
        hashed = hmac.new(aws_secret, base, hashlib.sha256)
        return base64.b64encode(hashed.digest())

signer = SignatureMethod_HMAC_SHA256()


