import re
import os, datetime, hashlib, hmac

import requests
import boto3


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def task_1_create_a_canonical_request(
        host,
        amzdate,
        method,
        security_token):
    """
    ************* TASK 1: CREATE A CANONICAL REQUEST *************
    http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    Step 1 is to define the verb (GET, POST, etc.)--already done.
    Step 2: Create canonical URI--the part of the URI from domain to query
    for lambda canonical_uri = '/'
    Step 3: Create the canonical query string. In this example (a GET request),
    request parameters are in the query string. Query string values must
    be URL-encoded (space=%20). The parameters must be sorted by name.
    For this example, the query string is pre-formatted in the
    request_parameters variable.
    """
    canonical_uri = '/'

    # Step 4: Create the canonical headers and signed headers. Header names
    # and value must be trimmed and lowercase, and sorted in ASCII order.
    # Note that there is a trailing \n.
    canonical_headers = ('host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n')
    canonical_headers += ('x-amz-security-token:' + security_token + '\n')

    # Step 5: Create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    # Note: The request can include any headers; canonical_headers and
    # signed_headers lists those that you want to be included in the
    # hash of the request. "Host" and "x-amz-date" are always required.
    signed_headers = 'host;x-amz-date'
    signed_headers += ';x-amz-security-token'

    # Step 6: Create payload hash (hash of the request body content). For GET
    # requests, the payload is an empty string ("").
    payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()

    # Step 7: Combine elements to create create canonical request
    canonical_request = (method + '\n' +
                         canonical_uri + '\n' +
                         '' + '\n' +
                         canonical_headers + '\n' +
                         signed_headers + '\n' +
                         payload_hash)

    return canonical_request, payload_hash, signed_headers


def task_2_create_the_string_to_sign(amzdate, datestamp, canonical_request, service, region):
    """
    ************* TASK 2: CREATE THE STRING TO SIGN*************
    Match the algorithm to the hashing algorithm you use, either SHA-1 or
    SHA-256 (recommended)
    """
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = (datestamp + '/' +
                        region + '/' +
                        service + '/' +
                        'aws4_request')
    string_to_sign = (algorithm + '\n' +
                      amzdate + '\n' +
                      credential_scope + '\n' +
                      hashlib.sha256(canonical_request.encode('utf-8')).hexdigest())

    return string_to_sign, algorithm, credential_scope


def task_3_calculate_the_signature(datestamp, string_to_sign, service, region, secret_key):
    """
    ************* TASK 3: CALCULATE THE SIGNATURE *************
    """

    def get_signature_key(key, date_stamp, region_name, service_name):
        """
        See: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
        In AWS Signature Version 4, instead of using your AWS access keys to sign a request, you
        first create a signing key that is scoped to a specific region and service.  For more
        information about signing keys, see Introduction to Signing Requests.
        """
        k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
        k_region = sign(k_date, region_name)
        k_service = sign(k_region, service_name)
        k_signing = sign(k_service, 'aws4_request')
        return k_signing

    # Create the signing key using the function defined above.
    signing_key = get_signature_key(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    encoded = string_to_sign.encode('utf-8')
    signature = hmac.new(signing_key, encoded, hashlib.sha256).hexdigest()
    return signature


def task_4_build_auth_headers_for_the_request(amzdate, payload_hash, algorithm, credential_scope, signed_headers,
                                              signature, access_key, security_token):
    """
    ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST ***********
    The signing information can be either in a query string value or in a header
    named Authorization. This function shows how to use the header.  It returns
    a headers dict with all the necessary signing headers.
    """
    # Create authorization header and add to request headers
    authorization_header = (
            algorithm + ' ' +
            'Credential=' + access_key + '/' + credential_scope + ', ' +
            'SignedHeaders=' + signed_headers + ', ' +
            'Signature=' + signature
    )

    # The request can include any headers, but MUST include "host",
    # "x-amz-date", and (for this scenario) "Authorization". "host" and
    # "x-amz-date" must be included in the canonical_headers and
    # signed_headers, as noted earlier. Order here is not significant.
    # Python note: The 'host' header is added automatically by the Python
    # 'requests' library.
    return {
        'Authorization': authorization_header,
        'x-amz-date': amzdate,
        'x-amz-security-token': security_token,
        'x-amz-content-sha256': payload_hash
    }


def url_path_to_dict(path):
    """http://stackoverflow.com/a/17892757/142207"""

    pattern = (r'^'
               r'((?P<schema>.+?)://)?'
               r'((?P<user>[^/]+?)(:(?P<password>[^/]*?))?@)?'
               r'(?P<host>.*?)'
               r'(:(?P<port>\d+?))?'
               r'(?P<path>/.*?)?'
               r'(\?(?P<query>.*?))?'
               r'$')
    regex = re.compile(pattern)
    url_match = regex.match(path)
    url_dict = url_match.groupdict() if url_match is not None else None

    if url_dict['path'] is None:
        url_dict['path'] = '/'

    if url_dict['query'] is None:
        url_dict['query'] = ''

    return url_dict


"""
    Inside a lambda, we can retrieve the credentials associated with the role using,
    session = Session()
    creds = session.get_credentials()
    print(f"{creds.access_key}, {creds.secret_key}, {creds.token}")
"""
def make_request(url, region, access_key, secret_key, token):
    host = url_path_to_dict(url)["host"]
    current_time = datetime.datetime.utcnow()
    amzdate = current_time.strftime('%Y%m%dT%H%M%SZ')
    datestamp = current_time.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    method = "GET"
    data = ''
    canonical_request, payload_hash, signed_headers = task_1_create_a_canonical_request(
        host,
        amzdate,
        method,
        token)
    string_to_sign, algorithm, credential_scope = task_2_create_the_string_to_sign(
        amzdate,
        datestamp,
        canonical_request,
        "lambda",
        "eu-west-1")
    signature = task_3_calculate_the_signature(
        datestamp,
        string_to_sign,
        "lambda",
        "eu-west-1",
        secret_key)
    auth_headers = task_4_build_auth_headers_for_the_request(
        amzdate,
        payload_hash,
        algorithm,
        credential_scope,
        signed_headers,
        signature,
        access_key,
        token)

    response = requests.get(url, headers=auth_headers)

    return response
