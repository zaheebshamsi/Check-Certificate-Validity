# checks if the certificate is valid
# Supported Format: .cer , .pem
# @TODO : Add supported formats to - .pkcs and .crt and .pfx
# Zaheeb Shamsi
# Function o chekc the certificate validity Rel 1.0
# 5/Jan/2020
# Pre-req python modules--- OpenSSSL , pem
# pip install pyOpenSSL
# pip install pem

import OpenSSL
import sys
from datetime import datetime
import os
import pem
import subprocess

def certificateCheck(certPath):
    try:
        for filename in os.listdir(certPath):
            if filename.endswith('.pem') or filename.endswith('.cer'):  # pfx to be added
                print("\n****Validity check for: {0}****\n".format(filename))
                if filename.endswith('.pem'):
                    file_path = os.path.join(certPath, filename)
                    certs = pem.parse_file(file_path)  # using pem module
                    for pem_certificates in certs:
                        strcert = str(pem_certificates)
                        loadCert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, strcert)  # FILETYPE_ASC1
                        issuer = loadCert.get_issuer()
                        issuer_str = "".join("/{0:s}={1:s}".format(name.decode(), value.decode()) for name, value in issuer.get_components())
                        print("Issuer:" , issuer_str)
                        date = datetime.strptime(loadCert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                        print("Certificate expiry date and time: {0}".format(str(date)))
                        if datetime.utcnow() < date:
                            print("Certificate Valid. ,0")
                        else:
                            print("Certificate has expired. ,1")
                else:
                    file_path = os.path.join(certPath, filename).encode('utf-8')
                    loadCert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM , open(file_path).read())  # FILETYPE_ASN1
                    date = datetime.strptime(loadCert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    issuer = loadCert.get_issuer()
                    issuer_str = "  ".join("/{0:s}={1:s}".format(name.decode(), value.decode()) for name, value in issuer.get_components())
                    print("Issuer:" , issuer_str)
                    print("Certificate expiry date and time: {0}".format(str(date)))
                    if datetime.utcnow() < date:
                        print("Certificate Valid. ,0")
                    else:
                        print("Certificate has expired. ,1")

    except Exception as e:
        exception_type, exception_object, exception_traceback = sys.exc_info()
        line_number = exception_traceback.tb_lineno
        print("Line number: ", line_number)
        print("Exception")
        print(e)

if __name__ == "__main__":
    #certificateCheck("/home/zaheebscr/test")
