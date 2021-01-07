# checks if the certificate is valid
# Zaheeb Shamsi
# Function o chekc the certificate validity Rel 1.0
# 5/Jan/2020

from datetime import datetime
from winRemoteConnectionClass import *
from encDecryptPassword import encDecryptPassword
import logging

logger = logging.getLogger('check')


def certificateCheckWin(product, target):

    if not product["configuration"]["check"]["sec"]["certificateCheck"]:
        logger.debug("Trigger for Security Certificate Validity Check not found, 0")
        print("Trigger for Security Certificate Validity check not found, 0")
        return
    else:
        logger.debug('Starting to run Security Certificate Validity check')
        print('Starting to run Security Certificate Validity check')
        try:
            prod = product["configuration"]["product"]
            flag = 0
            for prd in target["configuration"]["bundle"]["products"]:
                if prd["name"] != prod:
                    continue
                else:
                    for server in prd["target"]["hostNames"]:
                        if not prd['target']['operatingSystem'] == 'windows':
                            continue
                        else:
                            logger.debug('Trigger for operating system on ' + server + ' set')
                            print('Trigger for operating system on ' + server + ' set')
                            target_user = str(prd["target"]["security"]["userName"])
                            if prd["target"]["security"]["encrypted"]:
                                target_password = encDecryptPassword(prd["target"]["security"]['encryptionKey'],
                                                                     prd["target"]["security"]['password'])
                            else:
                                target_password = server(prd["target"]["security"]["password"])
                            target_host_name = str(server)
                            obj = WindowsNode(hostName=target_host_name, userName=target_user, password=target_password)
                            certPath = product["configuration"]["check"]["sec"]["certificatePathWin"]
                            cmd = "$CRT = New-Object System.Security.Cryptography.X509Certificates.X509Certificate ; $CRT.Import({0}) ; $CRT.GetExpirationDateString()".format(certPath)
                            out = obj.executePS(cmd)
                            print(out[-1])
                            print(type(out[0]))
                            err = "Exception calling \"Import\" with \"1\" argument(s):"
                            if err in out[-1] or out[0] == 1:
                                logger.debug("Certificate does not exist or wrong path. ,11")
                                print("Certificate does not exist or wrong path. ,11\n")
                                flag = 0
                            else:
                                cert_expiry_date = datetime.strptime(str(out[1]), '%m/%d/%Y %I:%M:%S %p\r\n')
                                print("Certificate expiry date and time: {0}".format(str(cert_expiry_date)))
                                if datetime.utcnow() < cert_expiry_date:
                                    logger.debug("Certificate Valid on host {0} ,0".format(target_host_name))
                                    print("Certificate Valid on host {0} ,0\n".format(target_host_name))
                                    flag = 1
                                else:
                                    logger.debug("Certificate Invalid on host {0} ,1".format(target_host_name))
                                    print("Certificate Invalid on host {0} ,1\n".format(target_host_name))
                                    flag = 0
                    '''if flag == 1:
                        return 0
                    else:
                        return 1'''

        except ConnectionError as c:
            logger.debug('cannot connect to host ' + server + ', 201')
            print(c)
            raise
        except KeyError as k:
            logger.debug("configuration file has wrong pattern, 51")
            print(k)
            raise
        except Exception as e:
            logger.debug("General Error, 1")
            print(e)
            raise
