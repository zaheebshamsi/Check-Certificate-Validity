# checks if the certificate is valid
# Zaheeb Shamsi
# Function o chekc the certificate validity Rel 1.0
# 5/Jan/2020

from datetime import datetime
from sshConnectionClass import *
from encDecryptPassword import encDecryptPassword
import logging

logger = logging.getLogger('check')


def certificateCheck(product, target):

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
                        if not prd['target']['operatingSystem'] == 'linux':
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
                            port = 22
                            obj = sshGetConnectionAPI(host=target_host_name, username=target_user)
                            obj.sshGetConnection(password=target_password, port=port)
                            certPath = product["configuration"]["check"]["sec"]["certificatePathLin"]
                            cmd = "openssl x509 -in {0} -noout -enddate".format(certPath)
                            out, err = obj.sshExecCmd(cmd)

                            if "Error opening Certificate {0}".format(certPath) in out:
                                logger.debug("Certificate File doesn't exist or wrong path. ,11")
                                print("Certificate File doesn't exist or wrong path. ,11\n")
                            else:
                                date1 = str(out[0])
                                date1 = date1.split('=')  # recursively using date1 variable in order
                                date1 = str(date1[1])  # to not consume much variable space.
                                date1 = date1.split(' ')
                                cert_expiry_date = datetime.strptime(
                                    "{0}{1}{2} {3}".format(str(date1[4]), str(date1[0]), str(date1[2]), str(date1[3])),
                                    '%Y%b%d %H:%M:%S')
                                print("Certificate expiry date and time: {0}".format(str(cert_expiry_date)))
                                if datetime.utcnow() < cert_expiry_date:
                                    logger.debug("Certificate Valid on host {0} ,0".format(target_host_name))
                                    print("Certificate Valid on host {0} ,0\n".format(target_host_name))
                                    flag = 1
                                else:
                                    logger.debug("Certificate Invalid on host {0} ,1".format(target_host_name))
                                    print("Certificate Invalid on host {0} ,1\n".format(target_host_name))
                                    flag = 0

                    if flag == 1:
                        return 0
                    else:
                        return 1

        except Exception as e:
            print(e)
