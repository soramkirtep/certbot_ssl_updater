"""
Author Maroš Petrík, 2020-9

Prerequisite:
Python 3.6.5
Java JDK
Tomcat
Certbot
Python
Open ports 80, 443

- install (in this order) python, add path to python in env var, openssl, certbot 
- install pip "python %JBOSS_HOME%\..\scripts\certbot_ssl_updater\materials\get-pip.py"
- install "pip install -r %JBOSS_HOME%\..\scripts\certbot_ssl_updater\requrements.txt"
- edit main.conf
- runs certbot_ssl_updater\run.bat

"""

import winreg 
import fileinput
import sys
import win32serviceutil
import subprocess
import time
import configparser
import os
import logging
import logging.config
from shutil import copyfile

logging.config.fileConfig("logging.conf")

logging.info("Getting data from configuration file")
conf = configparser.ConfigParser()
conf.read('main.conf')
java = os.environ['JAVA_HOME']


SERVICE = conf.get("server", "service")
TOMCAT_PROPERTIES = conf.get("server", "tomcat_properties")
TIME_TO_SLEEP = 5
HTTP = conf.get("server", "port_http")
HTTPS = conf.get("server", "port_https")
PASS = conf.get("server", "pass")
CERTBOT_PATH = conf.get("server", "certbot_path")


DOMAIN = conf.get("domain", "host")
# CERTBOT: Change second param between certbot_certonly and certbot_certonly_test
CERTBOT_CERTONLY = conf.get("domain", "certbot_certonly")
# CERTBOT_RENEW: Change second param between certbot_renew and certbot_renew_test
CERTBOT_RENEW = conf.get("domain", "certbot_renew")
EMAIL = conf.get("domain", "email")
KEYTOOL = conf.get("domain", "keytool")
KEYSTORE = conf.get("domain", "keystore")


def service_status(service):
    """
    Checks service status, returns int: 
    1 = stopped
    2 = stop pending
    3 = start pending
    4 = running
    """
    try:
      status = win32serviceutil.QueryServiceStatus(service)[1]
      return status
    except WindowsError:
        return None


def start_service(service):
    subprocess.run('net start '+ service)


def stop_service(service):
    subprocess.run('net stop '+ service +' /yes')


def service_reg_data_path(service):
    """
    Gets data from registry and returns service directory path. 
    """
    try:
        REG_PATH = f"SYSTEM\\CurrentControlSet\\Services\\{service}"
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0,winreg.KEY_READ)
        value, something = winreg.QueryValueEx(registry_key, 'ImagePath')
        winreg.CloseKey(registry_key)
        path = value.split('"')[-2].split('\\')[0:-2]
        location = '\\'.join([str(elem) for elem in path])
        return location
    except WindowsError:
        return None


def change_port(file, searchExp, replaceExp):
    """
    Params: 1_file to change, 2_lookup line with value, 3_new value
    Rewrites line in file if search=True  
    """
    for line in fileinput.input(file, inplace=1):
        if searchExp in line:
            line = line.replace(searchExp, replaceExp)
        sys.stdout.write(line)


def certbot_domain_check(certbot, email, domain):
    """
    Cerbot checks domain and issues .pen files in ~\Cerbot\live\ directory. 
    """
    try:
        result = subprocess.call(f"{certbot} -m {email} -d {domain}", shell=True)
        if result == 1:
            print('There is a error in certbot')
        else:
            print('Certificate was issued and stored')
    except WindowsError:
        None


def certbot_renew_cert(certbot_renew):
    """
    Certbot try renew .pem files and if these are not yet to expire, it skips the renew task and returns msg.
    """
    try:
        result = subprocess.check_output(certbot_renew, shell=True)
        return str(result).split("\\r\\n")[3-6].split(".")[0]
    except WindowsError:
        None


def openssl_create_pkcs12(certbot, domain, password):
    """
    Openssl creates pkcs12 file from ~\Certbot\~\some_domain.pem files in ~\Certbot\~\live directory.
    """
    try:
        openssl_command = f"openssl pkcs12 -export -out {certbot}{domain}_fullchain_and_key.p12 -in {certbot}live\\{domain}\\fullchain.pem -inkey {certbot}live\\{domain}\\privkey.pem -name tomcat -passout pass:{password}"
        result = subprocess.call(openssl_command, shell=True)
        if result == 1:
            print('Problem to create .p12')
        else:
            print('pkcs12 was issued and stored')
    except WindowsError:
        None


def delete_keystore_if_exists(certbot, keystore):
  if os.path.exists(certbot + keystore):
    os.remove(certbot + keystore)
  else:
    print("The file does not exist")


def keytool_create_jks(keytool, keystore, certbot, domain, password):
    """
    Keytool command to create .jks file from PKCS12 file, returns 0 or 1 if error. 
    """
    try:
        keytool_command = f"""{java}{keytool} -importkeystore -deststorepass {password} -destkeypass {password} -destkeystore {certbot}{keystore} -srckeystore {certbot}{domain}_fullchain_and_key.p12 -srcstoretype PKCS12 -srcstorepass {password} -alias tomcat"""
        
        result = subprocess.call(keytool_command, shell=True)
        if result == 1:
            print(f'Problem to create {keystore}')
        else:
            print(f'{keystore} has been created successfully')
    except WindowsError:
        print(f'Main problem to create {keystore}', sys.exc_info()[0])


# Script starts here________________________________________
def change_cert_format():
    """
    From issued/renewed .pem certificates creates pkcs12 file, deletes old keystore if exists, 
    remakes pkcs12 to .jks and store it in ~\{tomcat}\conf. 
    """
    try:
        logging.info("Remaking certifikate from .pem through pkcs12 to .jks")
        # 5. Create .p12 certificate
        openssl_create_pkcs12(CERTBOT_PATH, DOMAIN, PASS)
        # 6. check if keystore already exists and delete it 
        delete_keystore_if_exists(CERTBOT_PATH, KEYSTORE)
        # 7. create kyestore.jks
        keytool_create_jks(KEYTOOL, KEYSTORE, CERTBOT_PATH, DOMAIN, PASS)
        # 8. Replace keystore in directory
        wc_service_conf = str(service_reg_data_path(SERVICE)) + "\\conf\\"
        copyfile(CERTBOT_PATH + KEYSTORE, wc_service_conf + KEYSTORE)
        print(f'{KEYSTORE} is copied in {wc_service_conf}')
        logging.debug(f'{KEYSTORE} is copied in {wc_service_conf}')
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise SystemError("There is a problem with reformating .pem through pkcs12 to .jks.")


def start():
    logging.info("Starting script")
    """
    Main funcion call.
    Gets ~\{tomcat}\conf directory from registry
    Stops service if running
    Checks if specific cert already exists and renew cert or issue new one
    Calls change_cert_format() to reformat cert
    Changes config from http to https
    Starts WC to run on https
    """
    try:
        # 1. Get ~\{tomcat}\conf directory from registry
        logging.info("Looking for service path in registry")
        wc_conf = str(service_reg_data_path(SERVICE) + TOMCAT_PROPERTIES)

        # Change port on which tomcat is running
        # logging.info("Changing port config")
        # change_port(wc_conf, HTTPS, HTTP)

        # 2. Stop service if running
        logging.info(f"Stopping service {SERVICE}")
        status = service_status(SERVICE)
        if status == 4:
            # Restart WC to run on http
            stop_service(SERVICE)
        else:
            print(f'{SERVICE} is already stopped')
            logging.info(f'{SERVICE} is already stopped')

        # 3. Check if specific cert already exists and renew cert or issue new one
        fullchain = os.path.exists(f"{CERTBOT_PATH}live\\{DOMAIN}\\fullchain.pem")
        privkey = os.path.exists(f"{CERTBOT_PATH}live\\{DOMAIN}\\privkey.pem")
        
        if fullchain != 1 or privkey != 1:
            logging.info(f"fullchain.pem or privkey.pem does not exists in path {CERTBOT_PATH}live\\{DOMAIN}\\.")
            logging.info(f"New certificate need to be issued.")
            certbot_domain_check(CERTBOT_CERTONLY, EMAIL, DOMAIN)
            change_cert_format()
        else:
            certbot_renew_status = certbot_renew_cert(CERTBOT_RENEW)
            if certbot_renew_status == "No renewals were attempted":
                logging.info(f"{certbot_renew_status}, {KEYSTORE} file is not due yet.")
                print(f"{certbot_renew_status}, {KEYSTORE} file is not due yet.")
            else:
                logging.info(f'Certbot renewed .pem files and {KEYSTORE} is due and need to be renewed too.')
                print(f'Certbot renewed .pem files and {KEYSTORE} is due and need to be renewed.')
                # 4. Change cert format from .pem to .jks
                change_cert_format()
        

        # 9. Change config from http to https
        # logging.info("Changing port config")
        # change_port(wc_conf, HTTP, HTTPS)
        

        # 10. Start WC to run on https
        logging.info(f"Starting service {SERVICE}")
        start_service(SERVICE)
        logging.info("Script ended without error.\n")
    except:
        print("Unexpected error:", sys.exc_info()[0])
        logging.info("Script ended with error")
        raise
    

if __name__ == '__main__':
    start()
    
