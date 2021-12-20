'''
Security Tool Lab 1 - Project
SSL Grader

Submitted by: Rajaguru Rajasekaran
'''

from typing import Counter
import csv
import os
import validations
import argparse
import certifi
import requests
import subprocess
import re
import ssl
import math
import json
import socket
import OpenSSL 
from ocspchecker import ocspchecker
from datetime import datetime
import time

# Global variables

output_template = r"""
Certificate Grade for Server: %s

Certificate Score     : %s
Protocol Support      : %s
Key Exchange          : %s
Cipher suite          : %s

Certificate Grade     : %s

Server Score with Best configurations

Protocol Support      : %s
Cipher suite          : %s

Certificate Grade     : %s

Common Name                 :   %s
Subject Alternative Names   :   %s
Issuer                      :   %s
Serial Number               :   %s
SHA1 Thumbprint             :   %s
Publick Key Type            :   %s
Key Length                  :   %s         
Signature Algorithm         :   %s

Is_Valid Chain              :   %s
OCSP Origin                 :   %s
OCSP Status                 :   %s
CRL Status                  :   %s

The certificate expires     :   %s

Protocol's Supported        :   %s

Ciphers suite supported     :

%s

"""

path = os.getcwd()+"/"

with open(path+"cipher-ranking.json", 'r') as f:
    cipher_ranking = json.load(f)

'''
Certificate Class whose object holds information of cerificates, protocols used and supported ciphers
for the given host
'''
class Certificate:

    list_of_protocols = {
        OpenSSL.SSL.TLSv1_METHOD: "TLSv1",
        OpenSSL.SSL.TLSv1_2_METHOD: "TLSv1.2",
        OpenSSL.SSL.TLSv1_1_METHOD: "TLSv1.1",
        OpenSSL.SSL.SSLv23_METHOD: "SSLv2.3", }

    public_key_types = {
        OpenSSL.crypto.TYPE_RSA: 'RSA',
        OpenSSL.crypto.TYPE_DSA: 'DSA',
        408: 'id-ecPublicKey'}

    def __init__(self, host):
        self.hostname = host[0]
        self.port = host[1]

    def get_certificate(self):
        try:
            server_ip = socket.gethostbyname(self.hostname)
            server_port = self.port
            server_certificate = ssl.get_server_certificate(
                (server_ip, server_port))
            certificate_x509 = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, server_certificate)

            certificate_info = {
                'versionNumber': certificate_x509.get_version(),
                'serialNumber': hex(certificate_x509.get_serial_number())[2:].upper(),
                'signatureAlgorithmID': certificate_x509.get_signature_algorithm().decode(),
                'issuerName': {key.decode(): dict(certificate_x509.get_issuer().get_components())[key].decode() for key in dict(certificate_x509.get_issuer().get_components())},
                'subjectName': {key.decode(): dict(certificate_x509.get_subject().get_components())[key].decode() for key in dict(certificate_x509.get_subject().get_components())},
                'publicKey': OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, certificate_x509.get_pubkey()).decode(),
                'validNotBefore': datetime.strptime(certificate_x509.get_notBefore().decode(), '%Y%m%d%H%M%SZ'),
                'validNotAfter': datetime.strptime(certificate_x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ'),
                'hasExpired': certificate_x509.has_expired()
            }

            extensions = (certificate_x509.get_extension(index)
                          for index in range(certificate_x509.get_extension_count()))
            extension_data = {extension.get_short_name().decode(): str(
                extension) for extension in extensions}
            certificate_info.update(extension_data)
            self.certificate_details = certificate_info
            self.certificate_x509 = certificate_x509

        except Exception as exception:
            print('Error!\n'+exception)

    def verify_certificate_chain(self):
        self.certificate_chain = list()
        try:
            for protocol in self.list_of_protocols:
                try:
                    context = OpenSSL.SSL.Context(method=protocol)
                    context.set_verify(OpenSSL.SSL.VERIFY_PEER)
                    context.load_verify_locations(cafile=certifi.where())
                    conn = OpenSSL.SSL.Connection(
                        context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                    conn.settimeout(5)
                    conn.connect((self.hostname, 443))
                    conn.setblocking(1)
                    conn.do_handshake()
                    conn.set_tlsext_host_name(self.hostname.encode())
                    return [{"subject": cert.get_subject(),
                            "issuer": cert.get_issuer(),
                             "fingerprint": cert.digest("sha1").decode()}
                            for cert in conn.get_verified_chain()]
                except Exception:
                    continue
        except Exception as e:
            print('Error............!\n'+str(e))

    def verify_ocsp_status(self):
        self.ocsp_status = None
        ocsp_response = ocspchecker.get_ocsp_status(self.hostname)
        if len(ocsp_response) > 2:
            ocsp_status = {
                "status": ocsp_response[2].lstrip("OCSP Status: "),
                "url": ocsp_response[1].lstrip("OCSP URL: ")}
            self.ocsp_status = ocsp_status
        else:
            ocsp_status = {"status": ocsp_response[0]}

    def verify_crl(self):
        pattern = r'URI:(\S+)'
        self.crl_status = False
        if "crlDistributionPoints" in self.certificate_details:
            for crl_url in re.findall(pattern, self.certificate_details["crlDistributionPoints"]):
                crl_response = requests.get(crl_url)
                crl = OpenSSL.crypto.load_crl(
                    OpenSSL.crypto.FILETYPE_ASN1, crl_response.content)
                if crl.get_revoked():
                    rev_serial_numbers = [rev.get_serial().decode()
                                          for rev in crl.get_revoked()]
                    if self.certificate_details["serialNumber"] in rev_serial_numbers:
                        self.crl_status = True

    def get_server_accepted_ciphers_and_versions(self):
        self.supproted_ciphers = list()
        self.supported_protocols = list()
        cmd = ['pysslscan', 'scan', '--scan=server.ciphers',
               '--tls', '--ssl', self.hostname]
        output = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

        for line in output.stdout.readlines():
            line = ansi_escape.sub('', line.decode().strip())
            if (line.strip().startswith("Accepted") or line.strip().startswith("Preferred")):
                server_supported = line.split(" ")
                if server_supported[2] not in self.supported_protocols:
                    self.supported_protocols.append(server_supported[2])
                self.supproted_ciphers.append(server_supported[-1])

    def get_certificate_score(self):
        certificate_data = dict()
        certificate_data['hostname'] = self.hostname
        certificate_data['common_name'] = self.certificate_details["subjectName"]["CN"]
        certificate_data["subj_alt_names"] = self.certificate_details[
            "subjectAltName"] if 'subjectAltName' in self.certificate_details else ""
        certificate_data["issuerName"] = self.certificate_details["issuerName"]["CN"]
        certificate_data["serial_number"] = self.certificate_details["serialNumber"]
        certificate_data["is_cert_chain_verified"] = True if self.certificate_chain else False
        certificate_data["sha_thumbprint"] = self.certificate_chain[0]["fingerprint"].replace(
            ':', '') if self.certificate_chain else None
        certificate_data["public_key_type"] = self.public_key_types[self.certificate_x509.get_pubkey(
        ).type()]
        certificate_data["public_key_length"] = self.certificate_x509.get_pubkey(
        ).bits()
        certificate_data["signature_algorthm"] = self.certificate_details["signatureAlgorithmID"]
        certificate_data["expirey_date"] = self.certificate_details["validNotAfter"]
        certificate_data["is_expired"] = self.certificate_details["hasExpired"]
        certificate_data["is_revocked"] = self.crl_status
        certificate_data["ocsp_status"] = self.ocsp_status
        certificate_data["supproted_cipher_suite"] = self.supproted_ciphers
        certificate_data["supported_protocols"] = self.supported_protocols
        certificate_score = CertificateScore(certificate_data)
        certificate_score.get_score()
        self.certificate_grade = certificate_score.certificate_grade
        self.best_grade = certificate_score.best_grade
        self.scan_out = certificate_score.scan_out

class CertificateScore:

    protocols_scores = {"TLSv10": 50, "TLSv12": 100,
                        "TLSv13": 100, "TLSv11": 70, "SSLv23": 50}

    strong_publickeys = ['RSA', 'DSA']

    def __init__(self, certificate_data):
        self.hostname = certificate_data["hostname"]
        self.common_name = certificate_data["common_name"]
        self.subj_alt_names = certificate_data["subj_alt_names"]
        self.issuerName = certificate_data["issuerName"]
        self.serial_number = certificate_data["serial_number"]
        self.is_cert_chain_verified = certificate_data["is_cert_chain_verified"]
        self.sha_thumbprint = certificate_data["sha_thumbprint"] if self.is_cert_chain_verified else None
        self.public_key_type = certificate_data["public_key_type"]
        self.public_key_length = certificate_data["public_key_length"]
        self.signature_algorthm = certificate_data["signature_algorthm"]
        self.expirey_date = certificate_data["expirey_date"]
        self.is_expired = certificate_data["is_expired"]
        self.is_revocked = certificate_data["is_revocked"]
        self.supproted_cipher_suite = certificate_data["supproted_cipher_suite"]
        self.ocsp_status = certificate_data["ocsp_status"]
        self.supported_protocols = certificate_data["supported_protocols"]

    def get_score(self):
        self.score_cipher()
        self.score_certificate()
        self.score_public_key()
        self.score_protocol()
        self.calculate_score()
        self.certificate_grade = self.get_grade(self.total_score)
        self.best_grade = self.get_grade(self.best_score)
        self.print_details()

    def calculate_score(self):
        if self.is_valid_certificate:
            self.total_score = (self.certificate_score + self.protocol_score +
                                self.public_key_score + self.cipher_score)/4
            self.best_score = (self.certificate_score + self.max_protocol_score +
                               self.public_key_score + self.max_cipher_score)/4
        else:
            self.total_score = 0
            self.best_score = 0

    def get_grade(self, score):

        if score >= 95:
            certificate_grade = 'O'
        elif score >= 90:
            certificate_grade = 'A'
        elif score >= 80:
            certificate_grade = 'B'
        elif score >= 70:
            certificate_grade = 'C'
        elif score >= 60:
            certificate_grade = 'D'
        elif score >= 50:
            certificate_grade = 'E'
        else:
            certificate_grade = 'F'
        return certificate_grade

    def score_certificate(self):
        self.certificate_score = 100
        self.is_valid_certificate = True
        if self.is_expired or self.is_revocked or self.ocsp_status["status"] != 'GOOD' or not self.is_cert_chain_verified:
            self.certificate_score = 0
            self.is_valid_certificate = False

    def score_protocol(self):
        protocol_scores = [self.protocols_scores[protocol]
                           for protocol in self.supported_protocols]
        self.protocol_score = min(protocol_scores)
        self.max_protocol_score = max(protocol_scores)

    def score_public_key(self):
        if self.public_key_type in self.strong_publickeys:
            strength = (1/math.log(2)) * (1.923 * pow(self.public_key_length*math.log(2), 1/3)
                                          * pow(math.log(self.public_key_length * math.log(2)), 2/3) - 4.69)
        else:
            strength = self.public_key_length/2
        self.public_key_score = min(
            100, int(math.ceil((strength/128*100)/10.0)) * 10)

    def score_cipher(self):
        supported_cipher_ranks = list()

        for cipher_suite in self.supproted_cipher_suite:
            try:
                if cipher_ranking[cipher_suite]:
                    supported_cipher_ranks.append(cipher_ranking[cipher_suite])
                else:
                    if 'ADH' in cipher_suite or 'RC4' in cipher_suite or 'NULL' in cipher_suite or 'DSS' in cipher_suite:
                        supported_cipher_ranks.append(0)
                    else:
                        supported_cipher_ranks.append(0)
            except KeyError as error:
                print(error)

        self.cipher_score = min(supported_cipher_ranks)
        self.max_cipher_score = max(supported_cipher_ranks)

    def print_details(self):
        output = (self.hostname, self.certificate_score, self.protocol_score, self.public_key_score, self.cipher_score, self.certificate_grade, self.max_protocol_score, self.max_cipher_score, self.best_grade, self.common_name, self.subj_alt_names, self.issuerName, self.serial_number, self.sha_thumbprint,
                  self.public_key_type, self.public_key_length, self.signature_algorthm, str(
                      self.is_cert_chain_verified), self.ocsp_status['url'], self.ocsp_status['status'],
                  'Not Revocked' if not self.is_revocked else 'Revocked', self.expirey_date, self.supported_protocols, self.supproted_cipher_suite)
        # print(output_template[62])
        scan_out = output_template % output
        self.scan_out = scan_out

def format_host(host):
    valid_host = list()

    if validations.is_valid_hostname(host):
        valid_host.append(host)
        valid_host.append(443)
    else:
        print("[!] Invalid hostname......", host)
        return False
    return valid_host

def start_scan(hostname):

    try:
        host = format_host(hostname)

        print("[+] Grading host....{}". format(host))
        current_host = Certificate(host)
        print("[+] Getting Certificate Details........")
        current_host.get_certificate()
        print("[+] Verifyig certificate chain.........")
        current_host.certificate_chain = current_host.verify_certificate_chain()
        print("[+] Verifyig certificate Revocation....")
        current_host.verify_crl()
        print("[+] Verifying OCSP status..............")
        current_host.verify_ocsp_status()
        print("[+] Checking Server support............")
        current_host.get_server_accepted_ciphers_and_versions()
        print("[+] Getting Certificate Score..........")
        current_host.get_certificate_score()
        print(current_host.scan_out)
        return current_host.scan_out

    except Exception as exception:
        print("Error........", str(exception))

def parse_args():
    aparser = argparse.ArgumentParser(description='Script will score the domain SSL\TLS implementation.\
        \n script usage:\
        \n #> python ssl-grader.py --mode 1 --hostname domain.com\
        \n #> python ssl-grader.py --mode 2 --hostsfile hosts.csv', formatter_class=argparse.RawTextHelpFormatter)
    aparser.add_argument('--mode', required=False, choices=['1', '2'], metavar='mode', help="Script can run in two modes.\n 1 -> Run on single host\
        \n 2 -> Run on list of hosts from the csv file")
    aparser.add_argument('--hostname', required=False,
                         metavar='hostname', help='hostname of the server to score')
    aparser.add_argument('--hostsfile', required=False,
                         metavar='hostsfile', help='Hosts file in csv')
    args = aparser.parse_args()

    return args

if __name__ == '__main__':
    args = parse_args()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    output_file = open(path+'sslgrader_'+timestr+'.txt', 'a')

    if args.mode == '1':
        output_file.write(start_scan(args.hostname))
    elif args.mode == '2':
        grade_file = open(path+'ssl_grade_file_'+timestr+'.csv', 'a')
        with open(path+args.hostsfile, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                try:
                    host = list()
                    hostname = re.sub('[^A-Za-z0-9.]+', '', row[0])
                    host.append(hostname)
                    host.append(443)
                    print("[+] Grading host....{}". format(host))
                    current_host = Certificate(host)
                    current_host.get_certificate()
                    current_host.certificate_chain = current_host.verify_certificate_chain()

                    current_host.verify_crl()
                    current_host.verify_ocsp_status()
                    current_host.get_server_accepted_ciphers_and_versions()
                    current_host.get_certificate_score()
                    row.append(current_host.certificate_grade)
                    row.append(current_host.best_grade)
                    writer = csv.writer(grade_file)
                    writer.writerow(row)
                    output_file.write(current_host.scan_out)
                except Exception as exception:
                    print("Error........", hostname)
                    output_file.write(str(exception))
                    continue
            grade_file.close()
    output_file.close()
    output_msg = os.path.basename(output_file.name)
    print("script executed successfully, scan output is stored in "+output_msg)
