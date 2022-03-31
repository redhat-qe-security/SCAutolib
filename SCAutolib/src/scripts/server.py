import re

import tempfile

import http
import http
import http.server
import python_freeipa as pipa
import ssl
from cryptography import x509
from subprocess import check_output, PIPE, run
import socket

cert_db = "/root/.mozilla/firefox/ccujsi73.default-release"
tmpdir = tempfile.mkdtemp()


def create_cert():
    ip = "192.168.122.34"
    hostname = "ipa-server-new.sc.test.com"
    admin = "admin"
    princ = "https-server-tmp"
    passwd = "SECret.123"
    csr_path = "server.csr"
    client = pipa.ClientMeta(hostname, verify_ssl=False)
    client.login(username=admin, password=passwd)
    with open(csr_path, "r") as f:
        csr = f.read()
    print(csr)
    print(princ)
    resp = client.cert_request(a_csr=csr, o_principal=princ)
    cert = resp["result"]["certificate"]
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    cert = f"{begin}\n{cert}\n{end}"
    with open("server.pem", "w") as f:
        f.write(cert)
    return "server.pem", "server-key.pem"


def start_server():
    server_address = ("127.0.0.1", 8888)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    # cert = "/root/server-opnessl/server.cert.pem"
    # key = "/root/server-opnessl/server.key.pem"
    cert, key = create_cert()
    # cert, key = "server.pem", "server-key.pem"
    # local_ca_cert = "/etc/SCAutolib/ca/rootCA.pem"
    local_ca_cert = "/etc/ipa/ca.crt"

    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   server_side=True,
                                   certfile=cert,
                                   keyfile=key,
                                   ca_certs=local_ca_cert,
                                   ssl_version=ssl.PROTOCOL_TLSv1_2,
                                   cert_reqs=ssl.CERT_REQUIRED,
                                   do_handshake_on_connect=True)

    # ssl.PROTOCOL_TLS_CLIENT = True
    # httpd.verify_request()
    try:
        print("Server is started")
        httpd.serve_forever()
    except:
        print("Server is stopped")


def create_client_nss_db():
    check_output(["certutil", "-N", "-d", tmpdir, "--empty-password"], encoding="utf-8")
    print(f"NSS db is created in {tmpdir}")
    name = "ipa-user-1-rhel-8"
    out = run(["certutil", "-A", "-n", "ipa-ca", "-t", 'TC,C,T', "-d",
               tmpdir, "-i", "/etc/ipa/ca.crt"], encoding="utf-8", stderr=PIPE,
              stdout=PIPE)

    assert out.returncode == 0, out
    print("CA cert is added to the nss database")
    out = check_output(["modutil", "-list", "-dbdir", tmpdir], encoding="utf-8")
    print(out)
    uri = re.search(rf"uri:\s(.*{name}.*)\n", out).group(1)
    print(f"URI for the card is {uri}")


if __name__ == "__main__":
    # start_server_ssl()
    # create_client_nss_db()
    start_server()
    # create_cert()
