from sci_common.vault import VaultClient
from webfarmd.drivers.letsencrypt import LetsEncrypt
from webfarmd.drivers.ssl import SSLDriver
from webfarmd.drivers.ssh import SSHDriver
from webfarmd.models.site import Site
import argparse


def tls_upload(fqdn, ca, cert, private, overwrite=False):
    vaultclient = VaultClient()

    found = False
    try:
        secret = vaultclient.get_v2_secret("tls", fqdn, "cert")
        if len(secret) > 0:
            found = True
    except:
        pass

    if not found or overwrite:
        try:
            vaultclient.store_tls_cert(fqdn, cert, private, ca)
            print("Uploaded %s certificate to Vault" % fqdn)
        except:
            print("Failed to upload %s to Vault" % fqdn)
    else:
        print("Existing cert found, not uploading %s" % fqdn)


def le_hook():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fqdn")
    args, unknown = parser.parse_known_args()

    # Upload new certs to vault and ceph.
    le = LetsEncrypt()
    le.write_to_vault(args.fqdn)
    le.write_to_ceph(args.fqdn)

    # Restart nginx/httpd.
    type_maps = Site.get_host_map()
    for host in type_maps.pop("frontend"):
        ssh = SSHDriver(host)
        ssh.simple_command(["/usr/local/sbin/nginx_safe_reload"])

    for host in type_maps.pop("proxy"):
        ssh = SSHDriver(host)
        ssh.simple_command(["/usr/local/sbin/apache_safe_reload"])


def generate_temporary_cert():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fqdn")
    args = parser.parse_args()
    (ca, cert, privatekey) = SSLDriver.self_sign_ssl(args.fqdn)
    vaultclient = VaultClient()
    vaultclient.store_tls_cert(args.fqdn, cert, privatekey, ca)
    print("Done")
