#
# Webfarmd
#
# Author: Skylar Kelty
#

import configparser
import re
import os
import subprocess
from sci_common.vault import VaultClient
from webfarmd.drivers.ssh import SSHDriver
from .templating import Templating


class LetsEncrypt:
    def __init__(self):
        self._vault_client = None

    @property
    def vault_client(self):
        if not self._vault_client:
            self._vault_client = VaultClient()
        return self._vault_client

    def delete(self, fqdn):
        if not os.path.exists("/etc/letsencrypt/live/%s/privkey.pem" % fqdn):
            return
        subprocess.run(["certbot", "delete", "--cert-name", fqdn])
        return os.path.exists("/etc/letsencrypt/live/%s/privkey.pem" % fqdn)

    def _extract_certs(self, fqdn):
        # Might need to strip www., let's check.
        if fqdn[:4] == "www." and not os.path.exists(
            "/etc/letsencrypt/live/%s/privkey.pem" % fqdn
        ):
            fqdn = fqdn[4:]
            if not os.path.exists("/etc/letsencrypt/live/%s/privkey.pem" % fqdn):
                raise Exception("Could not find certs for %s" % fqdn)

        # Read the certs.
        with open("/etc/letsencrypt/live/%s/privkey.pem" % fqdn, mode="r") as file:
            privatekey = file.read()
        with open("/etc/letsencrypt/live/%s/cert.pem" % fqdn, mode="r") as file:
            cert = file.read()
        with open("/etc/letsencrypt/live/%s/chain.pem" % fqdn, mode="r") as file:
            ca = file.read()

        return (cert, privatekey, ca)

    def verify_hooks(self, fqdn, certbot_type="webroot"):
        """
        Verify the renewal is present and up-to-date.
        """
        cert = "/etc/letsencrypt/renewal/%s.conf" % fqdn
        if not os.path.exists(cert):
            print("Renewal config does not exist: %s." % fqdn)
            return False

        # Check the hooks.
        renewal_conf = configparser.ConfigParser()
        with open(cert, mode="r") as file:
            renewal_conf.read_string("[DEFAULT]\n" + file.read())

        if renewal_conf["renewalparams"]["renew_hook"] != "/etc/webfarmd/le_hook":
            print("Renewal hook is not correct: %s." % fqdn)
            return False

        return True

    def write_to_vault(self, fqdn):
        """
        Write the LE certificates for a given domain to Vault.
        """
        (cert, privatekey, ca) = self._extract_certs(fqdn)
        self.vault_client.store_tls_cert(fqdn, cert, privatekey, ca)

    def _write_to_ceph(self, fqdn, cert, privatekey, ca):
        ssh = SSHDriver("localhost")
        ssh.ensure_directory("/ceph-data/core/webfarmd/tls/")
        ssh.ensure_directory(
            "/ceph-data/core/webfarmd/tls/private", "www-data", "root", "0500"
        )

        # Write the certs.
        ssh.create_file(
            "%s\n%s" % (cert, ca),
            "/ceph-data/core/webfarmd/tls/%s_fullchain.pem" % fqdn,
        )
        if len(ca) > 0:
            ssh.create_file(ca, "/ceph-data/core/webfarmd/tls/%s_ca.pem" % fqdn)
        ssh.create_file(cert, "/ceph-data/core/webfarmd/tls/%s_cert.pem" % fqdn)

        # Write the private key.
        ssh.create_file(
            privatekey,
            "/ceph-data/core/webfarmd/tls/private/%s.pem" % fqdn,
            "www-data",
            "root",
            "0400",
        )

    def write_to_ceph(self, fqdn):
        """
        Write the LE certificates for a given domain to webfarm ceph.
        """
        (cert, privatekey, ca) = self._extract_certs(fqdn)
        self._write_to_ceph(fqdn, cert, privatekey, ca)

    def ensure_registered(
        self, fqdn, extra_names=[], certbot_type="webroot", webroot=""
    ):
        """
        Ensure a given certificate with list of names is registered in certbot.
        """
        dns_names = [fqdn] + extra_names
        dns_names = list(set(dns_names))

        cert = "/etc/letsencrypt/live/%s/cert.pem" % fqdn
        if not os.path.exists(cert):
            return self.register(fqdn, extra_names, certbot_type, [], webroot)

        out = subprocess.check_output(
            [
                "/usr/bin/openssl",
                "x509",
                "-in",
                cert,
                "-text",
                "-noout",
            ]
        )

        m = re.search("DNS:(.*)", out.decode("ascii"), re.I + re.M)
        res = m.groups()
        parts = res[0].split(", DNS:")
        for dns_name in dns_names:
            if dns_name not in parts:
                return self.update(fqdn, extra_names, certbot_type, webroot)
        return self._extract_certs(fqdn)

    def update(self, fqdn, extra_names=[], certbot_type="webroot", webroot=""):
        """
        Update a given set of certs.
        """
        return self.register(fqdn, extra_names, certbot_type, ["--expand"], webroot)

    def ensure_deploy_hook(self):
        if os.path.exists("/etc/webfarmd/le_hook"):
            return
        templating = Templating()
        file_path = os.path.abspath("%s/../../" % __file__)
        hook = templating.render(
            "site/le_hook.j2",
            {"install_dir": file_path},
        )
        with open("/etc/webfarmd/le_hook", mode="w") as fp:
            fp.write(hook)
        subprocess.call(["chmod", "a+x", "/etc/webfarmd/le_hook"])

    def register(
        self, fqdn, extra_names=[], certbot_type="webroot", extra_opts=[], webroot=""
    ):
        """
        Register a given set of certs.
        """
        if certbot_type not in ["webroot", "infoblox"]:
            raise Exception(
                "Letsencrypt.register - type must be one of: webroot, infoblox"
            )

        args = [
            "--text",
            "--agree-tos",
            "--non-interactive",
            # "--key-type",
            # "ecdsa",
            "certonly",
        ]

        if webroot == "":
            webroot = "/var/www/vhost/%s/letsencrypt" % fqdn

        if certbot_type == "webroot":
            args.append("-a")
            args.append("webroot")
            args.append("-w")
            args.append(webroot)

        if certbot_type == "infoblox":
            args.append("-a")
            args.append("certbot-dns-infoblox:certbot_dns_infoblox")

        args.append("--cert-name")
        args.append("%s" % fqdn)
        args.append("-d")
        args.append(",".join([fqdn] + extra_names))

        # Manage the LE hook.
        self.ensure_deploy_hook()
        args.append("--deploy-hook")
        args.append("/etc/webfarmd/le_hook")

        subprocess.run(["certbot"] + extra_opts + args)

        if not os.path.exists("/etc/letsencrypt/live/%s/privkey.pem" % fqdn):
            raise Exception("Certbot failed to create certificates.")

        # Read the certs.
        (cert, privatekey, ca) = self._extract_certs(fqdn)
        self.vault_client.store_tls_cert(fqdn, cert, privatekey, ca)
        return (cert, privatekey, ca)
