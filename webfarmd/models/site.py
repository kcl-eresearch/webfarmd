#
# Webfarmd
#
# Author: Skylar Kelty
#


import json
import logging
import os
import re
import subprocess
import yaml

from datetime import datetime, timedelta
from dns import resolver
from threading import Thread
from sci_portal import Site as _Site
from sci_portal import SiteSecurityScan
from sci_common.vault import VaultClient
from webfarmd.models import CLIModel
from webfarmd.drivers.templating import Templating
from webfarmd.drivers.ssh import SSHDriver
from webfarmd.drivers.idp import IdentityProvider
from webfarmd.drivers.letsencrypt import LetsEncrypt
from webfarmd.drivers.ssl import SSLDriver
from webfarmd.drivers.software.wordpress import Wordpress
from webfarmd.drivers.software.phpfpm import PHPFPM


class Site(_Site, CLIModel):
    wildcard_certs = ["sites.er.kcl.ac.uk", "er.kcl.ac.uk"]

    fillable_fields = [
        "name",
        "description",
        "ssh_pubkey",
        "status",
        "repository",
        "revision",
        "metadata",
    ]

    def __init__(self, api, data, parent=None):
        super().__init__(api, data, parent)
        self._vault_client = None
        self.ssl_temp = False
        self.provision_httpd_proxy = False
        self._config_driver = None

    @property
    def vault_client(self):
        if not self._vault_client:
            self._vault_client = VaultClient()
        return self._vault_client

    @property
    def ssl_name(self):
        # Support wildcard domains here.
        if "sites.er.kcl.ac.uk" in self.fqdn:
            return "sites.er.kcl.ac.uk"
        if "er.kcl.ac.uk" in self.fqdn and len(self.fqdn.split(".")) == 5:
            return "er.kcl.ac.uk"
        ssl_name = self.fqdn
        if ssl_name.startswith("www.") and self.redirect_to_www:
            ssl_name = ssl_name[4:]
        return ssl_name

    @property
    def ssl_type(self):
        return "infoblox" if "er.kcl.ac.uk" in self.fqdn else "webroot"

    @property
    def scheme(self):
        return "https" if self.ssl else "http"

    @property
    def has_ca(self):
        return os.path.exists("/ceph-data/core/webfarmd/tls/%s_ca.pem" % self.ssl_name)

    @property
    def config_driver(self):
        if not self._config_driver:
            if self.configuration == "wordpress":
                self._config_driver = Wordpress(self)
            if self.configuration == "php-fpm":
                self._config_driver = PHPFPM(self)
        return self._config_driver

    def delete(self):
        """
        Delete this site from the webfarm.
        """
        dirs = [
            "/ceph-data/core/webfarmd/nginx/shared/%s.conf" % self.fqdn,
            "/ceph-data/core/webfarmd/nginx/external/%s.conf" % self.fqdn,
            "/ceph-data/core/webfarmd/nginx/internal/%s.conf" % self.fqdn,
            "/ceph-data/core/webfarmd/httpd/%s.conf" % self.fqdn,
            "/ceph-data/core/%s" % self.fqdn,
            "/ceph-datarw/core/%s" % self.fqdn,
        ]
        for dir in dirs:
            subprocess.call(["rm", "-rf", dir])

        # Delete any apps.
        if self.configuration != "standard":
            driver = self.config_driver
            if driver:
                driver.delete()

        # Make sure we aren't using anything elsewhere.
        reused_user = False
        reused_cert = False
        for site in Site.all():
            if site.id == self.id:
                continue
            if site.ssl_name == self.ssl_name:
                reused_cert = True
            if site.map_user() == self.map_user():
                reused_user = True
            if reused_cert and reused_user:
                break

        # Delete SSL cert.
        if not reused_cert and self.ssl_name not in self.wildcard_certs:
            le = LetsEncrypt()
            le.delete(self.ssl_name)

        # Delete keyfile.
        if not reused_user:
            keyfile = "/home/w3admin/.ssh/webfarmd/%s" % self.map_user()
            if os.path.isfile(keyfile):
                os.remove(keyfile)
            if os.path.isfile("%s.pub" % keyfile):
                os.remove("%s.pub" % keyfile)

        # Tidy up SP.
        mellon_xml_path = "/ceph-data/core/%s/mellon/https_%s.xml" % (
            self.fqdn,
            self.fqdn.replace("-", "_"),
        )
        if os.path.isfile(mellon_xml_path):
            idp = IdentityProvider()
            idp.clean_sp(mellon_xml_path)

    def on_group_members_changed(self):
        if self.configuration == "wordpress":
            try:
                self.config_driver.wp_check_members()
            except:
                pass

    def generate_deploy_key(self):
        """
        Generate a deploy key for a given user, and send to Portal.
        """
        if self.ssh_pubkey:
            return

        sshdir = "/home/w3admin/.ssh/webfarmd"
        ssh = SSHDriver("localhost")
        ssh.ensure_directory(sshdir, "w3admin", "w3admin", "0700")

        keyfile = "%s/w3site%s" % (sshdir, self.id)
        if not os.path.isfile(keyfile):
            # Create a new key.
            self.run_proc(
                [
                    "ssh-keygen",
                    "-q",
                    "-b",
                    "2048",
                    "-t",
                    "rsa",
                    "-f",
                    keyfile,
                    "-C",
                    "w3site%s@erportal" % self.id,
                    "-N",
                    "",
                ]
            )

        # Read the key.
        with open("%s.pub" % keyfile, mode="r") as file:
            public_key = file.read()

        # Send to portal.
        self.ssh_pubkey = public_key
        self.save()

    def set_metadata(self, k, v):
        """
        Set metadata.
        """
        if not self.metadata:
            self.metadata = {}
        self.metadata[k] = v
        self.save()

    def configure_applications(self):
        # We are not a website, but a specific application.
        # We need to write a docker file for the application,
        # associated config and such.
        if self.configuration == "wordpress":
            self.config_driver.check_installed()
            self.config_driver.wp_check_members()
            self.set_metadata("wordpress_version", self.config_driver.wp_get_version())
            self.save()

    def verify_dns(self, domain):
        # Try to resolve the fqdn via external DNS (8.8.8.8).
        # If we can't, then we can't get a certificate.
        try:
            res = resolver.Resolver()
            res.nameservers = ["8.8.8.8", "1.1.1.1"]
            result = res.resolve(domain)
            if (
                self.fqdn != self.ssl_name
                and domain == self.fqdn
                and result.canonical_name == self.ssl_name
            ):
                return True
            return (
                result.canonical_name == "lbext-vip.er.kcl.ac.uk"
                or result.rrset[0].address == "193.61.202.139"
            )
        except:
            return False

    def self_sign_cert(self):
        # Try and get a certificate from vault.
        # If we can't then self-sign one.
        # We get the client here so we aren't capturing Vault
        # instantiation errors.
        vault_client = self.vault_client
        try:
            ssl_data = vault_client.get_tls_cert(self.ssl_name)
        except:
            (ca, cert, privatekey) = SSLDriver.self_sign_ssl(self.ssl_name)
            vault_client.store_tls_cert(self.ssl_name, cert, privatekey, ca)
            ssl_data = {"ca": ca, "cert": cert, "private": privatekey}

        # Update our certificates on ceph.
        le = LetsEncrypt()
        le._write_to_ceph(
            self.ssl_name, ssl_data["cert"], ssl_data["private"], ssl_data["ca"]
        )

    def handle_ssl(self, initial=False):
        """
        Checks for a valid certificate and sets some local variables.
        """
        self.ssl_temp = False

        if self.ssl_name in self.wildcard_certs:
            return True

        if self.verify_letsencrypt():
            return True

        # If we can use LE, let's do so.
        if not initial and self.verify_dns(self.ssl_name):
            if self.register_letsencrypt():
                return True

        self.ssl_temp = not self.internal_only
        self.self_sign_cert()

        return True

    def register_letsencrypt(self):
        """
        Register an LE cert for this host.
        """
        if self.ssl_name in self.wildcard_certs:
            return True

        extras = []
        if "kcl.ac.uk" not in self.fqdn:
            if self.ssl_type == "dns":
                extras.append("*.%s" % self.ssl_name)
            elif self.fqdn.startswith("www.") and not self.ssl_name.startswith("www."):
                if not self.verify_dns(self.fqdn):
                    return False
                extras.append(self.fqdn)

        le = LetsEncrypt()
        try:
            webroot = "/var/www/vhost/%s/letsencrypt" % self.fqdn
            le.ensure_registered(self.ssl_name, extras, self.ssl_type, webroot)
            le.write_to_ceph(self.ssl_name)
            return True
        except:
            logging.error("LetsEncrypt failed for %s" % self.ssl_name)
        return False

    def verify_letsencrypt(self, on_renew=None):
        """
        Check to see if there is a newer certificate available.
        """
        if self.ssl_name in self.wildcard_certs:
            return True

        latestcert = "/etc/letsencrypt/live/%s/cert.pem" % self.ssl_name
        if not os.path.exists(latestcert):
            return False

        # Check the certificate is up to date.
        out = subprocess.check_output(
            [
                "/usr/bin/openssl",
                "x509",
                "-in",
                latestcert,
                "-text",
                "-noout",
            ]
        )
        m = re.search("Not After :(.*)", out.decode("ascii"), re.I + re.M)
        res = m.groups()
        expiry = res[0].strip()
        expiry = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
        if expiry < datetime.now() + timedelta(days=5):
            print(
                "Warning: Certificate for %s expires in less than 5 days."
                % self.ssl_name
            )

        # Verify the renewal is present and up-to-date.
        le = LetsEncrypt()
        le.verify_hooks(self.ssl_name, self.ssl_type)

        # Check the two certs match.
        currcert = "/ceph-data/core/webfarmd/tls/%s_cert.pem" % self.ssl_name
        if os.path.exists(currcert):
            lstdout = subprocess.check_output(["md5sum", latestcert])
            cstdout = subprocess.check_output(["md5sum", currcert])
            if (
                lstdout.decode("ascii").strip().split(" ")[0]
                == cstdout.decode("ascii").strip().split(" ")[0]
            ):
                return True

        logging.info("Updating certificate for %s..." % self.ssl_name)

        # We need updating.
        le.write_to_ceph(self.ssl_name)
        self._restart_frontends()

        return True

    def map_user(self):
        """
        Return our user
        """
        if self.configuration == "standard":
            return "w3general"
        return self.user

    @staticmethod
    def get_host_map():
        """
        Get a map of hosts.
        """
        try:
            with open(f"/etc/puppet_roles/role_webfarm.yaml") as fh:
                role_hosts = yaml.safe_load(fh)
            host_types = role_hosts["host_types"]
        except Exception as e:
            raise Exception("Cannot load host list")

        # Build a type map.
        type_maps = {}
        for host in host_types:
            types = [host_types[host]]
            if types[0] == "allinone":
                types = ["frontend", "backend", "proxy", "dockerworker", "controller"]

            for _type in types:
                if _type not in type_maps:
                    type_maps[_type] = []
                type_maps[_type].append(host)

        return type_maps

    def provision_directories(self, host):
        """
        Symlinks on host
        """
        ssh = SSHDriver(host)
        ssh.ensure_link(
            "/var/www/vhost/%s" % self.fqdn, "/ceph-data/core/%s" % self.fqdn
        )

    def provision_ctl_directories(self):
        """
        Make our directory controller structure
        """

        # Build standard dirs.
        ssh = SSHDriver("localhost")
        if self.configuration != "standard":
            ssh.ensure_directory(
                "/ceph-data/core/webfarmd/docker/%s" % self.fqdn,
                "w3admin",
                "root",
                "0750",
            )
        ssh.ensure_directory(
            "/ceph-data/core/%s" % self.fqdn, "w3admin", "root", "0755"
        )
        ssh.ensure_directory(
            "/ceph-data/core/%s/app" % self.fqdn, "w3admin", "root", "0755"
        )
        ssh.ensure_directory(
            "/ceph-data/core/%s/system" % self.fqdn, "w3admin", "root", "0755"
        )
        ssh.ensure_directory(
            "/ceph-data/core/%s/letsencrypt" % self.fqdn, "w3admin", "root", "0755"
        )
        ssh.ensure_directory(
            "/ceph-datarw/core/%s" % self.fqdn, "w3admin", "root", "0755"
        )

        # Build writable dir.
        # TODO: check FACLs
        user = self.map_user()
        acls = [
            "user::rwx",
            "group::rwx",
            "mask::rwx",
            "other::---",
            "user:www-data:r-x",
            "user:w3admin:rwx",
            "user:%s:rwx" % user,
            "default:user::rwx",
            "default:user:www-data:r-x",
            "default:user:w3admin:rwx",
            "default:user:%s:rwx" % user,
            "default:group::rwx",
            "default:mask::rwx",
            "default:other::---",
        ]
        writdir = "/ceph-datarw/core/%s/writable" % self.fqdn
        if not os.path.exists(writdir):
            os.mkdir(writdir)
            subprocess.call(["/usr/bin/setfacl", "-m" '"%s"' % ",".join(acls), writdir])

        pubwritdir = "/ceph-data/core/%s/writable" % self.fqdn
        if not os.path.exists(pubwritdir):
            subprocess.call(["ln", "-s", writdir, pubwritdir])

        pubdir = "/ceph-data/core/%s/app/current/public" % self.fqdn
        if self.public_folder == "writable" or self.configuration == "wordpress":
            pubdir = "/ceph-data/core/%s/writable" % self.fqdn
        elif self.public_folder == "root":
            pubdir = "/ceph-data/core/%s/app/current" % self.fqdn
        elif self.public_folder == "www":
            pubdir = "/ceph-data/core/%s/app/current/www" % self.fqdn

        ssh.ensure_link("/ceph-data/core/%s/public" % self.fqdn, pubdir)

    def configure_frontend(self, host):
        """
        Configure an nginx host
        """
        # Put symlinks in.
        self.provision_directories(host)

        # Finally, restart nginx.
        ssh = SSHDriver(host)
        ssh.simple_command(["/usr/bin/sudo", "/usr/local/sbin/nginx_safe_reload"])

    def configure_proxy(self, host):
        """
        Configure a httpd host
        """
        # Put symlinks in.
        self.provision_directories(host)

        # Finally, restart httpd.
        ssh = SSHDriver(host)
        ssh.simple_command(["/usr/bin/sudo", "/usr/local/sbin/apache_safe_reload"])

    def write_nginx_config(self):
        """
        Write out nginx config.
        """
        path = "/ceph-data/core/webfarmd/nginx"
        paths = [
            "%s/shared/%s.conf" % (path, self.fqdn),
            "%s/internal/%s.conf" % (path, self.fqdn),
            "%s/external/%s.conf" % (path, self.fqdn),
            "%s/shared/%s-ssl-redirect.conf" % (path, self.fqdn),
            "%s/shared/%s-www-redirect.conf" % (path, self.fqdn),
        ]

        # Write new config.
        configs = self.get_nginx_config()
        for config in configs:
            with open(config["path"], mode="w") as fp:
                fp.write(config["content"])
            paths.remove(config["path"])

        # Clear old config.
        for path in paths:
            if os.path.exists(path):
                os.remove(path)

    def print_nginx_config(self):
        """
        Print out nginx config (cli utility).
        """
        configs = self.get_nginx_config()
        for config in configs:
            print("%s:" % config["path"])
            print(config["content"])
            print("")

    def get_nginx_config(self):
        """
        Get our nginx config.
        """
        configs = []
        templating = Templating()
        path = "/ceph-data/core/webfarmd/nginx"
        sharedpath = "%s/shared" % path
        internalpath = "%s/internal" % path
        externalpath = "%s/external" % path

        httpd_proxy_target = (
            "https://primary-httpd-proxy-ssl"
            if self.ssl
            else "http://primary-httpd-proxy"
        )
        if self.configuration != "standard":
            httpd_proxy_target = (
                "https://primary-docker-ssl" if self.ssl else "http://primary-docker"
            )

        ssl_certificate = (
            "/ceph-data/core/webfarmd/tls/%s_fullchain.pem" % self.ssl_name
        )
        ssl_certificate_key = (
            "/ceph-data/core/webfarmd/tls/private/%s.pem" % self.ssl_name
        )
        if self.ssl_name in self.wildcard_certs:
            ssl_certificate = "/etc/nginx/ssl/certs/%s_fullchain.pem" % self.ssl_name
            ssl_certificate_key = "/etc/nginx/ssl/private_keys/%s.pem" % self.ssl_name

        # Build locations config.
        locations = []
        external_locations = []
        internal_locations = []
        has_mellon = False
        for location in self.locations:
            if location.in_error:
                continue

            # Fixup path.
            slashended_path = location.path
            if slashended_path[-1] != "/":
                slashended_path = slashended_path + "/"

            # Map mod_mellon to proxy through to httpd.
            has_mellon = has_mellon or location.mod_mellon

            # Determine if we are a proxy loc.
            loctype = (
                "proxy"
                if (location.type == "standard" and location.mod_mellon)
                else location.type
            )

            # For non-standard sites, we will always want to proxy to something.
            if self.configuration != "standard" and loctype == "standard":
                loctype = "proxy"

            # Check for maintenance.
            if (
                self.config_flags
                and "maintenance_mode" in self.config_flags
                and self.config_flags["maintenance_mode"]
            ):
                loctype = "maintenance"

            if loctype == "proxy":
                self.provision_httpd_proxy = True

            # Render the config.
            loccfg = templating.render(
                "site/nginx/location/%s.j2" % loctype,
                {
                    "fqdn": self.fqdn,
                    "path": location.path,
                    "target": location.target
                    if loctype == "redirect"
                    else httpd_proxy_target,
                    "permanance": "redirect",
                    "capture_errors": location.capture_errors,
                    "proxy_cache": location.cache_proxy,
                    "proxy_websocket": "proxy_websocket" in location.flags
                    and location.flags["proxy_websocket"],
                    "static_cache": False,
                },
            )

            # If we have static asset caching enabled, also render additional config.
            if location.cache_static:
                assetpath = (
                    "~* ^%s.*\\.(?:css|js|eot|woff|woff2|ttf|otf|jpg|jpeg|gif|png|ico|cur|gz|svg|svgz|mp4|ogg|ogv|webm|htc)$"
                    % slashended_path
                )

                loccfg = loccfg + templating.render(
                    "site/nginx/location/%s.j2" % loctype,
                    {
                        "fqdn": self.fqdn,
                        "path": assetpath,
                        "target": location.target
                        if loctype == "redirect"
                        else httpd_proxy_target,
                        "permanance": "redirect",
                        "capture_errors": True,
                        "static_cache": True,
                    },
                )

            # Internal locations have a "This is internal only" page on external nginx.
            if (
                location.internal_only or not location.external_approved
            ) and loctype != "redirect":
                internal_locations.append(loccfg)
                external_locations.append(
                    templating.render(
                        "site/nginx/location/internal_only.j2",
                        {
                            "path": location.path,
                        },
                    )
                )
            else:
                locations.append(loccfg)

        # We want to make sure /mellon redirects to httpd.
        if has_mellon:
            loccfg = templating.render(
                "site/nginx/location/proxy.j2",
                {"fqdn": self.fqdn, "path": "/mellon/", "target": httpd_proxy_target},
            )
            if len(locations) > 0:
                locations.append(loccfg)
            else:
                internal_locations.append(loccfg)

        # Build config.
        internal_nginx_conf = templating.render(
            "site/nginx/site.j2",
            {
                "fqdn": self.fqdn,
                "ssl": self.ssl,
                "hsts": self.hsts,
                "ssl_certificate": ssl_certificate,
                "ssl_certificate_key": ssl_certificate_key,
                "locations": locations + internal_locations,
                "max_body_size": int(self.config_flags["upload_limit"])
                if self.config_flags and "upload_limit" in self.config_flags
                else 0,
            },
        )
        external_nginx_conf = templating.render(
            "site/nginx/site.j2",
            {
                "fqdn": self.fqdn,
                "ssl": self.ssl,
                "hsts": self.hsts,
                "ssl_certificate": ssl_certificate,
                "ssl_certificate_key": ssl_certificate_key,
                "locations": locations + external_locations,
                "max_body_size": int(self.config_flags["upload_limit"])
                if self.config_flags and "upload_limit" in self.config_flags
                else 0,
            },
        )

        configs.append(
            {
                "path": "%s/%s.conf" % (internalpath, self.fqdn),
                "content": internal_nginx_conf,
            }
        )
        configs.append(
            {
                "path": "%s/%s.conf" % (externalpath, self.fqdn),
                "content": external_nginx_conf,
            }
        )

        # Redirect non-SSL to SSL.
        if self.ssl:
            fqdns = [self.fqdn]
            if self.redirect_to_www and "www." in self.fqdn:
                fqdns.append(self.fqdn[4:])
            redirect_conf = templating.render(
                "site/nginx/redirect.j2",
                {
                    "fqdns": fqdns,
                    "fqdn": self.fqdn,
                    "ssl": False,
                    "location": "/",
                    "target": "https://$host$request_uri?",
                    "permanance": "permanent",
                },
            )
            configs.append(
                {
                    "path": "%s/%s-ssl-redirect.conf" % (sharedpath, self.fqdn),
                    "content": redirect_conf,
                }
            )

        # Redirect non-www. to www.
        if self.redirect_to_www and "www." in self.fqdn:
            fqdn_nowww = self.fqdn[4:]
            redirect_conf = templating.render(
                "site/nginx/redirect.j2",
                {
                    "fqdns": [fqdn_nowww],
                    "fqdn": fqdn_nowww,
                    "ssl": self.ssl,
                    "hsts": self.hsts,
                    "ssl_certificate": ssl_certificate,
                    "ssl_certificate_key": ssl_certificate_key,
                    "location": "/",
                    "target": "%s://www.$host$request_uri?" % self.scheme,
                    "permanance": "permanent",
                },
            )
            configs.append(
                {
                    "path": "%s/%s-www-redirect.conf" % (sharedpath, self.fqdn),
                    "content": redirect_conf,
                }
            )

        return configs

    def handle_mellon(self):
        """
        If a site requires auth, we need to sign the SP and register it
        on the IdP.
        """
        # Create the certificate.
        mellon_path = "/ceph-data/core/%s/mellon" % self.fqdn
        mellon_xml_path = "%s/https_%s.xml" % (mellon_path, self.fqdn.replace("-", "_"))

        # Create mellon metadata if needs be.
        if not os.path.exists(mellon_path):
            os.mkdir(mellon_path)
        if not os.path.exists(mellon_xml_path):
            subprocess.run(
                [
                    "/etc/apache2/mellon/create_cert.sh",
                    "https://%s" % self.fqdn,
                    "https://%s/mellon" % self.fqdn,
                ],
                cwd=mellon_path,
            )

            if not os.path.exists(mellon_xml_path):
                raise Exception("Failed to create mellon certificate")

        # Register with IdP.
        idp = IdentityProvider()
        idp.ensure_sp(mellon_xml_path)

    def write_httpd_config(self):
        """
        Write out httpd config.
        """
        config = self.get_httpd_config()
        with open(config["path"], mode="w") as fp:
            fp.write(config["content"])

    def print_httpd_config(self):
        """
        Print our httpd config.
        """
        config = self.get_httpd_config()
        print("%s:" % config["path"])
        print(config["content"])
        print("")

    def get_waf_exclusions(self):
        """
        Get our WAF exclusions.
        """
        templating = Templating()
        waf_exclusions = []
        for exclusion in self.waf_exclusions:
            # Build config.
            exclusion_conf = templating.render(
                "site/httpd/wafexclusion.j2",
                {
                    "id": exclusion.id,
                    "path": exclusion.path,
                    "ruleid": exclusion.ruleid,
                },
            )
            waf_exclusions.append(exclusion_conf)
        return waf_exclusions

    def get_httpd_config(self):
        """
        Get our httpd config.
        """
        templating = Templating()

        ssl_certificate = "/ceph-data/core/webfarmd/tls/%s_cert.pem" % self.ssl_name
        ssl_certificate_key = (
            "/ceph-data/core/webfarmd/tls/private/%s.pem" % self.ssl_name
        )
        ssl_certificate_chain = "/ceph-data/core/webfarmd/tls/%s_ca.pem" % self.ssl_name
        if self.ssl_name in self.wildcard_certs:
            ssl_certificate = "/etc/ssl/certs/%s.cert" % self.ssl_name
            ssl_certificate_key = "/etc/ssl/private/%s.key" % self.ssl_name
            ssl_certificate_chain = "/etc/ssl/certs/%s_chain.cert" % self.ssl_name

        # Mellon config.
        handled_mellon = False
        mellon_fqdn = self.fqdn.replace("-", "_")
        for location in self.locations:
            if location.in_error:
                continue
            if location.mod_mellon and not handled_mellon:
                self.handle_mellon()
                handled_mellon = True

        # Build WAF exclusion list.
        waf_exclusions = self.get_waf_exclusions()

        # Are we a PHP site?
        php = self.configuration == "wordpress" or self.configuration == "php-fpm"

        # Build each location.
        has_ssl_proxy = False
        locations = []
        for location in self.locations:
            if location.in_error:
                continue

            if location.target and "," in location.target:
                balancer_name = "%s_%s" % (self.fqdn, location.id)
                location.target = "balancer://%s" % balancer_name

                # Build balancer config.
                balancer_conf = templating.render(
                    "site/httpd/proxybalancer.j2",
                    {
                        "balancername": balancer_name,
                        "balancers": location.target.split(","),
                    },
                )
                locations.append(balancer_conf)

            # Fix up target.
            slash_appended_target = location.target
            if location.target and location.target[-1] != "/":
                slash_appended_target = location.target + "/"

            # WS target.
            ws_support = (
                "proxy_websocket" in location.flags
                and location.flags["proxy_websocket"]
            )
            ws_target = ""
            if ws_support:
                if slash_appended_target.startswith("http://"):
                    ws_target = slash_appended_target.replace("http://", "ws://", 1)
                elif slash_appended_target.startswith("https://"):
                    ws_target = slash_appended_target.replace("https://", "wss://", 1)

            # Build config.
            loc_conf = templating.render(
                "site/httpd/location.j2",
                {
                    "ssl": self.ssl,
                    "path": location.path,
                    "global_mellon": handled_mellon,
                    "mellon": location.mod_mellon,
                    "fqdn": self.fqdn,
                    "mellon_fqdn": mellon_fqdn,
                    "mellon_groups": location.mod_mellon_groups,
                    "loctype": location.type,
                    "target": slash_appended_target,
                    "enable_waf": (not self.waf_learning)
                    and (not self.waf_disabled)
                    and location.enable_waf,
                    "host_passthrough": location.host_passthrough,
                    "proxy_websocket": ws_support,
                    "ws_target": ws_target,
                },
            )
            locations.append(loc_conf)

            if location.type == "proxy" and "https" in location.target:
                has_ssl_proxy = True

        # Build config.
        httpd_conf = templating.render(
            "site/httpd/site.j2",
            {
                "ssl": self.ssl,
                "fqdn": self.fqdn,
                "ssl_certificate": ssl_certificate,
                "ssl_certificate_key": ssl_certificate_key,
                "ssl_certificate_chain": ssl_certificate_chain,
                "has_ca": self.has_ca,
                "has_ssl_proxy": has_ssl_proxy,
                "locations": locations,
                "waf_disabled": self.waf_disabled,
                "waf_exclusions": waf_exclusions,
                "limit_body": (int(self.config_flags["upload_limit"]) * 1000000)
                if self.config_flags and "upload_limit" in self.config_flags
                else 0,
                "proxy_php": php,
                "app_path": "/var/www/html/current/public"
                if self.configuration == "php-fpm"
                else "/var/www/html",
                "app_port": self.app_port,
            },
        )
        return {
            "path": "/ceph-data/core/webfarmd/%shttpd/%s.conf"
            % ("docker-" if self.configuration != "standard" else "", self.fqdn),
            "content": httpd_conf,
        }

    def _provision_proxies(self):
        self.write_httpd_config()

        # Configure each proxy.
        type_maps = Site.get_host_map()
        hosts = (
            type_maps["proxy"]
            if self.configuration == "standard"
            else type_maps["dockerworker"]
        )
        for host in hosts:
            self.configure_proxy(host)

    def _provision_frontends(self):
        self.write_nginx_config()
        self._restart_frontends()

    def _restart_frontends(self):
        # Configure each frontend.
        type_maps = Site.get_host_map()
        for host in type_maps["frontend"]:
            self.configure_frontend(host)

    def provision(self):
        """
        Provision this site on the webfarm
        """
        self.lock()

        # Fail if we are a protected name.
        if self.fqdn in [
            "webfarmd",
            "portal.er.kcl.ac.uk",
            "idp.sso.er.kcl.ac.uk",
            "idp2.sso.er.kcl.ac.uk",
            "blogs.er.kcl.ac.uk",
        ]:
            return

        # Ensure we have an SSL cert in Vault.
        if self.ssl:
            self.handle_ssl(True)

        # Configure CTL host.
        self.generate_deploy_key()
        self.provision_ctl_directories()
        self.write_system_template_files()
        self.provision_directories("localhost")

        # Configure each frontend.
        self._provision_frontends()

        # Configure each proxy.
        if self.provision_httpd_proxy:
            self._provision_proxies()

        # Configure apps.
        self.configure_applications()

        self.status = "built"
        self.save()
        self.unlock()

        # Now the site is "live" we can use LE to get a proper certificate.
        if self.ssl and self.ssl_temp:
            self.handle_ssl()
            if not self.ssl_temp:
                self._provision_frontends()

        # If we need to run a security scan due to a location pending
        # approval, do it now.
        if self.needs_security_scan():
            self.run_security_scan()

    def needs_security_scan(self):
        """
        Returns true if this site needs to be scanned.
        """
        if self.configuration == "standard":
            for loc in self.locations:
                if loc.type == "proxy":
                    return True
            return False
        return True

    def run_location_security_scan(self, location):
        """
        Run a security scan on this fqdn + location.path.
        """
        ssh = SSHDriver("erwebzap1.er.kcl.ac.uk")
        url = "%s://%s%s" % (self.scheme, self.fqdn, location.path)
        (stdouttxt, stderrtxt) = ssh.simple_command(
            ["/usr/local/bin/run_site_scan", url]
        )
        try:
            data = json.loads(stdouttxt)
        except:
            logging.error(
                "Error running security scan for %s: %s, %s"
                % (url, stdouttxt, stderrtxt)
            )
            return

        SiteSecurityScan.create(
            {"scanner": "OWASP-ZAP", "ruleset": "web-default", "result": data}, location
        )

    def run_security_scan(self):
        """
        Run a security scan on this fqdn.
        """
        for location in self.locations:
            # Thread it.
            Thread(
                target=self.run_location_security_scan, args=(location,), daemon=True
            ).start()

    def write_system_template_files(
        self, rewrite_maintenance=False, maintenance_eta=None
    ):
        path = "/ceph-data/core/%s" % self.fqdn
        if not os.path.exists(path):
            return False

        path = "%s/system/" % path
        if not os.path.exists(path):
            self.provision_ctl_directories()

        # Write maintenance page.
        filename = "%s/maintenance.html" % path
        if rewrite_maintenance or not os.path.exists(filename):
            time_back_msg = "We'll be back as soon as possible"
            if maintenance_eta:
                eta = datetime.strptime(maintenance_eta, "%d-%m-%Y %H:%M")
                time_back_msg = "We expect to be back around <b>%s</b>" % eta.strftime(
                    "%H:%M %d/%m/%Y"
                )

            templating = Templating()
            html = templating.render(
                "site/maintenance.html.j2",
                {
                    "time_back_msg": time_back_msg,
                },
            )

            with open(filename, "w") as f:
                f.write(html)

        # TODO: customizable error pages.

        return True
