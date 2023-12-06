"""
This script holds site update jobs
"""

import argparse
import os
from datetime import datetime
from webfarmd.drivers.ssh import SSHDriver
from webfarmd.drivers.templating import Templating
from webfarmd.models.site import Site
from webfarmd.models.sitedeployment import SiteDeployment


def regenerate_webserver_config():
    for site in Site.all():
        if site.ssl:
            site.handle_ssl()

        # Write out configs.
        site.write_nginx_config()
        if site.language != "static":
            site.write_httpd_config()


def rebuild_docker_stacks():
    parser = argparse.ArgumentParser()
    parser.add_argument("--destroy", action="store_true")
    args = parser.parse_args()

    for site in Site.all():
        if site.configuration == "standard" or site.configuration == "static":
            continue

        if args.destroy:
            ssh = SSHDriver("erwebctl2.er.kcl.ac.uk")
            ssh.simple_command(
                [
                    "/usr/bin/sudo",
                    "/usr/bin/docker",
                    "stack",
                    "rm",
                    site.config_driver.stackname,
                ]
            )

        site.config_driver.deploy_stack()


def export_letsencrypt_sites():
    for site in Site.all():
        if not site.ssl:
            return
        print("%s: %s" % (site.fqdn, site.ssl_name))


def update_letsencrypt_certs():
    for site in Site.all():
        if not site.ssl or site.ssl_name in site.wildcard_certs:
            continue
        site.verify_letsencrypt()


def deploy_site():
    parser = argparse.ArgumentParser()
    parser.add_argument("siteid")
    parser.add_argument("deployid")
    args = parser.parse_args()

    site = Site.find(args.siteid)
    deploy = SiteDeployment.find(args.deployid, site)
    deploy.deploy()


def run_security_scan():
    parser = argparse.ArgumentParser()
    parser.add_argument("siteid")
    args = parser.parse_args()

    site = Site.find(args.siteid)
    if site.needs_security_scan():
        site.run_security_scan()


def run_security_scans():
    for site in Site.all():
        if site.needs_security_scan():
            site.run_security_scan()


def check_tls():
    for site in Site.all():
        if not site.ssl or site.ssl_name in site.wildcard_certs:
            continue
        if not site.verify_letsencrypt():
            print("Site %s certificate needs to be generated" % site.fqdn)
            site.handle_ssl()
