#
# Webfarmd
#
# Author: Skylar Kelty
#

import os
import json
import subprocess
from sci_common.vault import VaultClient
from webfarmd.drivers.ssh import SSHDriver


class StackBase:
    def __init__(self, site):
        self.site = site
        self.stackname = self.site.fqdn.replace(".", "_") + "_app"
        self.installdir = "/ceph-data/core/webfarmd/docker/%s" % self.site.fqdn
        self.writabledir = "/ceph-data/core/%s/writable" % self.site.fqdn

    def check_installed(self):
        if not os.path.exists(self.installdir) or not os.path.exists(self.writabledir):
            self.site.provision_ctl_directories()

        if os.path.exists("%s/stack.yml" % self.installdir):
            # We have tried to install before.
            ssh = SSHDriver("erwebctl2.er.kcl.ac.uk")
            (stdouttxt, stderrtxt) = ssh.simple_command(
                [
                    "/usr/bin/sudo",
                    "/usr/bin/docker",
                    "stack",
                    "ps",
                    "--format",
                    "json",
                    self.stackname,
                ]
            )
            if len(stdouttxt) > 0 and "nothing found in stack" not in stderrtxt:
                lines = stdouttxt.split("\n")
                for line in lines:
                    try:
                        service = json.loads(line)
                        if "Running" in service["CurrentState"]:
                            self.check_config()
                            return
                    except:
                        pass

        # No active containers found.
        self.install()

    def check_config(self):
        return

    def deploy_stack(self):
        return

    def install(self):
        return

    def ensure_password_file(self, filename):
        # Get or generate password.
        if not os.path.exists(filename):
            password = (
                subprocess.check_output(["pwgen", "-s", "32", "1"])
                .strip()
                .decode("utf-8")
            )
            with open(filename, "w") as f:
                f.write(password)
            os.chmod(filename, 0o600)
            return password

        # Already have one.
        with open(filename, "r") as f:
            return f.read().strip()

    def get_loki_vars(self):
        vault_client = VaultClient()
        return {
            "loki_username": vault_client.get_v2_secret("webfarm", "loki", "username"),
            "loki_password": vault_client.get_v2_secret("webfarm", "loki", "password"),
            "loki_url": vault_client.get_v2_secret("webfarm", "loki", "url"),
        }
