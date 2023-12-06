#
# Webfarmd
#
# Author: Skylar Kelty
#

import subprocess
import os
from io import BytesIO
from paramiko import SSHClient, AutoAddPolicy, RSAKey
from scp import SCPClient


class SSHDriver:
    def __init__(self, address):
        if address == "localhost":
            self.localhost = True
        else:
            self.localhost = False
            self.client = SSHClient()
            self.client.set_missing_host_key_policy(AutoAddPolicy())
            pkey = RSAKey.from_private_key_file("/home/w3admin/.ssh/id_rsa")
            self.client.connect(
                address, username="w3admin", pkey=pkey, look_for_keys=False
            )

    def simple_command(self, command):
        if self.localhost:
            stdout = subprocess.check_output(command)
            return (stdout.decode("utf8").strip(), "")

        if isinstance(command, list):
            command = " ".join(command)

        stdin, stdout, stderr = self.client.exec_command(command)
        stdouttxt = stdout.readlines()
        stdouttxt = "\n".join(stdouttxt)
        stderrtxt = stderr.readlines()
        stderrtxt = "\n".join(stderrtxt)
        stdin.close()
        stdout.close()
        stderr.close()
        return (stdouttxt, stderrtxt)

    def ensure_directory(self, dir, owner="w3admin", group="w3admin", mode="0755"):
        if not self.file_exists(dir):
            self.simple_command(["mkdir", "-p", dir])
        self.ensure_permissions(dir, owner, group, mode)

    def ensure_link(self, path, target):
        if not self.file_exists(path):
            self.simple_command(["ln", "-s", target, path])

    def stat_path(self, path):
        """
        Returns (mode, group, user) e.g. (0777, root, root)
        """
        (stdouttxt, stderrtxt) = self.simple_command(
            ["stat", "-c", '"0%a %G %U"', path]
        )
        parts = stdouttxt.split(" ")
        return (parts[0].lstrip('"'), parts[1], parts[2])

    def ensure_permissions(self, path, owner, group, mode):
        stat = self.stat_path(path)
        if stat[1] != group or stat[2] != group:
            self.simple_command(["chown", "%s:%s" % (owner, group), path])
        if stat[0] != mode:
            self.simple_command(["chmod", mode, path])

    def create_file(
        self, content, remotepath, owner="w3admin", group="w3admin", mode="0644"
    ):
        if self.localhost:
            with open(remotepath, mode="w") as fp:
                fp.write(content)
        else:
            with SCPClient(self.client.get_transport()) as scp:
                fl = BytesIO()
                fl.write(content.encode("ascii"))
                fl.seek(0)
                scp.putfo(fl, remotepath)
                fl.close()
        self.ensure_permissions(remotepath, owner, group, mode)

    def send_file(
        self, localpath, remotepath, owner="w3admin", group="w3admin", mode="0644"
    ):
        if self.localhost:
            self.simple_command(["cp", localpath, remotepath])
        else:
            with SCPClient(self.client.get_transport()) as scp:
                scp.put(localpath, remote_path=remotepath)
        self.ensure_permissions(remotepath, owner, group, mode)

    def file_exists(self, remotepath):
        if self.localhost:
            return os.path.exists(remotepath) or os.path.islink(remotepath)
        (stdout, stderr) = self.simple_command(
            ["test", "-e", remotepath, "&&", "echo", "exists"]
        )
        return "exists" in stdout

    def close(self):
        if not self.localhost:
            self.client.close()
