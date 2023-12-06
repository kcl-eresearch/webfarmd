#
# Webfarmd
#
# Author: Skylar Kelty
#

import os
import time
import shutil
from datetime import datetime
from webfarmd.drivers.software.stackbase import StackBase
from webfarmd.drivers.templating import Templating
from webfarmd.drivers.mysql import MySQLDriver
from webfarmd.drivers.ssh import SSHDriver


class PHPFPM(StackBase):
    def __init__(self, site):
        super().__init__(site)
        self.stackname = self.site.fqdn.replace(".", "_") + "_phpfpm"
        self.db_name = "phpfpm-%s" % self.site.id
        self.db_username = "phpfpm-%s" % self.site.id

    def deploy_stack(self):
        templating = Templating()
        stack_data = self.get_env()
        stack_data.update(self.get_loki_vars())

        # Write out the .env file
        envfile = "%s/.env" % self.installdir
        with open(envfile, "w") as f:
            f.write(templating.render("site/software/php-fpm/env.j2", stack_data))
        os.chmod(envfile, 0o600)

        # Write out the stack.yml file
        stackyml = "%s/stack.yml" % self.installdir
        with open(stackyml, "w") as f:
            f.write(templating.render("site/software/php-fpm/stack.yml.j2", stack_data))
        os.chmod(stackyml, 0o600)

        # Deploy stack.
        ssh = SSHDriver("erwebctl2.er.kcl.ac.uk")
        ssh.simple_command(
            [
                "/usr/bin/sudo",
                "/usr/bin/docker",
                "stack",
                "deploy",
                "-c",
                stackyml,
                self.stackname,
            ]
        )

    def install(self):
        # Ensure DB.
        self.ensure_db_password()
        mysql = MySQLDriver()
        mysql.ensure_db(self.db_name)
        mysql.ensure_user(self.db_username, self.db_password)
        mysql.ensure_grant(self.db_username, self.db_name)

        # Now the stack.
        self.deploy_stack()

    def ensure_db_password(self):
        filename = "%s/mysql_password" % self.installdir
        self.db_password = self.ensure_password_file(filename)

    def get_env(self):
        self.ensure_db_password()

        mysql = MySQLDriver()
        return {
            "fqdn": self.site.fqdn,
            "app_port": self.site.app_port,
            "db_host": mysql.mysql_host,
            "db_user": self.db_name,
            "db_password": self.db_password,
            "db_name": self.db_name,
        }

    def backup_db(self):
        mysql = MySQLDriver()
        datestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        mysql.dump_db(self.db_name, "%s/backup-%s.sql" % (self.installdir, datestamp))

    def delete(self):
        # Dump the DB.
        self.backup_db()

        # Delete DB.
        mysql = MySQLDriver()
        mysql.delete_grant(self.db_name, self.db_name)
        mysql.delete_user(self.db_name)
        mysql.delete_db(self.db_name)

        # Delete the stack.
        # TODO: backup volume?
        ssh = SSHDriver("erwebctl2.er.kcl.ac.uk")
        ssh.simple_command(
            [
                "/usr/bin/sudo",
                "/usr/bin/docker",
                "stack",
                "rm",
                self.stackname,
            ]
        )

        # Tidy up the filesystem.
        if shutil.rmtree.avoids_symlink_attacks:
            shutil.rmtree(self.writabledir, ignore_errors=True)

        files = [
            ".env",
            "stack.yml",
            "mysql_password",
        ]
        for f in files:
            try:
                os.remove("%s/%s" % (self.installdir, f))
            except OSError:
                pass
