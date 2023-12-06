#
# Webfarmd
#
# Author: Skylar Kelty
#

import subprocess
from sci_common.config import ConfigReader


class MySQLDriver:
    def __init__(self):
        config = ConfigReader("/etc/webfarmd/webfarmd.yaml")
        self.mysql_host = config.required_attribute("mysql_host")
        self.mysql_user = config.required_attribute("mysql_user")
        self.mysql_password = config.required_attribute("mysql_password")

    def run_mysql_command(self, cmd):
        return subprocess.check_output(
            [
                "mysql",
                "-h",
                self.mysql_host,
                "-u",
                self.mysql_user,
                "-p" + self.mysql_password,
                "-e",
                cmd,
            ]
        )

    def ensure_db(self, dbname):
        self.run_mysql_command("CREATE DATABASE IF NOT EXISTS `%s`" % dbname)

    def ensure_user(self, username, password):
        self.run_mysql_command(
            "CREATE USER IF NOT EXISTS `%s`@`%%` IDENTIFIED BY '%s'"
            % (username, password)
        )

    def ensure_grant(self, username, dbname):
        self.run_mysql_command(
            "GRANT ALL PRIVILEGES ON `%s`.* TO `%s`@`%%`" % (dbname, username)
        )

    def delete_grant(self, username, dbname):
        self.run_mysql_command(
            "REVOKE ALL PRIVILEGES ON `%s`.* FROM `%s`@`%%`" % (dbname, username)
        )

    def delete_user(self, username):
        self.run_mysql_command("DROP USER `%s`@`%%`" % username)

    def delete_db(self, dbname):
        self.run_mysql_command("DROP DATABASE `%s`" % dbname)

    def dump_db(self, dbname, filename):
        with open(filename, "w") as f:
            subprocess.run(
                [
                    "mysqldump",
                    "--column-statistics=0",
                    "--skip-add-locks",
                    "-h",
                    self.mysql_host,
                    "-u",
                    self.mysql_user,
                    "-p" + self.mysql_password,
                    dbname,
                ],
                stdout=f,
            )
