#
# Webfarmd
#
# Author: Skylar Kelty
#

import subprocess
import os
import json
import time
import shutil
from datetime import datetime
from sci_common.vault import VaultClient
from webfarmd.models.group import Group
from webfarmd.drivers.software.stackbase import StackBase
from webfarmd.drivers.templating import Templating
from webfarmd.drivers.mysql import MySQLDriver
from webfarmd.drivers.ssh import SSHDriver
from webfarmd.drivers.idp import IdentityProvider


class Wordpress(StackBase):
    def __init__(self, site):
        super().__init__(site)
        self.stackname = self.site.fqdn.replace(".", "_") + "_wp"
        self.db_name = "wordpress-%s" % self.site.id
        self.db_username = "wordpress-%s" % self.site.id

    @property
    def wp_manages_members(self):
        return not (
            self.site.config_flags and "wp_no_member_sync" in self.site.config_flags
        )

    def check_config(self):
        self.deploy_stack()

    def deploy_stack(self):
        templating = Templating()
        stack_data = self.get_env()
        stack_data.update(self.get_loki_vars())

        upload_limit = int(self.site.config_flags["upload_limit"]) if "upload_limit" in self.site.config_flags else 4
        php_data = {
            "upload_limit": "%sM" % upload_limit,
            "execution_limit": 600,
        }

        files = [
            (
                "stack.yml",
                templating.render("site/software/wordpress/stack.yml.j2", stack_data),
            ),
            (".env", templating.render("site/software/wordpress/env.j2", stack_data)),
            (
                "php.ini",
                templating.render("site/software/wordpress/php.ini.j2", php_data),
            ),
        ]

        is_new = False
        has_update = False
        for base_filename, contents in files:
            filename = "%s/%s" % (self.installdir, base_filename)

            # Get hash.
            if os.path.exists(filename):
                oldhash = subprocess.check_output(["md5sum", filename]).decode("utf-8")
                oldhash = oldhash.split(" ")[0]
            else:
                oldhash = None
                is_new = True

            # Write out the file.
            with open(filename, "w") as f:
                f.write(contents)
            os.chmod(filename, 0o600)

            # Get the new hash.
            newhash = subprocess.check_output(["md5sum", filename]).decode("utf-8")
            newhash = newhash.split(" ")[0]

            if oldhash != newhash:
                has_update = True

        # Deploy stack.
        if has_update:
            ssh = SSHDriver("erwebctl2.er.kcl.ac.uk")

            # Delete old stack for forced update.
            if not is_new:
                ssh.simple_command(
                    [
                        "/usr/bin/sudo",
                        "/usr/bin/docker",
                        "stack",
                        "rm",
                        self.stackname,
                    ]
                )
                time.sleep(1)

            # Deploy new stack.
            ssh.simple_command(
                [
                    "/usr/bin/sudo",
                    "/usr/bin/docker",
                    "stack",
                    "deploy",
                    "-c",
                    "%s/stack.yml" % self.installdir,
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

        self.deploy_stack()

        # Wait a bit for the container to start.
        time.sleep(15)

        # Install WP.
        self.wp_install()
        self.wp_install_themes()
        self.wp_install_plugins()
        self.wp_check_members()
        self.wp_check_settings()

        # Register SP.
        idp = IdentityProvider()
        idp.register_wordpress_sp("https://%s" % self.site.fqdn)

    def update(self):
        self.copy_themes()
        self.copy_plugins()

        # Update WP.
        cmd = self.get_base_wp_command()
        cmd.append("core")
        cmd.append("update")
        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")
        ssh.simple_command(cmd)

    def copy_themes(self):
        # Delete everything in writable that exists in ceph-data.
        paths = os.listdir("/ceph-data/core/webfarmd/software/wordpress/themes/")
        for path in paths:
            if shutil.rmtree.avoids_symlink_attacks and os.path.exists(
                "%s/wp-content/themes/%s" % (self.writabledir, path)
            ):
                shutil.rmtree(
                    "%s/wp-content/themes/%s" % (self.writabledir, path),
                    ignore_errors=True,
                )

            # Copy over.
            shutil.copytree(
                "/ceph-data/core/webfarmd/software/wordpress/themes/%s" % path,
                "%s/wp-content/themes/%s" % (self.writabledir, path),
                dirs_exist_ok=True,
            )

    def copy_plugins(self):
        # Delete everything in writable that exists in ceph-data.
        paths = os.listdir("/ceph-data/core/webfarmd/software/wordpress/plugins/")
        for path in paths:
            if shutil.rmtree.avoids_symlink_attacks and os.path.exists(
                "%s/wp-content/plugins/%s" % (self.writabledir, path)
            ):
                shutil.rmtree(
                    "%s/wp-content/plugins/%s" % (self.writabledir, path),
                    ignore_errors=True,
                )

            # Copy over.
            shutil.copytree(
                "/ceph-data/core/webfarmd/software/wordpress/plugins/%s" % path,
                "%s/wp-content/plugins/%s" % (self.writabledir, path),
                dirs_exist_ok=True,
            )

    def get_base_wp_command(self):
        return [
            "/usr/bin/sudo",
            "/usr/bin/docker",
            "run",
            "--rm",
            "-v",
            "%s/:/var/www/html" % self.writabledir,
            "--network",
            "%s_default" % self.stackname,
            "--env-file",
            "%s/.env" % self.installdir,
            "--user",
            "www-data",
            "wordpress:cli",
            "wp",
        ]

    def wp_get_version(self):
        cmd = self.get_base_wp_command()
        cmd.append("core")
        cmd.append("version")
        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")
        (stdouttxt, stderrtxt) = ssh.simple_command(cmd)
        return stdouttxt.strip()

    def wp_install(self):
        cmd = self.get_base_wp_command()
        cmd.append("core")
        cmd.append("install")
        cmd.append("--url='%s'" % self.site.fqdn)
        cmd.append("--title='%s'" % self.site.name)
        cmd.append("--admin_user=webfarmd")
        cmd.append("--admin_password='%s'" % self.ensure_admin_user_password())
        cmd.append("--admin_email=webfarmd@localhost.local")
        cmd.append("--skip-email")

        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")
        ssh.simple_command(cmd)

    def wp_set_option(self, option, value):
        cmd = self.get_base_wp_command()
        cmd.append("option")
        cmd.append("update")
        cmd.append(option)
        if type(value) is not str:
            cmd.append("--format=json")
            cmd.append("'%s'" % json.dumps(value))
        else:
            cmd.append(value)
        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")
        ssh.simple_command(cmd)

    def wp_check_settings(self):
        self.wp_set_option("admin_email", "webfarmd@localhost.local")
        self.wp_set_option("permalink_structure", "/%year%/%monthnum%/%postname%/")

        # Stop unregistered users commenting.
        self.wp_set_option("comment_registration", 1)
        self.wp_set_option("close_comments_for_old_posts", 1)

    def wp_install_themes(self):
        self.copy_themes()

        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")

        # First the theme.
        cmd = self.get_base_wp_command()
        cmd.append("theme")
        cmd.append("activate")
        cmd.append("kcl")
        ssh.simple_command(cmd)

    def wp_install_plugins(self):
        self.copy_plugins()

        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")

        # WP Mail SMTP
        try:
            smtp_password = VaultClient().get_v2_secret(
                "webfarm", "smtp_user_apps", "password"
            )
        except:
            smtp_password = ""

        cmd = self.get_base_wp_command()
        cmd.append("plugin")
        cmd.append("activate")
        cmd.append("wp-mail-smtp")
        self.wp_set_option(
            "wp_mail_smtp",
            {
                "mail": {
                    "from_email": "noreply@er.kcl.ac.uk",
                    "from_name": self.site.name,
                    "mailer": "smtp",
                    "return_path": False,
                    "from_email_force": True,
                    "from_name_force": False,
                },
                "smtp": {
                    "autotls": True,
                    "auth": True,
                    "host": "mta.er.kcl.ac.uk",
                    "encryption": "tls",
                    "port": 587,
                    "user": "er_web_smtp",
                    "pass": smtp_password,
                },
                "general": {"summary_report_email_disabled": False},
            },
        )

        # SAML auth.
        cmd = self.get_base_wp_command()
        cmd.append("plugin")
        cmd.append("activate")
        cmd.append("saml-auth")
        ssh.simple_command(cmd)

        # Add the settings to the database.
        saml_settings = {
            "auto_provision": False,
            "get_user_by": "login",
            "baseurl": "https://%s" % self.site.fqdn,
            "sp_entityId": "https://%s/wp-login.php" % self.site.fqdn,
            "sp_assertionConsumerService_url": "https://%s/wp-login.php"
            % self.site.fqdn,
            "idp_entityId": "https://idp.sso.er.kcl.ac.uk/saml2/idp/metadata.php",
            "idp_singleSignOnService_url": "https://idp.sso.er.kcl.ac.uk/saml2/idp/SSOService.php",
            "idp_singleLogoutService_url": "https://idp.sso.er.kcl.ac.uk/saml2/idp/SingleLogoutService.php",
            "certFingerprint": "",
            "certFingerprintAlgorithm": "",
            "user_login_attribute": "uid",
            "user_email_attribute": "mail",
            "display_name_attribute": "displayname",
            "first_name_attribute": "givenname",
            "last_name_attribute": "surname",
            "permit_wp_login": False,
        }
        self.wp_set_option("wp_saml_auth_settings", saml_settings)

    def wp_get_members(self):
        cmd = self.get_base_wp_command()
        cmd.append("user")
        cmd.append("list")
        cmd.append("--format=json")
        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")
        (stdouttxt, stderrtxt) = ssh.simple_command(cmd)
        if not stdouttxt:
            return []
        return json.loads(stdouttxt)

    def wp_check_members(self):
        if not self.wp_manages_members:
            return

        current_members = self.wp_get_members()
        current_usernames = [x["user_login"] for x in current_members]

        # We want to make sure this lines up with Portal.
        group = Group.find(self.site.group_id)
        userroles = {x.username: x.role for x in group.members}

        # Maps Portal roles to WP roles.
        role_map = {
            "admin": "administrator",
            "maintainer": "administrator",
            "developer": "editor",
            "member": "subscriber",
        }

        # First, check for any members in WP that are not in Portal.
        for current_member in current_members:
            if current_member["user_login"] == "webfarmd":
                # This is the webfarmd user, ignore it.
                continue

            if current_member["user_login"] not in userroles:
                # This user is not in Portal.
                self.wp_delete_member(current_member["user_login"])
            else:
                # Check the role.
                expected_role = role_map[userroles[current_member["user_login"]]]
                current_roles = current_member["roles"].split(",")
                if expected_role not in current_roles:
                    self.wp_add_member_role(current_member["user_login"], expected_role)
                for current_role in current_roles:
                    if current_role != expected_role:
                        self.wp_remove_member_role(
                            current_member["user_login"], current_role
                        )

        # Now check for any members in Portal that are not in WP.
        for user in group.members:
            if user.username not in current_usernames:
                # This user is not in WP.
                role = role_map[userroles[user.username]]
                self.wp_add_member(user, role)

    def wp_ensure_webfarmd_user(self):
        try:
            self.wp_add_member_base(
                "webfarmd",
                "webfarmd@localhost.local",
                "Webfarmd Service Account",
                "administrator",
                self.ensure_admin_user_password(),
            )
        except:
            pass
        current_members = self.wp_get_members()
        for current_member in current_members:
            if current_member["user_login"] == "webfarmd":
                return current_member["ID"]
        raise Exception("Could not find webfarmd user")

    def wp_add_member_base(self, username, email, display_name, role, password=None):
        cmd = self.get_base_wp_command()
        cmd.append("user")
        cmd.append("create")
        cmd.append(username)
        cmd.append(email)
        cmd.append("--role=%s" % role)
        cmd.append("--display_name='%s'" % display_name)
        if password:
            cmd.append("--user_pass='%s'" % password)

        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")
        ssh.simple_command(cmd)

    def wp_add_member(self, user, role, password=None):
        if not self.wp_manages_members:
            return
        self.wp_add_member_base(
            user.username, user.email, user.display_name, role, password
        )

    def wp_delete_member(self, username):
        if not self.wp_manages_members or username == "webfarmd":
            return

        reassignid = self.wp_ensure_webfarmd_user()

        cmd = self.get_base_wp_command()
        cmd.append("user")
        cmd.append("delete")
        cmd.append(username)
        cmd.append("--reassign=%s" % reassignid)
        cmd.append("--yes")

        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")
        ssh.simple_command(cmd)

    def wp_add_member_role(self, username, role):
        if not self.wp_manages_members:
            return
        cmd = self.get_base_wp_command()
        cmd.append("user")
        cmd.append("add-role")
        cmd.append(username)
        cmd.append(role)

        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")
        ssh.simple_command(cmd)

    def wp_remove_member_role(self, username, role):
        if not self.wp_manages_members:
            return
        cmd = self.get_base_wp_command()
        cmd.append("user")
        cmd.append("remove-role")
        cmd.append(username)
        cmd.append(role)

        ssh = SSHDriver("erwebdocker1.er.kcl.ac.uk")
        ssh.simple_command(cmd)

    def ensure_db_password(self):
        filename = "%s/mysql_password" % self.installdir
        self.db_password = self.ensure_password_file(filename)

    def ensure_admin_user_password(self):
        filename = "%s/admin_user_password" % self.installdir
        return self.ensure_password_file(filename)

    def ensure_rand_keys(self):
        # Get or generate random keys for WP.
        dbfile = "%s/rand_keys" % self.installdir
        if not os.path.exists(dbfile):
            rand_keys = (
                subprocess.check_output(["pwgen", "-s", "64", "8"])
                .strip()
                .decode("utf-8")
            )
            with open(dbfile, "w") as f:
                f.write(rand_keys)
            os.chmod(dbfile, 0o600)
        else:
            with open(dbfile, "r") as f:
                rand_keys = f.read().strip()

        self.rand_keys = rand_keys.split("\n")

    def get_env(self):
        self.ensure_db_password()

        mysql = MySQLDriver()
        stack_data = {
            "fqdn": self.site.fqdn,
            "app_port": self.site.app_port,
            "db_host": mysql.mysql_host,
            "db_user": self.db_name,
            "db_password": self.db_password,
            "db_name": self.db_name,
        }

        # Make sure we have our random keys.
        self.ensure_rand_keys()
        for i in range(0, 8):
            stack_data["rand_key_%s" % i] = self.rand_keys[i]

        return stack_data

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
            "admin_user_password",
            "rand_keys",
        ]
        for f in files:
            try:
                os.remove("%s/%s" % (self.installdir, f))
            except OSError:
                pass
