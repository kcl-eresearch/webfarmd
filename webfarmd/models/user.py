#
# Webfarmd
#

from sci_common.config import ConfigReader
from sci_portal import User as _User
from sci_portal.api import PortalAPI
from webfarmd.drivers.ad import ActiveDirectory
import logging
import secrets
import smtplib
import string


class User(_User):
    @staticmethod
    def find_or_create(username):
        api = PortalAPI()
        try:
            res = api.list_json("/users/?username=%s" % username)
            return User(api, res[0])
        except Exception:
            pass

        # Going to have to create it.
        user = {
            "username": username,
            "display_name": username,
            "email": "%s@kcl.ac.uk" % username,
        }
        res = api.post_json("/users", user)
        if res is None or "data" not in res:
            raise Exception("Invalid API response: %s" % res)

        return User(api, res["data"])

    def create_in_ad(self, dn, desc="Autocreated by webfarmd", email_pw=None):
        alphabet = string.ascii_letters + string.digits
        password = "".join(secrets.choice(alphabet) for i in range(32))

        ad = ActiveDirectory()
        if ad.create_user(self.username, dn, password, desc):
            if email_pw:
                self.email_password(password, email_pw)

    def email_password(self, password, email_pw):
        sender = "noreply@er.kcl.ac.uk"
        receivers = [email_pw.email]

        message = """From: e-Research Portal <noreply@kcl.ac.uk>
To: %s <%s>
Subject: *encrypt* New service account created

A new service account has been created for you by the e-Research Portal.
Username: %s
Password: %s

""" % (
            email_pw.display_name,
            email_pw.email,
            self.username,
            password,
        )

        try:
            config = ConfigReader("/etc/webfarmd/webfarmd.yaml")
            with smtplib.SMTP(
                config.required_attribute("mail_hostname"), 587
            ) as smtpObj:
                smtpObj.starttls()
                smtpObj.ehlo()
                smtpObj.login(
                    config.required_attribute("mail_username"),
                    config.required_attribute("mail_password"),
                )
                smtpObj.sendmail(sender, receivers, message)
        except Exception:
            logging.exception("Failed to send email to %s" % email_pw.email)
