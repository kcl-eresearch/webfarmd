#
# Webfarmd
#
# Author: Skylar Kelty
#

import ldap
import logging
import re
from sci_common.config import ConfigReader
from sci_common.ldap import LDAPClient
from sci_common.utils import list_diff_ci


class ActiveDirectory:
    def __init__(self):
        config = ConfigReader("/etc/webfarmd/webfarmd.yaml")
        ad_hostname = config.required_attribute("ad_hostname")
        ad_user_upn = config.required_attribute("ad_user_upn")
        ad_password = config.required_attribute("ad_password")
        self.ad_writable_ous = config.required_attribute("ad_writable_ous")
        self.ldap = LDAPClient(ad_hostname, ad_user_upn, ad_password)
        self.members = {}

    def get_nested_groups(self, group_dn):
        """
        Get the nested groups of an AD group
        """
        return self.ldap.get_group_nested_groups(group_dn)

    def get_group_members(self, group_dn, recursive=False):
        """
        Get the members of an AD group
        """
        self.members[group_dn] = self.ldap.get_group_members(
            group_dn, recursive=recursive
        )
        return self.members[group_dn]

    def set_group_members(self, group_dn, usernames):
        """
        Set the members of an AD group, creating it if necessary
        """
        current = [x for x in self.get_group_members(group_dn)]
        diff = list_diff_ci(usernames, current)
        logging.info("Found %s AD users (group %s)" % (len(current), group_dn))
        logging.info(
            "Found %s new users and %s old users (group %s)"
            % (len(diff["new"]), len(diff["old"]), group_dn)
        )

        for username in diff["old"]:
            try:
                self.remove_group_member(group_dn, username)
            except Exception as e:
                print("Could not remove user from group: %s" % str(e))

        for username in diff["new"]:
            try:
                self.add_group_member(group_dn, username)
            except Exception as e:
                print("Could not add user to group: %s" % str(e))

    def add_group_member(self, group_dn, username):
        """
        Add a member to an AD group
        """
        if self.has_group_member(group_dn, username):
            return True
        self.ldap.add_group_member(group_dn, username)

    def remove_group_member(self, group_dn, username):
        """
        Remove a member from an AD group
        """
        if not self.has_group_member(group_dn, username):
            return True
        self.ldap.remove_group_member(group_dn, username)

    def get_service_ou(self, username):
        """
        Get the DN of a service account
        """
        # regex this: er_(service)_group3
        m = re.match(r"^er_([a-z]+)_group([0-9]+)$", username)
        if not m:
            return None
        prefix = m.group(1)
        return (
            "OU=%s,OU=role_accounts,OU=e-research,DC=kclad,DC=ds,DC=kcl,DC=ac,DC=uk"
            % prefix
        )

    def add_group_service_member(self, group_dn, username):
        """
        Add a service member to an AD group
        """
        service_ou = self.get_service_ou(username)
        if not service_ou:
            return False

        if self.has_group_service_member(group_dn, username, service_ou):
            return True

        user_dn = "CN=%s,%s" % (username, service_ou)
        self.ldap.mod_group_memberdn(group_dn, user_dn)

    def remove_group_service_member(self, group_dn, username):
        """
        Remove a service member from an AD group
        """
        service_ou = self.get_service_ou(username)
        if not service_ou:
            return False

        if not self.has_group_service_member(group_dn, username, service_ou):
            return True

        user_dn = "CN=%s,%s" % (username, service_ou)
        self.ldap.mod_group_memberdn(group_dn, user_dn, ldap.MOD_DELETE)

    def has_group_service_member(self, group_dn, username, ad_user_ou):
        """
        Returns true if the given service user exists in the given group.
        """
        return username in self.ldap.get_group_members(group_dn, True, ad_user_ou)

    def add_group_group(self, group_dn, group_dn2):
        """
        Add a group to an AD group
        """
        if self.ldap.has_group_memberdn(group_dn, group_dn2):
            return True
        self.ldap.mod_group_memberdn(group_dn, group_dn2)

    def has_group_member(self, group_dn, username):
        """
        Returns true if the given user exists in the given group.
        """
        if group_dn not in self.members:
            self.get_group_members(group_dn)
        return username in self.members[group_dn]

    def group_exists(self, group_dn):
        """
        Returns true if the given group exists in AD.
        """
        return self.ldap.group_exists(group_dn)

    def get_group(self, group_dn):
        """
        Returns true if the given group exists in AD.
        """
        return self.ldap.get_group(group_dn)

    def create_group(self, group_dn):
        """
        Create an AD group if it is in the correct format and OU
        """
        m = re.match(
            r"^CN=(er_([a-z]{3})(?:_[a-z0-9]+)+),((?:OU=[a-zA-Z0-9_-]+,)+DC=kclad,DC=ds,DC=kcl,DC=ac,DC=uk)$",
            group_dn,
        )
        if not m:
            return False
        group_name = m.group(1)
        prefix = m.group(2)
        ou = m.group(3)

        if not ou in self.ad_writable_ous:
            return False

        if prefix != self.ad_writable_ous[ou]:
            return False

        return self.ldap.create_group(group_name, ou)

    def create_user(self, username, user_dn, password, desc):
        return self.ldap.create_user(
            username, user_dn, password, other_attrs={"description": desc}
        )
