#
# Webfarmd
#

from webfarmd.drivers.ad import ActiveDirectory
import logging

from sci_portal import Group as _Group


class Group(_Group):
    fillable_fields = ["ad_sync_at", "ad_gid"]

    def on_created(self):
        self.ensure_group_in_ad()

    def update_subresource_members(self):
        for site in self.sites:
            site.on_group_members_changed()

    def on_change(self):
        self.ensure_group_in_ad()

    def ensure_group_in_ad(self):
        """
        Ensure this ad_ref exists in AD.
        """
        if self.readonly:
            return False

        if (
            self.ad_ref is None
            or len(self.ad_ref) == 0
            or (self.ad_gid is not None and len(self.ad_gid) > 0)
        ):
            return True

        ad = ActiveDirectory()
        if not ad.group_exists(self.ad_ref):
            if not ad.create_group(self.ad_ref):
                raise Exception("Could not create group %s" % self.ad_ref)

        grpdata = ad.get_group(self.ad_ref)
        self.ad_gid = grpdata["gid"]
        self.save()

        return True

    def on_add_member(self, user):
        """
        Connects to AD and adds username
        """
        if self.ad_ref is None or len(self.ad_ref) == 0:
            return False
        if self.readonly:
            return False

        try:
            self.ensure_group_in_ad()
        except Exception as err:
            logging.error(err)
            logging.error("Failed to create AD group %s" % self.ad_ref)
            self.audit_log(
                user,
                "add_member_failed",
                "Failed to add user to AD group as we couldn't create the group. %s"
                % err,
            )
            return False

        try:
            ad = ActiveDirectory()
            if user.service:
                ad.add_group_service_member(self.ad_ref, user.username)
            else:
                ad.add_group_member(self.ad_ref, user.username)
        except Exception as err:
            logging.error(err)
            logging.error(
                "Failed to add user %s to AD group %s" % (user.username, self.ad_ref)
            )
            self.audit_log(
                user, "add_member_failed", "Failed to add user to AD group %s" % err
            )
            return False

        # Notify Portal.
        self.api.put_json(
            "/%s/%s/users/%s/ldap" % (self.endpoint, self.id, user.id), {}
        )

        self.update_subresource_members()

        return True

    def on_remove_member(self, user):
        """
        Connects to AD and removes username
        """
        if self.ad_ref is None or len(self.ad_ref) == 0:
            return False
        if self.readonly:
            return False

        try:
            self.ensure_group_in_ad()
        except:
            return False

        try:
            ad = ActiveDirectory()
            if user.service:
                ad.remove_group_service_member(self.ad_ref, user.username)
            else:
                ad.remove_group_member(self.ad_ref, user.username)
        except Exception as err:
            logging.error(err)
            logging.error(
                "Failed to remove user %s from AD group %s"
                % (user.username, self.ad_ref)
            )
            self.audit_log(
                user,
                "remove_member_failed",
                "Failed to remove user from AD group %s" % err,
            )
            return False

        # Notify Portal.
        self.api.delete_json("/%s/%s/users/%s/ldap" % (self.endpoint, self.id, user.id))

        self.update_subresource_members()

        return True

    def on_add_group(self, group):
        """
        Connects to AD and adds group
        """
        if self.ad_ref is None or len(self.ad_ref) == 0:
            return False
        if group.ad_ref is None or len(group.ad_ref) == 0:
            return False

        try:
            self.ensure_group_in_ad()
            group.ensure_group_in_ad()
        except Exception as err:
            logging.error(err)
            return False

        try:
            ad = ActiveDirectory()
            ad.add_group_group(self.ad_ref, group.ad_ref)
        except Exception as err:
            logging.error(err)
            logging.error(
                "Failed to add group %s to AD group %s" % (group.ad_ref, self.ad_ref)
            )
            return False

    def audit_log(self, user, action, reason):
        # Notify Portal.
        self.api.put_json(
            "/%s/%s/users/%s/auditlog" % (self.endpoint, self.id, user.id),
            {
                "action": action,
                "reason": reason,
            },
        )
        return True
