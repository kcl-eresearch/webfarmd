"""
This script holds group update jobs
"""

import argparse
import ldap
from webfarmd.drivers.ad import ActiveDirectory
from webfarmd.models.group import Group


def update_all_groups():
    """
    Update all non-authoritative groups.
    """
    pass


def sync_ou():
    parser = argparse.ArgumentParser()
    parser.add_argument("ou")
    parser.add_argument("--dry", action="store_true")
    args = parser.parse_args()

    ad = ActiveDirectory()
    res = ad.ldap.adconn.result(
        ad.ldap.adconn.search(
            args.ou, ldap.SCOPE_SUBTREE, "(objectClass=*)", ["sAMAccountName"]
        )
    )
    if len(res) < 2:
        raise Exception("Could not search: invalid OU")

    for group_dn, gdata in res[1]:
        if "sAMAccountName" in gdata:
            group_name = gdata["sAMAccountName"][0].decode("ascii")
            res = Group.find_by("name", group_name)
            if len(res) == 0:
                if args.dry:
                    print("Would create %s: %s" % (group_name, group_dn))
                else:
                    print("Creating %s: %s" % (group_name, group_dn))
                    Group.create(
                        {
                            "name": group_name,
                            "description": "Created by webfarmd",
                            "ad_ref": group_dn,
                        }
                    )
