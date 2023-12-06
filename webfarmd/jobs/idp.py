"""
This script parses a list of XML files (Mellon SPs) and creates
SimpleSAMLPHP config for the IdP
"""

from webfarmd.drivers.idp import IdentityProvider


def run():
    driver = IdentityProvider()
    driver.regenerate()
