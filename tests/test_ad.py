# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch

from webfarmd.drivers.ad import ActiveDirectory
from sci_common.ldap.mockclient import MockClient


class ADTestSuite(unittest.TestCase):
    """AD driver test cases."""

    @patch('webfarmd.drivers.ad.LDAPClient')
    def test_create_group_validation(self, cls):
        cls.return_value = MockClient("", "", "")
        driver = ActiveDirectory()
        assert driver.create_group("wjfbnwiyufgwyf") == False
        assert driver.create_group("CN=er_fac_test,OU=wrong,DC=kclad,DC=ds,DC=kcl,DC=ac,DC=uk") == False
        assert driver.create_group("CN=er_fac_test,OU=test,DC=kclad,DC=ds,DC=kcl,DC=ac,DC=uk") == False
        assert driver.create_group("CN=er_prj_test,OU=wrong,DC=kclad,DC=ds,DC=kcl,DC=ac,DC=uk") == False
        assert driver.create_group("CN=er_prj_test,OU=test,DC=kclad,DC=ds,DC=kcl,DC=ac,DC=uk") == True
