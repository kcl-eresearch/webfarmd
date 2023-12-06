# -*- coding: utf-8 -*-

from .context import MockResponse, MockVaultClient, MockPortalAPI

import unittest
import os
import pwd
import subprocess
from unittest.mock import patch

from webfarmd.models.site import Site
from sci_portal import SiteLocation
from webfarmd.models.sitedeployment import SiteDeployment
from webfarmd.drivers.ssl import SSLDriver


class SiteTestSuite(unittest.TestCase):
    """Site test cases."""

    def tearDown(self):
        emptydirs = [
            "/ceph-data/core/webfarmd/nginx/shared/",
            "/ceph-data/core/webfarmd/nginx/external/",
            "/ceph-data/core/webfarmd/nginx/internal/",
            "/ceph-data/core/webfarmd/httpd/",
            "/ceph-data/core/webfarmd/docker-httpd/",
        ]
        for dirname in emptydirs:
            # Delete all files in directory.
            for filename in os.listdir(dirname):
                file_path = os.path.join(dirname, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                except Exception as e:
                    print("Failed to delete %s. Reason: %s" % (file_path, e))
        dirs = [
            "/ceph-data/core/example.ertest.kcl.ac.uk",
            "/ceph-datarw/core/example.ertest.kcl.ac.uk",
            "/opt/webfarm/logs/example.ertest.kcl.ac.uk",
            "/ceph-data/core/blogexample.ertest.kcl.ac.uk",
            "/ceph-datarw/core/blogexample.ertest.kcl.ac.uk",
            "/opt/webfarm/logs/blogexample.ertest.kcl.ac.uk",
            "/var/www/vhost/idp.sso.er.kcl.ac.uk/writable/auto_sp_list.txt",
            "/var/www/vhost/idp.sso.er.kcl.ac.uk/app/ssphp-config/metadata/saml20-sp-remote-autogen.php",
        ]
        for dirname in dirs:
            subprocess.call(["rm", "-rf", dirname])
        
        if os.path.exists("/var/www/vhost/example.ertest.kcl.ac.uk"):
            subprocess.call(["unlink", "/var/www/vhost/example.ertest.kcl.ac.uk"])
        if os.path.exists("/var/www/vhost/blogexample.ertest.kcl.ac.uk"):
            subprocess.call(["unlink", "/var/www/vhost/blogexample.ertest.kcl.ac.uk"])
        
        subprocess.call(
            ["touch", "/var/www/vhost/idp.sso.er.kcl.ac.uk/writable/auto_sp_list.txt"]
        )
        subprocess.call(
            [
                "touch",
                "/var/www/vhost/idp.sso.er.kcl.ac.uk/app/ssphp-config/metadata/saml20-sp-remote-autogen.php",
            ]
        )

    def line_in_file(self, file, line):
        line = line.strip()
        with open(file, "r") as file:
            for t in file:
                if t.strip() == line:
                    return True
        return False

    def get_example_site(self, ssl=False):
        ret = {
            "id": 1,
            "fqdn": "example.ertest.kcl.ac.uk",
            "configuration": "standard",
        }
        if ssl:
            ret["ssl"] = True
        return ret

    def get_example_locations(self):
        locationa = SiteLocation(
            None,
            {
                "id": 1,
                "site": 1,
                "path": "/",
                "type": "standard",
                "target": "",
                "enable_waf": False,
                "internal_only": False,
                "mod_mellon": False,
                "mod_mellon_groups": "",
                "flags": [],
            },
        )
        locationb = SiteLocation(
            None,
            {
                "id": 2,
                "site": 1,
                "path": "/testredirect",
                "type": "redirect",
                "target": "https://bnlah",
                "flags": [],
            },
        )
        locationc = SiteLocation(
            None,
            {
                "id": 3,
                "site": 1,
                "path": "/testproxy",
                "type": "proxy",
                "target": "https://bnlah",
                "enable_waf": False,
                "internal_only": True,
                "mod_mellon": True,
                "mod_mellon_groups": ["blah", "also", "bleh"],
                "flags": [],
            },
        )
        return [locationa, locationb, locationc]

    def get_example_blog(self, ssl=False):
        ret = {
            "id": 2,
            "fqdn": "blogexample.ertest.kcl.ac.uk",
            "configuration": "wordpress",
            "app_port": 9001,
        }
        if ssl:
            ret["ssl"] = True
        return ret

    def get_blog_locations(self):
        locationa = SiteLocation(
            None,
            {
                "id": 4,
                "site": 2,
                "path": "/",
                "type": "standard",
                "flags": [],
            },
        )
        locationb = SiteLocation(
            None,
            {
                "id": 5,
                "site": 2,
                "path": "/wp-admin",
                "type": "standard",
                "flags": [],
            },
        )
        locationc = SiteLocation(
            None,
            {
                "id": 6,
                "site": 2,
                "path": "/xmlrpc.php",
                "type": "block",
                "flags": [],
            },
        )
        return [locationa, locationb, locationc]

    def get_example_deployment(self):
        return {
            "repo": "https://github.com/kcl-eresearch/placeholder.er.kcl.ac.uk.git",
            "revision": "main",
        }

    def test_self_signed_cert(self):
        (ca, cert, key) = SSLDriver.self_sign_ssl("example.ertest.kcl.ac.uk")
        assert len(ca) == 0
        assert len(cert) > 0
        assert len(key) > 0

    def test_static_user_map(self):
        s = Site(None, self.get_example_site())
        assert s.map_user() == "w3general"

    def test_static_host_map(self):
        type_maps = Site.get_host_map()
        assert len(type_maps.pop("proxy")) == 1
        assert len(type_maps.pop("frontend")) == 1
        assert len(type_maps.pop("backend")) == 1
        assert len(type_maps.pop("controller")) == 1

    @patch("webfarmd.models.site.Site.save")
    def test_ssh_keygen(self, mock_save):
        mock_save.return_value = True
        s = Site(None, self.get_example_site())
        assert "ssh_pubkey" not in s.data or len(s.ssh_pubkey) == 0
        s.generate_deploy_key()
        assert len(s.ssh_pubkey) > 0

    @patch("sci_portal.api.requests.get")
    def test_sites_get(self, mock_get):
        site = {"data": self.get_example_site()}
        mock_get.return_value = MockResponse(site, 200)

        s = Site.find(1)
        assert s.fqdn == "example.ertest.kcl.ac.uk"

    def test_sites_provision_directories(self):
        s = Site(None, self.get_example_site())
        s.provision_ctl_directories()
        s.provision_directories("localhost")

    def test_sites_provision_frontend(self):
        s = Site(None, self.get_example_site())
        s.subrelation_cache['locations'] = self.get_example_locations()
        s.subrelation_cache['waf_exclusions'] = []
        s.internal_only = True
        s.provision_ctl_directories()
        s.provision_directories("localhost")
        s._provision_frontends()
        assert not os.path.exists(
            "/ceph-data/core/webfarmd/nginx/shared/example.ertest.kcl.ac.uk.conf"
        )
        assert os.path.exists(
            "/ceph-data/core/webfarmd/nginx/internal/example.ertest.kcl.ac.uk.conf"
        )
        assert os.path.exists(
            "/ceph-data/core/webfarmd/nginx/external/example.ertest.kcl.ac.uk.conf"
        )
        output = subprocess.check_output(
            ["nginx", "-t"], stderr=subprocess.STDOUT
        ).decode("utf-8")
        assert "test is successful" in output

    def test_sites_provision_frontend_ssl(self):
        s = Site(None, self.get_example_site(ssl=True))
        s.subrelation_cache['locations'] = self.get_example_locations()
        s.subrelation_cache['waf_exclusions'] = []
        s._vault_client = MockVaultClient()

        s.provision_ctl_directories()
        s.provision_directories("localhost")
        s.handle_ssl()
        assert s.ssl_name == "example.ertest.kcl.ac.uk"
        assert s.ssl_temp
        s._provision_frontends()
        assert os.path.exists(
            "/ceph-data/core/webfarmd/nginx/internal/example.ertest.kcl.ac.uk.conf"
        )
        assert os.path.exists(
            "/ceph-data/core/webfarmd/nginx/external/example.ertest.kcl.ac.uk.conf"
        )
        assert os.path.exists(
            "/ceph-data/core/webfarmd/nginx/shared/example.ertest.kcl.ac.uk-ssl-redirect.conf"
        )
        output = subprocess.check_output(
            ["nginx", "-t"], stderr=subprocess.STDOUT
        ).decode("utf-8")
        assert "test is successful" in output

    def test_sites_provision_proxy(self):
        s = Site(None, self.get_example_site())
        s.subrelation_cache['locations'] = self.get_example_locations()
        s.subrelation_cache['waf_exclusions'] = []
        s.provision_ctl_directories()
        s.provision_directories("localhost")
        s._provision_proxies()
        assert os.path.exists(
            "/ceph-data/core/webfarmd/httpd/example.ertest.kcl.ac.uk.conf"
        )
        output = subprocess.check_output(
            ["apachectl", "configtest"], stderr=subprocess.STDOUT
        ).decode("utf-8")
        assert "Syntax OK" in output

    def test_sites_provision_proxy_ssl(self):
        s = Site(None, self.get_example_site(ssl=True))
        s.subrelation_cache['locations'] = self.get_example_locations()
        s.subrelation_cache['waf_exclusions'] = []
        s._vault_client = MockVaultClient()

        s.provision_ctl_directories()
        s.provision_directories("localhost")
        s.handle_ssl()
        assert s.ssl_name == "example.ertest.kcl.ac.uk"
        s._provision_proxies()
        assert os.path.exists(
            "/ceph-data/core/webfarmd/httpd/example.ertest.kcl.ac.uk.conf"
        )
        output = subprocess.check_output(
            ["apachectl", "configtest"], stderr=subprocess.STDOUT
        ).decode("utf-8")
        assert "Syntax OK" in output

    def test_sites_provision_mellon(self):
        s = Site(None, self.get_example_site(ssl=True))
        s.subrelation_cache['locations'] = self.get_example_locations()
        s.subrelation_cache['waf_exclusions'] = []
        s._vault_client = MockVaultClient()

        s.provision_ctl_directories()
        s.provision_directories("localhost")
        s.handle_ssl()
        s._provision_proxies()
        assert os.path.exists(
            "/ceph-data/core/webfarmd/httpd/example.ertest.kcl.ac.uk.conf"
        )
        output = subprocess.check_output(
            ["apachectl", "configtest"], stderr=subprocess.STDOUT
        ).decode("utf-8")
        assert "Syntax OK" in output
        mellon_xml_path = (
            "/ceph-data/core/example.ertest.kcl.ac.uk/mellon/https_example.ertest.kcl.ac.uk.xml"
        )
        assert os.path.exists(mellon_xml_path)
        assert self.line_in_file(
            "/var/www/vhost/idp.sso.er.kcl.ac.uk/writable/auto_sp_list.txt",
            mellon_xml_path,
        )
        assert os.path.exists("/var/www/vhost/example.ertest.kcl.ac.uk/mellon/https_example.ertest.kcl.ac.uk.key")
        assert self.line_in_file(
            "/var/www/vhost/idp.sso.er.kcl.ac.uk/app/ssphp-config/metadata/saml20-sp-remote-autogen.php",
            "$metadata['https://%s'] = array (" % s.fqdn,
        )
        assert self.line_in_file(
            "/ceph-data/core/webfarmd/httpd/example.ertest.kcl.ac.uk.conf",
            "AuthType Mellon",
        )
        assert self.line_in_file(
            "/ceph-data/core/webfarmd/httpd/example.ertest.kcl.ac.uk.conf",
            'MellonRequire "groups" "blah" "also" "bleh" ',
        )
        assert self.line_in_file(
            "/ceph-data/core/webfarmd/httpd/example.ertest.kcl.ac.uk.conf",
            'SSLProxyEngine on',
        )

    @patch("webfarmd.models.site.Site.save")
    def test_sites_deploy(self, mock_save):
        mock_save.return_value = True

        s = Site(MockPortalAPI(), self.get_example_site())
        s.subrelation_cache['locations'] = self.get_example_locations()
        s.subrelation_cache['waf_exclusions'] = []
        s.provision_ctl_directories()
        s.provision_directories("localhost")

        dep = SiteDeployment(MockPortalAPI(), self.get_example_deployment(), s)
        assert not os.path.exists(
            "/var/www/vhost/example.ertest.kcl.ac.uk/app/current/public/index.html"
        )
        dep.deploy()
        assert os.path.exists(
            "/var/www/vhost/example.ertest.kcl.ac.uk/app/current/public/index.html"
        )
        assert dep.status == "complete"
        adminuid = pwd.getpwnam("w3admin").pw_uid
        assert os.stat("/var/www/vhost/example.ertest.kcl.ac.uk/app/current").st_uid == adminuid

    def test_sites_provision_wordpress(self):
        s = Site(None, self.get_example_blog())
        s.subrelation_cache['locations'] = self.get_blog_locations()
        s.subrelation_cache['waf_exclusions'] = []
        s.internal_only = True
        s.provision_ctl_directories()
        s.provision_directories("localhost")
        s._provision_frontends()
        s._provision_proxies()

        assert not os.path.exists(
            "/ceph-data/core/webfarmd/nginx/shared/blogexample.ertest.kcl.ac.uk.conf"
        )
        assert os.path.exists(
            "/ceph-data/core/webfarmd/nginx/internal/blogexample.ertest.kcl.ac.uk.conf"
        )
        assert os.path.exists(
            "/ceph-data/core/webfarmd/nginx/external/blogexample.ertest.kcl.ac.uk.conf"
        )
        assert os.path.exists(
            "/ceph-data/core/webfarmd/docker-httpd/blogexample.ertest.kcl.ac.uk.conf"
        )
        output = subprocess.check_output(
            ["nginx", "-t"], stderr=subprocess.STDOUT
        ).decode("utf-8")
        assert "test is successful" in output

        output = subprocess.check_output(
            ["apachectl", "configtest"], stderr=subprocess.STDOUT
        ).decode("utf-8")
        assert "Syntax OK" in output

        assert self.line_in_file("/ceph-data/core/webfarmd/docker-httpd/blogexample.ertest.kcl.ac.uk.conf", 'ProxyPassMatch "^/(.*\\.php(/.*)?)$" "fcgi://127.0.0.1:9001/var/www/html/$1"')

if __name__ == "__main__":
    unittest.main()
