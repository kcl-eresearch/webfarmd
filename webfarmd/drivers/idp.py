#
# Webfarmd
#
# Author: Skylar Kelty
#

import xml.etree.ElementTree as ET
import os
import validators
import hashlib

from urllib.parse import urlparse
from webfarmd.drivers.templating import Templating


class IdentityProvider:
    def __init__(self):
        self._service_provider_xmls = None
        self._service_providers = None

    @property
    def service_provider_xmls(self):
        if self._service_provider_xmls is None:
            with open(
                "/var/www/vhost/idp.sso.er.kcl.ac.uk/writable/auto_sp_list.txt", "r"
            ) as file:
                self._service_provider_xmls = [
                    x.strip() for x in file.readlines() if len(x) > 0
                ]
        return self._service_provider_xmls

    @property
    def service_providers(self):
        if self._service_providers is None:
            self._service_providers = []
            for line in self.service_provider_xmls:
                path = line.rstrip()
                self._service_providers.append(self.parse_sp(path))
        return self._service_providers

    def sanitize(self, str):
        str = str.replace("'", "")
        return str

    def parse_sp(self, path):
        tree = ET.parse(path)
        root = tree.getroot()

        # EntityID, e.g. https://sysdocs.er.kcl.ac.uk
        entityid = root.attrib["entityID"]

        # This is the only check that really matters, everything else is not technically user input
        # as it comes from the mellon script.
        # Additionally, the actual user input bit is already sanitized.
        # This is like a final check, in case of injection somewhere else along the chain.
        if not validators.url(entityid):
            raise Exception("Invalid URL supplied: %s" % entityid)

        tpldata = {
            "entityid": self.sanitize(entityid),
        }

        # {'Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'Location': 'https://sysdocs.er.kcl.ac.uk/mellon/postResponse', 'index': '0'}
        acs = root.find(
            ".//*{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService"
        ).attrib
        tpldata["ACSBinding"] = self.sanitize(acs["Binding"])
        tpldata["ACSUrl"] = self.sanitize(acs["Location"])

        # The X509Certificate
        sslcert = root.find(".//*{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
        if sslcert:
            tpldata["X509Certificate"] = self.sanitize(sslcert.text)
        else:
            tpldata["X509Certificate"] = ""

        # {'Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'Location': 'https://sysdocs.er.kcl.ac.uk/mellon/logout'}
        slo = root.find(".//*{urn:oasis:names:tc:SAML:2.0:metadata}SingleLogoutService")
        if slo:
            slo = slo.attrib
            tpldata["SLOBinding"] = self.sanitize(slo["Binding"])
            tpldata["SLOUrl"] = self.sanitize(slo["Location"])
        else:
            tpldata["SLOBinding"] = ""
            tpldata["SLOUrl"] = ""

        templating = Templating()
        return templating.render("site/software/simplesamlphp/idp_sp.j2", tpldata)

    def ensure_sp(self, path):
        """
        Ensure the supplied SP exists.
        """
        if not os.path.exists(path):
            raise Exception("Could not find SP XML %s" % path)

        if path in self.service_provider_xmls:
            return

        # Try to parse.
        sp = self.parse_sp(path)

        # Make sure we are in the auto sp list.
        xmls = self.service_provider_xmls
        xmls.append(path)
        with open(
            "/var/www/vhost/idp.sso.er.kcl.ac.uk/writable/auto_sp_list.txt", "w"
        ) as file:
            for x in xmls:
                file.write("%s\n" % x)
        self._service_provider_xmls = None

        # Also add the sp to autogen.
        with open(
            "/var/www/vhost/idp.sso.er.kcl.ac.uk/app/ssphp-config/metadata/saml20-sp-remote-autogen.php",
            "a",
        ) as file:
            file.write(sp)
            file.write("\n\n")

    def register_sp(self, entityid, remote_acs, remote_slo="", bind_artifact=False):
        """
        Register an SP with the given data.
        """
        urlparts = urlparse(entityid)
        urlhash = hashlib.md5(entityid.encode()).hexdigest()
        path = "/var/www/vhost/idp.sso.er.kcl.ac.uk/writable/sp_metadata/%s_%s.xml" % (
            urlparts.hostname,
            urlhash,
        )
        if os.path.exists(path):
            return
        if path in self.service_provider_xmls:
            return

        # Render.
        templating = Templating()
        spxml = templating.render(
            "site/software/simplesamlphp/simplesp.xml.j2",
            {
                "entityid": entityid,
                "remote_acs": remote_acs,
                "remote_slo": remote_slo,
                "bind_artifact": bind_artifact,
            },
        )

        # Write to path.
        with open(path, "w") as file:
            file.write(spxml)

        # Register with IdP.
        self.ensure_sp(path)

    def register_simple_sp(self, url):
        """
        Register an SP with the given URL.
        This is expected to be a very generic SAML 2.0 SP.
        URL must point to a SAML installation, e.g. https://blah.er.kcl.ac.uk/_sp
        """
        if url[-1] == "/":
            url = url[:-1]
        self.register_sp(
            entityid="%s/module.php/saml/sp/metadata.php/default-sp" % url,
            remote_acs="%s/module.php/saml/sp/saml2-acs.php/default-sp" % url,
            remote_slo="%s/module.php/saml/sp/saml2-logout.php/default-sp" % url,
            bind_artifact=True,
        )

    def register_wordpress_sp(self, url):
        """
        Register a simple WordPress SP, given a URL.
        """
        if url[-1] == "/":
            url = url[:-1]
        acs = "%s/wp-login.php" % url
        self.register_sp(
            entityid=acs,
            remote_acs=acs,
        )

    def clean_sp(self, path):
        """
        Remove an old SP.
        """
        # Make sure we are not in the auto sp list.
        with open(
            "/var/www/vhost/idp.sso.er.kcl.ac.uk/writable/auto_sp_list.txt", "w"
        ) as file:
            for x in self.service_provider_xmls:
                if x != path:
                    file.write("%s\n" % x)
        self._service_provider_xmls = None
        self.regenerate()

    def regenerate(self):
        """
        Rebuild the whole autogen file from scratch.
        """
        content = ""
        for sp in self.service_providers:
            content = "%s\n\n%s" % (content, sp)

        with open(
            "/var/www/vhost/idp.sso.er.kcl.ac.uk/app/ssphp-config/metadata/saml20-sp-remote-autogen.php",
            "w",
        ) as file:
            file.write("<?php")
            file.write("\n")
            file.write("// Auto generated by webfarmd DO NOT EDIT.")
            file.write(content)
