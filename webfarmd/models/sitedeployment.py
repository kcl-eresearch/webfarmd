#
# Webfarmd
#

import os
from webfarmd.models import CLIModel
from sci_portal import SiteDeployment as _SiteDeployment


class SiteDeployment(_SiteDeployment, CLIModel):
    def deploy(self):
        """
        Deploy this site.
        """
        deploypath = "/var/www/vhost/%s/app" % self.parent.fqdn

        self.status = "deploying"
        self.save()

        # Check if we have a custom SSH key.
        keyfilegen = "/home/w3admin/.ssh/webfarmd/w3general"
        keyfile = "/home/w3admin/.ssh/webfarmd/w3site%s" % self.parent.id
        environment = {}
        if os.path.isfile(keyfilegen):
            if os.path.isfile(keyfile):
                environment[
                    "GIT_SSH_COMMAND"
                ] = "ssh -i %s -i %s -o IdentitiesOnly=yes" % (keyfile, keyfilegen)
            else:
                environment["GIT_SSH_COMMAND"] = (
                    "ssh -i %s -o IdentitiesOnly=yes" % keyfilegen
                )

        # Deploy.
        self.run_proc(["rm", "-rf", "%s/latest" % deploypath])

        result = self.run_proc(
            [
                "git",
                "-C",
                deploypath,
                "clone",
                "-b",
                self.revision,
                self.repo,
                "latest",
            ],
            cwd=deploypath,
            text=True,
            env=environment,
        )
        if result != 0:
            self.reason = (
                "Checkout of %s:%s failed. Check the deployment key and ensure the repository is visible."
                % (self.repo, self.revision)
            )
            self.status = "error"
            self.save()
            raise Exception("%s: %s" % (self.parent.fqdn, self.reason))

        # Move latest to new current.
        self.run_proc(["rm", "-rf", "%s/old" % deploypath])

        # Move old deployment out of the way.
        if os.path.exists("%s/current" % deploypath):
            result = self.run_proc(
                ["mv", "%s/current" % deploypath, "%s/old" % deploypath]
            )
            if result != 0:
                self.reason = "Cannot move current deployment folder."
                self.status = "error"
                self.save()
                raise Exception("%s: %s" % (self.parent.fqdn, self.reason))

        self.run_proc(["mv", "%s/latest" % deploypath, "%s/current" % deploypath])

        # Update Portal.
        self.reason = ""
        self.status = "complete"
        self.save()
