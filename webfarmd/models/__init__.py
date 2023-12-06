#
# Webfarmd
#

import os
import pwd
import grp
import subprocess


class CLIModel(object):
    def demote_wwwadmin(self):
        adminuid = pwd.getpwnam("w3admin").pw_uid
        admingid = grp.getgrnam("w3admin").gr_gid
        os.setgid(admingid)
        os.setuid(adminuid)

    def run_proc(self, args, **kwargs):
        return subprocess.Popen(args, preexec_fn=self.demote_wwwadmin, **kwargs).wait()
