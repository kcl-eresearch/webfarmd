"""
This webfarm daemon is responsible for listening to the dashboard
database and message queues and setting up or modifying sites on demand.

This should run on webctl.
It will run commands on the frontends and backends via the client.
"""

import logging
import socket
import threading
import queue

from logging.handlers import RotatingFileHandler
from webfarmd.queue_daemon import QueueDaemon
from webfarmd.jobs.tls import tls_upload
from webfarmd.models.group import Group
from webfarmd.models.user import User
from webfarmd.models.site import Site
from webfarmd.models.sitedeployment import SiteDeployment
from sci_portal import SiteLocation
from sci_portal.base import LockedException
from sci_common.omb import OMBClient
from sci_common.config import ConfigReader


class ServerD(QueueDaemon):
    def run_msg_group_on_member_added(self, obj):
        user = User.find(obj["userid"])
        group = Group.find(obj["id"])
        logging.info("Found new group_on_member_added job for group %s" % group.id)
        group.on_add_member(user)

    def run_msg_group_on_member_removed(self, obj):
        user = User.find(obj["userid"])
        group = Group.find(obj["id"])
        logging.info("Found new group_on_member_removed job for group %s" % group.id)
        group.on_remove_member(user)

    def run_msg_group_created(self, obj):
        group = Group.find(obj["id"])
        logging.info("Found new group_on_created job for group %s" % group.id)
        group.on_created()

    def run_msg_group_on_group_added(self, obj):
        group = Group.find(obj["id"])
        group2 = Group.find(obj["groupid"])
        logging.info("Found new group_on_group_added job for group %s" % group.id)
        group2.on_add_group(group)

    def run_msg_group_changed(self, obj):
        groupid = obj["id"]
        logging.info("Found new group_changed job for group %s" % groupid)
        group = Group.find(groupid)
        group.on_change()

    def run_msg_site_changed(self, obj):
        logging.info("Found new site_changed job")
        site = Site.find(obj["id"])
        try:
            site.provision()
        except LockedException:
            # Retry later
            self.retry_message(obj)

    def run_msg_site_update_tls(self, obj):
        logging.info("Found new site_update_tls job")
        site = Site.find(obj["id"])
        site.handle_ssl()

    def run_msg_site_security_scan(self, obj):
        logging.info("Found new site_security_scan job")
        site = Site.find(obj["id"])
        site.run_security_scan()

    def run_msg_site_location_security_scan(self, obj):
        logging.info("Found new site_location_security_scan job")

        site = Site.find(obj["siteid"])
        location = SiteLocation.find(obj["id"], site)
        if not location:
            logging.info("Could not find location")
            return
        site.run_location_security_scan(location)

    def run_msg_deploy_site(self, obj):
        siteid = obj["site_id"]
        deployid = obj["deploy_id"]
        logging.info("Found new job: deploy %s" % siteid)
        site = Site.find(siteid)
        deploy = SiteDeployment.find(deployid, site)
        deploy.deploy()

    def run_msg_upload_ssl_cert(self, obj):
        fqdn = obj["fqdn"]
        logging.info("Found new job: upload SSL cert for '%s'" % fqdn)
        tls_upload(fqdn, obj["ca"], obj["cert"], obj["private"])

    def run_msg_enter_maintenance_mode(self, obj):
        siteid = obj["site_id"]
        logging.info("Found new job: enter maintenance mode for %s" % siteid)
        site = Site.find(siteid)
        site.write_system_template_files(True, obj["eta"] if "eta" in obj else None)
        site._provision_frontends()

    def run_msg_exit_maintenance_mode(self, obj):
        siteid = obj["site_id"]
        logging.info("Found new job: exit maintenance mode for %s" % siteid)
        site = Site.find(siteid)
        site.write_system_template_files(True)
        site._provision_frontends()

    def run_msg_create_ad_user(self, obj):
        id = obj["id"]
        dn = obj["dn"]
        description = obj["description"]

        email_pw = None
        if "for_user_id" in obj:
            try:
                email_pw = User.find(obj["for_user_id"])
            except Exception:
                email_pw = None
        if "for_user_email" in obj:
            email_pw = {
                "display_name": obj["for_user_email"],
                "email": obj["for_user_email"],
            }

        logging.info("Found new job: create AD user from Portal user %s" % id)
        try:
            user = User.find(id)
            user.create_in_ad(dn, description, email_pw)
        except Exception:
            logging.info("Could not create AD user from Portal user %s" % id)
            return

    def run_msg_delete_site(self, obj):
        id = obj["id"]
        logging.info("Found new job: delete site %s" % id)
        site = Site.find(id)
        site.delete()

    def run_msg_wordpress_sync_users(self, obj):
        id = obj["id"]
        logging.info("Found new job: wordpress sync_users %s" % id)
        site = Site.find(id)
        site.config_driver.wp_check_members()

    def run_msg_wordpress_sync_themes(self, obj):
        id = obj["id"]
        logging.info("Found new job: wordpress sync_themes %s" % id)
        site = Site.find(id)
        site.config_driver.wp_install_themes()

    def run_msg_wordpress_sync_plugins(self, obj):
        id = obj["id"]
        logging.info("Found new job: wordpress sync_plugins %s" % id)
        site = Site.find(id)
        site.config_driver.wp_install_plugins()

    def run_msg_wordpress_wipe_reset(self, obj):
        id = obj["id"]
        logging.info("Found new job: wordpress sync_plugins %s" % id)
        site = Site.find(id)
        site.config_driver.delete()
        site.config_driver.check_installed()
        site.config_driver.wp_check_members()

    def handle_admin_client(self, client_socket):
        request = client_socket.recv(1024).decode("utf-8").strip()
        print(f"Received request: {request}")

        if request == "status":
            self.tidy_threads()

            if not self.active_thread.is_alive():
                response = "Degraded (no active main thread, %s/%s workers active)" % (
                    len(self.threads),
                    self.num_worker_threads,
                )
            elif not self.internal_queue_thread.is_alive():
                response = (
                    "Degraded (no active internal queue thread, %s/%s workers active)"
                    % (len(self.threads), self.num_worker_threads)
                )
            else:
                response = "OK (%s/%s workers active)" % (
                    len(self.threads),
                    self.num_worker_threads,
                )

        else:
            response = "Invalid request"

        client_socket.send(response.encode("utf-8"))
        client_socket.close()


def handle_internal_queue(intq):
    while True:
        try:
            msg = intq.get()
            logging.info("Got internal message: %s" % msg)

            if msg["message"] == "site_changed":
                while True:
                    try:
                        site = Site.find(msg["id"])
                        site.provision()
                        break
                    except LockedException:
                        # Retry later
                        pass
        except Exception as e:
            logging.error("Error handling internal message: %s" % e)


def handle_admin_client_queue(serverd):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 9342))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(
            target=serverd.handle_admin_client, args=(client_socket,)
        )
        client_handler.start()


def run_server():
    logging.basicConfig(
        handlers=[
            RotatingFileHandler(
                "/var/log/webfarmd.log", maxBytes=100000, backupCount=10
            )
        ],
        level=logging.INFO,
    )

    logging.info("Starting webfarmd...")

    # Load config.
    config = ConfigReader("/etc/webfarmd/webfarmd.yaml")
    username = config.required_attribute("omb_username")
    password = config.required_attribute("omb_password")
    vhost = config.optional_attribute("omb_vhost", "webfarm_primary")
    host = config.optional_attribute("omb_host", "auto")

    # Create OMB.
    intq = queue.Queue()
    omb = OMBClient(username, password, vhost, host)
    serverd = ServerD(omb, config, intq)

    qdt = threading.Thread(
        target=omb.simple_receive,
        args=[serverd.get_queue(), serverd.on_message],
        daemon=True,
    )
    qdt.start()
    serverd.active_thread = qdt

    iqdt = threading.Thread(target=handle_internal_queue, args=[intq], daemon=True)
    iqdt.start()
    serverd.internal_queue_thread = iqdt

    act = threading.Thread(
        target=handle_admin_client_queue, args=[serverd], daemon=True
    )
    act.start()

    qdt.join()

    logging.info("Stopping webfarmd...")
