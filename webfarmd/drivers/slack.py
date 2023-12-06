#
# Webfarmd
#
# Author: Skylar Kelty
#

from sci_common.config import ConfigReader
from sci_common.slack import SlackClient


class SlackDriver(SlackClient):
    def __init__(self):
        config = ConfigReader("/etc/webfarmd/webfarmd.yaml")
        slack_webhook = config.required_attribute("slack_webhook")
        super(SlackDriver, self).__init__(slack_webhook)

    @staticmethod
    def send_message(message):
        client = SlackDriver()
        client.send(message)
