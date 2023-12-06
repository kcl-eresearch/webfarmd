import json
import hashlib
import logging
import time
from threading import Thread


class QueueDaemon:
    def __init__(self, omb, config, internal_queue):
        self.omb = omb
        self.psk = config.required_attribute("psk")
        self.queue = config.optional_attribute("omb_queue", "webfarm")
        self.num_worker_threads = config.optional_attribute("num_threads", 10)
        self.internal_queue = internal_queue
        self.threads = []

    def tidy_threads(self):
        self.threads = [thread for thread in self.threads if thread.is_alive()]

    def wait_for_available_thread(self):
        while len(self.threads) >= self.num_worker_threads:
            self.tidy_threads()
            time.sleep(0.1)

    def get_queue(self):
        return self.queue

    def retry_message(self, msg):
        self.internal_queue.put_nowait(msg)

    def chksum(self, str):
        saltedmsg = "%s%s" % (self.psk, str)
        return hashlib.sha224(saltedmsg.encode("ascii")).hexdigest()

    def send_message(self, msg, queue=None):
        msg["chksum"] = self.chksum(msg["message"])
        self.omb.simple_send(self.queue if not queue else queue, msg)

    def require_chksum(self, obj):
        if "chksum" not in obj or obj["chksum"] != self.chksum(obj["message"]):
            raise Exception("Message had invalid chksum: %s" % obj["chksum"])

    def on_message(self, ch, method, properties, body):
        try:
            obj = json.loads(body)
        except Exception as e:
            logging.warning("Found malformed message: %s" % body)
            return

        if "message" not in obj:
            logging.warning("Found malformed message: %s" % body)
            return

        self.wait_for_available_thread()

        try:
            func = getattr(self, "run_msg_%s" % obj["message"])
            t = Thread(target=func, args=[obj])
            t.start()
            self.threads.append(t)
        except Exception as e:
            logging.error("Encountered exception processing message %s" % body)
            return
