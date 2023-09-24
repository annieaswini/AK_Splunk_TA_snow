import os.path as op
import sys
import time
from traceback import format_exc

sys.path.insert(0, op.dirname(op.dirname(op.abspath(__file__))))

import snow_event_base as seb  # noqa : E402


class ModSnowEvent(seb.SnowEventBase):
    def __init__(self, payload, account):
        self._payload = payload
        self._payload["configuration"]["url"] = payload["results_link"]
        self._session_key = payload["session_key"]
        self.account = account
        super(ModSnowEvent, self).__init__()

    def _get_session_key(self):
        return self._session_key

    def _get_events(self):
        return (self._payload["configuration"],)


def process_event(helper, *args, **kwargs):

    # Initialize the class and execute the code for alert action
    helper.log_info("Alert action snow_event started.")
    helper.settings["configuration"]["time_of_event"] = time.strftime(
        "%Y-%m-%d %H:%M:%S", time.gmtime()
    )
    account_list = [
        account.strip()
        for account in helper.settings["configuration"].pop("account", "").split(",")
    ]

    for acc_name in account_list:
        try:
            handler = ModSnowEvent(helper.settings, acc_name)
            handler.handle()
        except Exception:
            helper.log_error(
                "Failed to create event for the account: {}. Reason: {}".format(
                    acc_name, format_exc()
                )
            )
            continue
    return 0
