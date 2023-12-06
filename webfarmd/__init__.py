import os

from sci_common.config import ConfigReader

if "PORTAL_API_TOKEN" not in os.environ:
    config = ConfigReader("/etc/webfarmd/webfarmd.yaml")
    os.environ["PORTAL_URL"] = config.required_attribute("dashboard_api_url")
    os.environ["PORTAL_API_TOKEN"] = config.required_attribute("dashboard_api_token")

try:
    import sentry_sdk

    sentry_sdk.init(
        "https://14398d32cc6a4991a1630109067acdc9@sentry.er.kcl.ac.uk/3",
    )
except:
    pass
