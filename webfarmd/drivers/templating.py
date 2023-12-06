#
# Webfarmd
#
# Author: Skylar Kelty
#

from jinja2 import Environment, PackageLoader, select_autoescape


class Templating:
    def __init__(self):
        self.env = Environment(
            loader=PackageLoader("webfarmd"), autoescape=select_autoescape()
        )

    def render(self, tpl, data={}):
        template = self.env.get_template(tpl)
        return template.render(**data)
