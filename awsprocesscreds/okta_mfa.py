import botocore
from botocore.compat import json

import os

class OktaMFAError(Exception):
    pass

class OktaMFA:

    # initialize with the object returned from Okta authn request
    def __init__(self, authn_obj):
        self.authn_obj = authn_obj

        sf_json = open(os.getcwd() + "/awsprocesscreds/supported_factors.json")

        self.supported_factors = json.load(sf_json)

        self.my_factors = self.authn_obj["_embedded"]["factors"]

        self._get_factors()

    def _get_factors(self):
        i = 0
        user_has_supported_factor = False
        choices = ""

        for factor in self.my_factors:

            friendly_name = self._get_friendly_name(factor)

            if friendly_name != "not supported":
                # print "%s) %s" % (i, friendly_name)
                choices += "%s) %s \n" % (i, friendly_name)
                user_has_supported_factor = True
            i += 1

        if not user_has_supported_factor:
            raise OktaMFAError("you are not enrolled in any factors that are supported by this tool")

        print "Choose a factor: \n%s" % choices

    def _get_friendly_name(self, this_factor):
        for key, value in self.supported_factors.iteritems():
            if this_factor["factorType"] == value["factor_type"] and this_factor["provider"] == value["provider"]:
                return key
        return "not supported"
