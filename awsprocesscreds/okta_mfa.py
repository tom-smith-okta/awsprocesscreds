import botocore
from botocore.compat import json

import os
import requests

import supported_factors

class OktaMFAError(Exception):
    pass

class OktaMFA:

    # this tool supports only a subset of Okta's MFA factors
    # sf_json = open(os.getcwd() + "/awsprocesscreds/supported_factors.json")
    # _SUPPORTED_FACTORS = json.load(sf_json)

    print "the supported factors are: %s" % supported_factors.sf

    _SUPPORTED_FACTORS = supported_factors.sf

    # initialize with the object returned from Okta authn request
    def __init__(self, authn_obj, requests_session=None):
        self.authn_obj = authn_obj

        if requests_session is None:
            requests_session = requests.Session()
            self._requests_session = requests_session

        print "authn obj is: %s " % authn_obj

        self.my_supported_factors = self._get_my_supported_factors()

        print "my supported factors are: %s" % self.my_supported_factors

    def _get_my_supported_factors(self):

        my_factors = self.authn_obj["_embedded"]["factors"]

        my_sf = {}

        i = 0
        user_has_supported_factor = False

        for factor in my_factors:

            friendly_name = self._get_friendly_name(factor)

            if friendly_name != "not supported":
                my_sf[i] = {}
                my_sf[i]["url"] = factor["_links"]["verify"]["href"]
                my_sf[i]["name"] = friendly_name
                user_has_supported_factor = True
                i += 1

        if not user_has_supported_factor:
            raise OktaMFAError("you are not enrolled in any factors that are supported by this tool")

        return my_sf

    def _display_choices(self):
        choices = ""
        for key, value in self.my_supported_factors.iteritems():
            choices += "%s) %s \n" % (key, value["name"])

        print "\nMFA in place. Available factors: \n%s" % choices

        choice = raw_input("which factor? ")

        return int(choice)

    def get_session_token(self):
        choice = self._display_choices()

        response = self._send_challenge(choice)

        if response.status_code != 200:
            raise OktaMFAError("something went wrong with the request.")

        passcode = raw_input("passcode: ")

        payload = "{\"stateToken\": \"%s\", \"passCode\": \"%s\"}" % (self.authn_obj["stateToken"], passcode)

        url = self.my_supported_factors[choice]["url"]

        headers = {
            'Accept': "application/json",
            'Content-Type': "application/json",
            'Cache-Control': "no-cache",
        }

        response = self._requests_session.post(
            url, data=payload, headers=headers
        )

        parsed = json.loads(response.text)

        print "the response text is: %s " % response.text

        if parsed["status"] == "SUCCESS":

            self.session_token = parsed["sessionToken"]

        return parsed["sessionToken"]

    def _send_challenge(self, choice):
        url = self.my_supported_factors[choice]["url"]

        print "the state token is: %s " % self.authn_obj["stateToken"]

        payload = "{\"stateToken\": \"%s\"}" % self.authn_obj["stateToken"]

        headers = {
            'Accept': "application/json",
            'Content-Type': "application/json",
            'Cache-Control': "no-cache",
        }

        response = self._requests_session.post(
            url, data=payload, headers=headers
        )

        print "the response text is: %s " % response.text

        return response

    def _get_friendly_name(self, this_factor):
        for key, value in self._SUPPORTED_FACTORS.iteritems():
            if this_factor["factorType"] == value["factor_type"] and this_factor["provider"] == value["provider"]:
                return key
        return "not supported"
