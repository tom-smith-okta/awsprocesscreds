# {
#     "sms": {
#         "factor_type": "sms",
#         "provider": "OKTA"
#     },
#     "Okta Verify (push)": {
#         "factor_type": "push",
#         "provider": "OKTA"
#     },
#     "Okta Verify (otp)": {
#         "factor_type": "token:software:totp",
#         "provider": "OKTA"
#     },
#     "Google Authenticator": {
#         "factor_type": "token:software:totp",
#         "provider": "GOOGLE"
#     }
# }

sf = {}

sf["sms"] = {}
sf["sms"]["factor_type"] = "sms"
sf["sms"]["provider"] = "OKTA"

sf["Okta Verify (push)"] = {}
sf["Okta Verify (push)"]["factor_type"] = "push"
sf["Okta Verify (push)"]["provider"] = "OKTA"

sf["Okta Verify (otp)"] = {}
sf["Okta Verify (otp)"]["factor_type"] = "token:software:totp"
sf["Okta Verify (otp)"]["provider"] = "OKTA"

sf["Google Authenticator"] = {}
sf["Google Authenticator"]["factor_type"] = "token:software:totp"
sf["Google Authenticator"]["provider"] = "GOOGLE"