Using the AWS Process Credential tool with Okta
===============================================

Using this tool with Okta ensures that you have easy, secure, CLI access to your AWS resources through Okta.


Prerequisites
-------------

Before starting with this installation, you need to [set up Okta as an identity provider for your AWS account(s)](https://support.okta.com/help/servlet/fileField?retURL=/help/articles/Knowledge_Article/Amazon-Web-Services-and-Okta-Integration-Guide&entityId=ka0F0000000MeyyIAC&field=File_Attachment__Body__s). You should be able to SSO into your AWS dashboard via a web browser before starting to use this CLI tool.

You also need the AWS CLI tool itself (unless you are using the [Docker container](https://github.com/tom-smith-okta/okta-awscli-python) as mentioned below).

If you have not updated your AWS CLI tool recently, you should [update it](https://docs.aws.amazon.com/cli/latest/userguide/installing.html). Support for the `credentials-process` keyword (which this tool relies on) was added to the AWS CLI in the 2nd half of 2017.

Installing
-------------

If you would like to use a Docker container to run the tool, you can use the Docker container described [here](https://github.com/tom-smith-okta/okta-awscli-python).

## Installing from git ##

To install the awsprocesscreds tool, run these commands:
```
git clone https://github.com/tom-smith-okta/awsprocesscreds

cd awsprocesscreds

git checkout tsmith/rc03

pip install -e .

```

Updating your .aws/config file
------------------------------

Now that you have installed the `awsprocesscreds` tool, you can add profiles that leverage this tool (and Okta authentication) to your `.aws/config` file.

To test, add a new profile to your `.aws/config` file like the following example:

>Note: line breaks are shown here for readability only. In your `config` file the command must all be on one line.

```
# example for user Clark Kent
[profile ck]
credential_process = awsprocesscreds-saml  
-e https://partnerpoc.oktapreview.com/home/amazon_aws/0oadci5fdr3PZtXB30h7/137  
-u clark.kent  
-p okta  
-a arn:aws:iam::919536943542:role/okta2_S3_read_only  
--no-cache
```

You can then execute a command like:

```
aws s3 ls --profile ck
```

and you will be prompted to enter Clark Kent's Okta credentials.

The syntax of the credential_process and awsprocesscreds-saml commands is as follows:

```
credential_process = awsprocesscreds-saml [-h] -e ENDPOINT -u USERNAME -p {okta,adfs} [-a ROLE_ARN] [--no-cache] [-v]
```

`ENDPOINT` is your Okta AWS app URL

`ROLE_ARN` is the AWS role ARN

For troubleshooting, you can use the `-v` (or `--verbose`) flag to see more details about the authentication event.

>Note: the `-v` and `--verbose` flags work only when using the awsprocesscreds-saml command as a standalone command, outside of the AWS CLI.

