#!/usr/bin/env python3

from aws_cdk import core

from security_automation_respond_to_failed_ssh_access.security_automation_respond_to_failed_ssh_access_stack import SecurityAutomationRespondToFailedSshAccessStack


app = core.App()
SecurityAutomationRespondToFailedSshAccessStack(app, "security-automation-respond-to-failed-ssh-access")

app.synth()
