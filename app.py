#!/usr/bin/env python3

from aws_cdk import core

from security_automation_respond_to_failed_ssh_access.respond_to_failed_ssh_access_stack import RespondToFailedSshAccessStack


app = core.App()
RespondToFailedSshAccessStack(app, "security-automation-respond-to-failed-ssh-access")


# Tag the stack resources
core.Tag.add(app,key="Owner",value=app.node.try_get_context('owner'))
core.Tag.add(app,key="OwnerProfile",value=app.node.try_get_context('github_profile'))
core.Tag.add(app,key="ToKnowMore",value=app.node.try_get_context('youtube_profile'))

"""
# Tags in a loop
with open('tags.json', 'rb') as f:
    tag_data = json.load(f)

if data:
    try:
        core.Tag.add(app, 'Environment', app_env)
        app_env = app.node.try_get_context('Environment')
        for tag_key, tag_value in tag_data.get(app_env).items():
            core.Tag.add(app, tag_key, tag_value)
    except json.JSONDecodeError as e:
        print(str(e))
"""

# Synth the CF template
app.synth()