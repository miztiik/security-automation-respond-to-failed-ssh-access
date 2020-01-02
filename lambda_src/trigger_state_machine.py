# -*- coding: utf-8 -*-
"""
.. module: trigger_state_machine
    :Actions: Trigger state machine for given arn
    :platform: AWS
    :copyright: (c) 2020 Mystique.,
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Mystique
.. contactauthor:: miztiik@github issues
"""

import json
import logging
import base64
import urllib
import zlib
import os

import boto3
from botocore.exceptions import ClientError

__author__      = 'Mystique'
__email__       = 'miztiik@github'
__version__     = '0.0.1'
__status__      = 'production'

"""
GENERIC HELPERS
"""

class global_args:
    """
    Helper to define global statics
    """
    OWNER                       = 'Mystique'
    ENVIRONMENT                 = 'production'
    TAG_NAME                    = 'trigger_state_machine'
    LOG_LEVEL                   = logging.INFO


def set_logging(lv=global_args.LOG_LEVEL):
    '''
    Helper to enable debugging
    '''
    logging.basicConfig(level=lv)
    logger = logging.getLogger()
    logger.setLevel(lv)
    return logger


# Initialize Logger
logger = set_logging(logging.INFO)


def trigger_state_machine(event):
    resp = {'status': False,}
    client = boto3.client('stepfunctions')
    try:
        if 'STATE_MACHINE_ARN' in os.environ:
            logger.info(f'Logs:{event}')
            resp['message'] = client.start_execution(
                stateMachineArn=os.environ.get('STATE_MACHINE_ARN'),
                input=json.dumps({
                        'inst_id': event.get('inst_id'),
                        'message':event.get('message')
                        }
                    )
                )
            resp['status'] = True
    except ClientError as e:
        logger.error(f"Something went wrong. ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp


def awslogs_handler(event):
    resp = {'status': False,}
    if 'awslogs' in event:
        if 'data' in event['awslogs']:
            try:
                log_data = zlib.decompress(base64.b64decode(event["awslogs"]["data"]), 16 + zlib.MAX_WBITS)
              # json.loads(zlib.decompress(base64.b64decode(event['awslogs']['data']), zlib.MAX_WBITS | 32))
                log_data = log_data.decode("utf-8")
                resp['logs'] = json.loads(log_data)
                resp['inst_id'] = resp['logs'].get('logStream')
                resp['message'] = resp['logs'].get('logEvents')[0].get('message')
                resp['status'] = True
            except ClientError as e:
                logger.error(f"Something went wrong. ERROR:{str(e)}")
                resp['error_message'] = str(e)
    return resp


def lambda_handler(event, context):
    resp = {'status': False}
    # logger.info(f'Event:{event}')
    event = awslogs_handler(event)
    resp = trigger_state_machine(event)
    # t_resp = trigger_state_machine(event)
    # resp['status'] = t_resp.pop('status', None)
    return resp


if __name__ == '__main__':
    lambda_handler({}, {})
