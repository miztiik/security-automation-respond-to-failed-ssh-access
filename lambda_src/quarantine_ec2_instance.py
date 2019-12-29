# -*- coding: utf-8 -*-
"""
.. module: quarantine_ec2_instance
    :Attaches: the instance a SG with no rules so it can't communicate with the outside world
"""

import logging
import os

import boto3
from botocore.exceptions import ClientError

__author__      = 'Mystique'
__email__       = 'miztiik@github'
__version__     = '0.0.1'
__status__      = 'production'


class global_args:
    """
    Helper to define global statics
    """
    TAG_NAME                    = 'quarantine_ec2_instance'
    LOG_LEVEL                   = logging.INFO


def set_logging(lv=global_args.LOG_LEVEL):
    '''
    Helper to enable debugging
    '''
    logging.basicConfig(level=lv)
    logger = logging.getLogger()
    logger.setLevel(lv)
    return logger


logger = set_logging(logging.INFO)


def get_qurantine_sg_id(inst_id):
    ec2_resource = boto3.resource('ec2')
    ec2_client = boto3.client('ec2')

    q_sg_name="infosec-quarantine"

    inst_attr = ec2_client.describe_instances( InstanceIds=[inst_id] )['Reservations'][0]['Instances'][0]
    if inst_attr:
        inst_vpc_id = inst_attr.get('VpcId')

    # Check or create the Quarantine SG
    try:    
        result = ec2_client.describe_security_groups(
            Filters=[
                    {
                        'Name': 'group-name',
                        'Values': [q_sg_name]
                    },
                    {
                        'Name': 'vpc-id',
                        'Values': [inst_vpc_id]
                    }
                ]
            )
        if result['SecurityGroups']: 
            quarantine_sg_id = result['SecurityGroups'][0]['GroupId']

        else:
            result = ec2_client.create_security_group(
                    Description='Quarantine SG. No Ingress or Egress.',
                    GroupName=q_sg_name,
                    VpcId=inst_vpc_id 
                    )

            security_group = ec2_resource.SecurityGroup(result['GroupId'])
            delete_outbound_result = security_group.revoke_egress(
                GroupId=result['GroupId'],
                IpPermissions=[{'IpProtocol':'-1','IpRanges': [{'CidrIp':'0.0.0.0/0'}]}]
                )
            tag = security_group.create_tags(Tags=[
                {'Key': 'Name','Value': "QUARANTINE-SG"}
                ]
            )
            logger.info(f"New quarantine Security Group Created. sg_id: {result['GroupId']}")
            quarantine_sg_id = result['GroupId']
        
    except ClientError as e:
        logger.info(f"Unable to find/create quarantine security group.ERROR: {str(e)}")
        exit

    return quarantine_sg_id

def quarantine_ec2_instance(inst_id, quarantine_sg_id):
    resp = {'status': False, 'message': {} }
    ec2_resource = boto3.resource('ec2')
    # Attach the instance to only the quarantine SG
    try:
        result = ec2_resource.Instance(inst_id).modify_attribute(Groups=[quarantine_sg_id])  
        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            resp['error_message'] = str(result)
        else:
            logger.info(f"Instance:{inst_id} quarantined with SG:{quarantine_sg_id}")
            resp['status'] = True
            resp['message'] = {'instance_id':inst_id, 'qurantine_sg_added':True, 'qurantine_sg_id': quarantine_sg_id}
    except ClientError as e:
        resp['message'] = {'instance_id':inst_id, 'qurantine_sg_added':False, 'error_message':str(e)}
    return resp


def lambda_handler(event, context):
    resp = {'status':False}
    if 'inst_id' in event:
        inst_id = event.get('inst_id')
        if inst_id:
            logger.info(f"Going to qurantine Instance :{inst_id}")
            quarantine_sg_id = get_qurantine_sg_id(inst_id)
            resp = quarantine_ec2_instance(inst_id, quarantine_sg_id)
            resp['message']['event_logs'] = event['message']
    else:
        resp['message'] = f"Instance ID is missing. Unable to Qurantine"
        resp['error_message']=f"Instance ID is missing. Unable to Qurantine"
    return resp
