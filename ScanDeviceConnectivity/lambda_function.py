###########################################################################################
# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at## http://aws.amazon.com/apache2.0/
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
# This function does the following:
# 1. Retrieve ASP API auth access token from secret manager
# 1. Scan all available units under ASP Org
# 2. Find the devices currently connectivity is OFFLINE
# 3. Send OFFLINE connectivity devices to property
###########################################################################################

import json
import boto3
import urllib3
import os
from datetime import datetime
from zoneinfo import ZoneInfo

import logging
logger = logging.getLogger()
logger.setLevel("INFO")

device_offline = ''

#Read ASP API Access Token from AWS Secret Manager 
def get_access_token():
    secret_name = os.environ['secret_mgr_asp_access_token'];
    region_name = os.environ['region'];

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        logger.error(e)
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString'];
    return 'Bearer ' + json.loads(secret)[os.environ['access_token_key']];


def check_device_connectivity(access_token, unit_id, unit_name, list_units):
    global device_offline
    url = f'https://api.amazonalexa.com/v2/endpoints?associatedUnits.id={unit_id}&expand=feature:connectivity'
    
    request = urllib3.PoolManager()
    response = request.request("GET", url, headers={'Content-Type': 'application/json', 'Authorization': access_token})
    if response.status == 200:
        all_devices = json.loads(response.data)
        for d_obj in all_devices['results']:
            if 'features' in d_obj:
                for obj in d_obj['features']:
                    if obj['name'] == 'connectivity':
                        try:
                            if obj['properties'][0]['value']['value'] != 'OK':
                                device_offline = f'{device_offline} \nDevice(s) in unit: {unit_name} connectivity: offline.  Last time offline: {obj['properties'][0]['timeOfSample']}'
                        except:
                            device_offline = f'{device_offline} \nDevice(s) in unit: {unit_name} connectivity: unknown.'
    

def check_all_rooms(access_token, next_token, parent_id, list_units):
    url = f'https://api.amazonalexa.com/v2/units/?parentId={parent_id}&expand=all'
    if next_token is not None:
        url = f'{url}&nextToken={next_token}'
    
    request = urllib3.PoolManager()
    response = request.request("GET", url, headers={'Content-Type': 'application/json', 'Authorization': access_token})
    if response.status == 200: 
        ret_val = json.loads(response.data)
        units = ret_val['results']
        
        for unit in units:
            check_device_connectivity(access_token, unit["id"], unit["name"]["value"]["text"], list_units)
            
        nextToken = ret_val['paginationContext']['nextToken']
        if nextToken is None:
            return list_units
        else:
            check_all_rooms(access_token, nextToken, parent_id, list_units)
    else:
        raise Exception (f'Failed to get room ids from parent room: {parent_id}')


def get_current_local_time():
     # Get the current time in UTC
    utc_time = datetime.utcnow()
    # Set the timezone to AST (Atlantic Standard Time)
    ast_tz = ZoneInfo("America/Halifax")
    # Adjust the current time to AST timezone with DST rules considered
    ast_time = utc_time.astimezone(ast_tz)
    # Format the current time for display
    return ast_time.strftime("%Y-%m-%d %H:%M:%S %Z")


def send_offline_devices_to_sns(summary):
    client = boto3.client("sns")
    resp = client.publish(TargetArn=os.environ['sns_arn'], Message=summary, Subject=get_current_local_time())
    logger.info(f'Send {summary} \n to sns for current offline devices')
    

def lambda_handler(event, context):
    units = []
    check_all_rooms(get_access_token(), None, os.environ['parent_unit_id'], units)
    logger.debug(f'Device offline summary: \n {device_offline}')
    
    send_offline_devices_to_sns(device_offline)