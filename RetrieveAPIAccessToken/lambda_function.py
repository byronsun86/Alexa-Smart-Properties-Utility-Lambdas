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
# 1. Get all required info for OAuth2 of LWA from AWS Secret Manager
# 2. Call LWA Auth to get access token
# 3. Update the ASP API access token to AWS Secret Manager 
###########################################################################################

import json
import urllib3
import boto3
import os
from botocore.exceptions import ClientError

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Get Client Id, secret, refresh token, and scope value from secret manager
def get_oauth_required_info(client):
    secret_name_for_oauth = os.environ['lwa_oauth_info']
    
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name_for_oauth
        )
    except ClientError as e:
        logger.error (f'Failed to retrieve required info for LWA API call')
        raise e

    # Decrypts secret using the associated KMS key.
    return get_secret_value_response['SecretString']


# call auth API to get access token 
def lwa_oauth(oauth_info):
    lib3_request = urllib3.PoolManager()
    request_body = {'grant_type': 'refresh_token', 'refresh_token': oauth_info["lwa-refresh-token"], 'client_id': oauth_info["lwa-client-id"], 'client_secret': oauth_info["lwa-client-secret"], 'scope': oauth_info["lwa-auth-scope"]}
    response = lib3_request.request("POST", oauth_info["lwa-auth-url"], headers={'Accept': 'application/x-www-form-urlencoded'}, body=json.dumps(request_body).encode('utf-8'))
   
    logger.debug (response.data)
    if response.status == 200:
        return json.loads(response.data)['access_token']
    else:
        logger.error (f'Failed to get access token with response status: {response.status} and body: {response.data}')
        return None
        

# save api access token to secret manager
def save_access_token(client, access_token):
    secret_name_access_token = os.environ['api_access_token']
    secret_name_access_token_key = os.environ['api-access-token']
    
    try:
        get_secret_value_response = client.put_secret_value(
            SecretId = secret_name_access_token,
            SecretString = f'{{"{secret_name_access_token_key}": "{access_token}"}}'
        )
    except ClientError as e:
        logger.error (f'Failed to save access token: {access_token} to secret name: {secret_name_access_token}')
        raise e


def lambda_handler(event, context):
    try:
        #secret manager region value
        region_name = os.environ['sm_region'] 
        
        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )
        
        save_access_token(client, lwa_oauth(json.loads(get_oauth_required_info(client))))
    except Exception as e:
        logger.error (e)
