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
# This function includes the method to:
# 1. Delete all campaign cards
# 2. Delete specific campagin card
# 3. Get all campaign cards
###########################################################################################

import json
import os
import boto3
import urllib3

import logging
logger = logging.getLogger()
logger.setLevel("INFO")

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


def get_all_campaign_cards(access_token, nextToken):
    url = f'https://api.amazonalexa.com/v1/proactive/campaigns?maxResults=10'
    
    if nextToken != None: 
        url = f'{url}&nextToken={nextToken}'
    
    logger.debug(url);
    lib3_request = urllib3.PoolManager()
    response = lib3_request.request("GET", url, headers={'Content-Type': 'application/json', 'Authorization': access_token})

    if response.status == 200:
        #this is for deleting all camaign cards, be very cautions this call before uncomment the method below
        clean_all_campaign_cards(access_token, json.loads(response.data)['results'])
        
        if json.loads(response.data)['paginationContext']['nextToken'] != None:
            get_all_campaign_cards(access_token, json.loads(response.data)['paginationContext']['nextToken'])
        else:
            return 'Done'
    else:
        logger.debug(response.status);    
        logger.error(f'Failed to get campaign cards list')


def clean_all_campaign_cards(access_token, cards_list):
    for card in cards_list:
        delete_campaign_card(access_token, card['campaignId']);


def delete_campaign_card(access_token, id):
    url = f'https://api.amazonalexa.com/v1/proactive/campaigns/{id}'
    
    logger.debug(url);
    lib3_request = urllib3.PoolManager()
    response = lib3_request.request("DELETE", url, headers={'Content-Type': 'application/json', 'Authorization': access_token})

    if response.status == 202:
        logger.info(f'Deleted campaign card with id: {id}');
    else:
        logger.debug(response.status);    
        logger.error(f'Failed to get campaign card with id: {id}')


def lambda_handler(event, context):
    get_all_campaign_cards(get_access_token(), None);
    
