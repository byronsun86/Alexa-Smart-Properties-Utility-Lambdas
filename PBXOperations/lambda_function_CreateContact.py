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
# 1.Create AddressBook
# 2.Read CSV line by line and create contact from the info within each line (Ex: room name, pbx number)
###########################################################################################

import json
import os
import urllib3
import boto3
from datetime import datetime

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


def generate_address_book_name():
    now = datetime.now()
    return now.strftime("%Y%m%d-%H-%M-%S")


def create_address_book(access_token):
    url = 'https://api.amazonalexa.com/v1/addressBooks'
    
    lib3_request = urllib3.PoolManager()
    post_data = {"name": generate_address_book_name()}
    response = lib3_request.request("POST", url, headers={'Content-Type': 'application/json', 'Authorization': access_token}, body=json.dumps(post_data).encode('utf-8'))

    if response.status == 201:
        return json.loads(response.data)['addressBookId']
    else:
        logger.error(f'Failed to create address book from API: {response.status}')
        raise Exception('Failed to create address book')


def create_contact(addressBookId, name, number, access_token):
    url = f'https://api.amazonalexa.com/v1/addressBooks/{addressBookId}/contacts'
    
    lib3_request = urllib3.PoolManager()
    post_data = {"contact": {"name": name, "phoneNumbers": [{"number": number}]}}
    response = lib3_request.request("POST", url, headers={'Content-Type': 'application/json', 'Authorization': access_token}, body=json.dumps(post_data).encode('utf-8'))

    if response.status == 201:
        return True
    else:
        logger.error(f'Failed to create contact with name and number {name}: {number} with API response: {response.status} and {response.data}')
        raise Exception('Failed to create contact')


def build_address_book_from_csv(addressBookId, access_token):
    file = open("room-extension.csv")
    lines = file.readlines()
    for line in lines:
        list = line.split(',')
        name = list[0].rstrip().upper()
        number = list[1].rstrip()
        if create_contact(addressBookId, name, number, access_token):
            logger.info(f'creating contact name: {name}, number: {number} to address book id: {addressBookId}')


def lambda_handler(event, context):
    try:
        build_address_book_from_csv(create_address_book(get_access_token()))
    except Exception as e:
        logger.error(e)
    


