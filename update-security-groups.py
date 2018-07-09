'''
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.


Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at


    http://aws.amazon.com/apache2.0/


or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

'''
To use this function, you must have a security group with the following two tags:
    - lambda-managed-cloudfront-ips-enabled     =>  truthy or falsey value
    - lambda-managed-cloudfront-ips-port        =>  port number

A third tag, named 'lambda-managed-cloudfront-ips-hash', is dynamically added that contains the hash of the most recent IP list.
This saves us from having the query every security group for its IP list.

This function will update the security groups to contain the CloudFront IP list for a specific port number.

Security groups may only hold up to 50 rules, so you may need two security groups if the IP list
gets too large. This function will automatically spread the IPs across security groups that
share the same port number.


TODO: if the number of IPs cannot fit into the security groups, print an error.
TODO: spread the IP list

'''

import boto3
import hashlib
import json
import requests

REGION = "ap-southeast-2"
# Name of the service, as seen in the ip-groups.json file, to extract information for
SERVICE = "CLOUDFRONT"
# Ports your application uses that need inbound permissions from the service for
# Tags which identify the security groups you want to update. The key is the hash of the last response.
SECURITY_GROUP_TAG_ENABLED = 'lambda-managed-cloudfront-ips-enabled'
SECURITY_GROUP_TAG_PORT = 'lambda-managed-cloudfront-ips-port'
SECURITY_GROUP_TAG_HASH = 'lambda-managed-cloudfront-ips-hash'
TRUTHY_VALUES = [1, 'true', 'True', True]
SECURITY_GROUP_MAXIMUM_RULES = 50

def lambda_handler(event, context):
    ##print("Received event: " + json.dumps(event, indent=2))
    ##message = json.loads(event['Records'][0]['Sns']['Message'])

    # Load the ip ranges from the url
    url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
    ip_ranges = json.loads(get_ip_groups_json(url))

    # extract the IP ranges for the service
    ranges = get_ranges_for_service(ip_ranges, SERVICE)

    # update the security groups
    result = update_security_groups(ranges)

    return result

def get_ip_groups_json(url):
    print("Fetching IP list from " + url)

    response = requests.get(url)
    ip_json = response.content

    return ip_json

def get_ranges_for_service(ranges, service):
    service_ranges = list()
    for prefix in ranges['prefixes']:
        if prefix['service'] == service:
            service_ranges.append(prefix['ip_prefix'])

    print ('Found', len(service_ranges), 'CloudFront IPs.')
    return service_ranges

def calculate_md5_hash(text):
    m = hashlib.md5()
    m.update(text.encode('utf-8'))
    md5_hash = m.hexdigest()
    print("Hash of IP ranges is", md5_hash)
    return md5_hash

def update_security_groups(new_ranges):
    client = boto3.client('ec2', region_name=REGION)

    md5_hash = calculate_md5_hash(str(new_ranges))
    groups = get_security_groups_for_update(client, md5_hash)

    print ('Found ' + str(len(groups)) + ' security groups to update.')

    result = list()
    groups_updated = 0

    # Update IPs
    for group, port in groups:
        if update_security_group(client, group, new_ranges, port, md5_hash):
            groups_updated += 1
            result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(groups_updated) + ' security groups.')

    return result

def is_truthy_value(value):
    return str(value).lower() in ['1', 'true']

def extract_keys_and_values(lst):
    """Convert a list of dicts like:
        [{'Key':'Name', 'Value':'Apple'}]
    into a single dict:
        {'Name':'Apple'}
    """
    new_dict = {}

    for item in lst:
        key = item['Key']
        value = item['Value']
        new_dict[key] = value

    return new_dict

def get_security_groups_for_update(client, md5_hash):
    filters = list();
    security_groups_to_update = []
    filters = [{ 'Name': "tag-key", 'Values': [ SECURITY_GROUP_TAG_ENABLED ] }]

    response = client.describe_security_groups(Filters=filters)
    groups = response['SecurityGroups']

    # Find security groups with the tag
    for group in groups:
        tags = extract_keys_and_values(group['Tags'])

        # Check the "enabled" tag
        enabled = tags[SECURITY_GROUP_TAG_ENABLED]
        if not is_truthy_value(enabled):
            print ("%s is tagged but does not have a truthy value. Skipping." % (group['GroupId']))
            continue

        # Check the "port" tag
        if SECURITY_GROUP_TAG_PORT in tags:
            port = tags[SECURITY_GROUP_TAG_PORT]
            if not port.isnumeric():
                print ("%s is tagged with a port (%s) that is non-numeric. Skipping." % (group['GroupId'], port))
                continue
            port = int(port)
        else:
            print ("%s not does not have the 'lambda-managed-cloudfront-ips-port' tag. Skipping.")
            continue

        # Check the "hash" tag. If it doesn't exist, create it. If it's outdated, update the IP list.
        if SECURITY_GROUP_TAG_HASH in tags:
            _hash = tags[SECURITY_GROUP_TAG_HASH]
            if _hash != md5_hash:
                print ("%s has a mismatching hash (%s)." % (group['GroupId'], _hash))
                security_groups_to_update.append((group, port))
            else:
                print ("%s has the latest hash. Skipping." % (group['GroupId']))
        else:
            # Create the tag.
            security_groups_to_update.append((group, port))

    return security_groups_to_update

def update_security_group(client, group, new_ranges, port, md5_hash):
    added = 0
    removed = 0

    if len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            old_prefixes = []
            to_revoke = []
            to_add = []

            if permission['FromPort'] != port or permission['ToPort'] != port:
                # Remove all the IPs with a mismatching port.
                for ip in permission['IpRanges']:
                    cidr = ip['CidrIp']
                    print("%s (%s): Revoking %s:%s as the port does not match the tag." % (group['GroupId'], group['GroupName'], cidr, permission['FromPort']))
                    to_revoke.append(ip)

                    if cidr in new_ranges:
                        to_add.append({'CidrIp': cidr})
                        print("%s (%s): Adding %s:%s" % (group['GroupId'], group['GroupName'], cidr, port))

                removed += revoke_permissions(client, group, permission, to_revoke)
                added += add_permissions(client, group, permission, to_add, port)
            else:
                # Check if the IP is correct.
                for ip in permission['IpRanges']:
                    cidr = ip['CidrIp']
                    old_prefixes.append(cidr)

                    if cidr not in new_ranges:
                        to_revoke.append(ip)
                        print("%s (%s): Revoking %s:%s" % (group['GroupId'], group['GroupName'], cidr, port))

                for ip in new_ranges:
                    if ip not in old_prefixes:
                        to_add.append({'CidrIp': ip})
                        print("%s (%s): Adding %s:%s" % (group['GroupId'], group['GroupName'], ip, port))

                removed += revoke_permissions(client, group, permission, to_revoke)
                added += add_permissions(client, group, permission, to_add, port)

    else:
        to_add = list()
        for ip in new_ranges:
            to_add.append({'CidrIp': ip})
            print("%s (%s): Adding %s:%s" % (group['GroupId'], group['GroupName'], ip, port))

        permission = {
            'ToPort': port,
            'FromPort': port,
            'IpProtocol': 'tcp'
        }
        added += add_permissions(client, group, permission, to_add, port)

    # Update the hash
    tags = {
        'Key': SECURITY_GROUP_TAG_HASH,
        'Value': md5_hash
    }

    client.create_tags(Resources=[group['GroupId']], Tags=[tags])
    print("%s (%s): Added %s, Revoked %s." % (group['GroupId'], group['GroupName'], str(added), str(removed)))
    return (added > 0 or removed > 0)

def revoke_permissions(client, group, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }

        client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)

def add_permissions(client, group, permission, to_add, port):
    if len(to_add) > 0:
        add_params = {
            'ToPort': port,
            'FromPort': port,
            'IpRanges': to_add,
            'IpProtocol': permission['IpProtocol']
        }
        client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])

    return len(to_add)


'''
Sample Event From SNS:

{
  "Records": [
    {
      "EventVersion": "1.0",
      "EventSubscriptionArn": "arn:aws:sns:EXAMPLE",
      "EventSource": "aws:sns",
      "Sns": {
        "SignatureVersion": "1",
        "Timestamp": "1970-01-01T00:00:00.000Z",
        "Signature": "EXAMPLE",
        "SigningCertUrl": "EXAMPLE",
        "MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
        "Message": "{\"create-time\": \"yyyy-mm-ddThh:mm:ss+00:00\", \"synctoken\": \"0123456789\", \"md5\": \"45be1ba64fe83acb7ef247bccbc45704\", \"url\": \"https://ip-ranges.amazonaws.com/ip-ranges.json\"}",
        "Type": "Notification",
        "UnsubscribeUrl": "EXAMPLE",
        "TopicArn": "arn:aws:sns:EXAMPLE",
        "Subject": "TestInvoke"
      }
    }
  ]
}

'''

lambda_handler(None, None)