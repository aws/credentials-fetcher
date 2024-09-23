#!/usr/bin/env python3
import os

import aws_cdk as cdk

from cdk.cdk_stack import CdkStack
import aws_cdk.aws_ec2 as ec2
import aws_cdk as cdk
import aws_cdk.aws_secretsmanager as secretsmanager

import json

# Open the input file
with open('data.json', 'r') as file:
    # Load the JSON data
    data = json.load(file)

#print(data)

tag = cdk.Tag("Name", "Test Credentials-fetcher in Domainless mode")
aws_region = data["aws_region"]
prefix_list = data["prefix_list"]
domain_admin_password = data["domain_admin_password"]
directory_name = data["directory_name"]
windows_instance_tag = data["windows_instance_tag"]
linux_instance_tag = data["linux_instance_tag"]
key_name = data["key_pair_name"]
number_of_gmsa_accounts = data["number_of_gmsa_accounts"]
empty_s3_bucket = data["s3_bucket"]
app_name = data["stack_name"]
username = data["username"]
password = data["password"]
secret_name = data["secret_name"]
task_definition_template_name = data["task_definition_template_name"]
cluster_name = data["cluster_name"]

app = cdk.App()

cdk_stack = CdkStack(app, app_name)

cdk_stack.init_vpc(prefix_list = prefix_list, key_pair_name=key_name, stack_name=app_name)

cfn_microsoft_AD = cdk_stack.init_DirectoryService(directory_name=directory_name, domain_admin_password=domain_admin_password)

directory_id = cfn_microsoft_AD.ref

cdk_stack.init_route53_endpoint(domain_name = directory_name,
                                vpc = cdk_stack.vpc)

windows_instance = cdk_stack.launch_windows_instance(instance_tag = windows_instance_tag,
                          password = domain_admin_password,
                          domain_name = directory_name,
                          key_name = key_name,
                          number_of_gmsa_accounts = number_of_gmsa_accounts,
                          s3_bucket_name = empty_s3_bucket
                        )

windows_instance.node.add_dependency(cfn_microsoft_AD)

ecs_cluster = cdk_stack.create_ecs_cluster( cluster_name,
                                            instance_tag=linux_instance_tag,
                                            password = domain_admin_password,
                                            domain_name = directory_name,
                                            key_pair=cdk_stack.key_pair,
                                            number_of_gmsa_accounts=number_of_gmsa_accounts,
                                            vpc = cdk_stack.vpc,
                                            security_group=cdk_stack.security_group)
ecs_cluster.node.add_dependency(windows_instance)

task_definition = cdk_stack.create_task_definition(task_definition_template_name=task_definition_template_name)

app.synth()
