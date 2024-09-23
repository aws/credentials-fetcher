import boto3
import json

# Open the input file
with open('data.json', 'r') as file:
    # Load the JSON data
    data = json.load(file)

directory_name = data["directory_name"]
netbios_name = data["netbios_name"]
number_of_gmsa_accounts = data["number_of_gmsa_accounts"]
stack_name = data["stack_name"]
cluster_name = data["cluster_name"]
vpc_name = data["vpc_name"]
task_definition_template_name = data["task_definition_template_name"]


