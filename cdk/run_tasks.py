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

ecs_client = boto3.client('ecs')

# Find VPC of stack_name
ec2_client = boto3.client('ec2')
response = ec2_client.describe_vpcs(
    Filters=[
        {
            'Name': 'tag:Name',
            'Values': [vpc_name]
        }
    ]
)
vpc_id = response['Vpcs'][0]['VpcId']

ec2_client = boto3.client('ec2')

# list of subnets from vpc_id
# Get a list of subnets in the VPC
response = ec2_client.describe_subnets(
    Filters=[
        {
            'Name': 'vpc-id',
            'Values': [vpc_id]
        }
    ]
)
subnet_ids = [subnet['SubnetId'] for subnet in response['Subnets']]

# list of security groups from vpc
# Get a list of security groups in the VPC
response = ec2_client.describe_security_groups(
    Filters=[
        {
            'Name': 'vpc-id',
            'Values': [vpc_id]
        }
    ]
)
security_groups = []
security_group_id = ""
for security_group in response['SecurityGroups']:
    security_group_id = security_group['GroupId']
    security_group_name = security_group['GroupName']
    security_groups.append((security_group_id, security_group_name))

# list all task definitions
task_definitions = ecs_client.list_task_definitions()

for task_definition in task_definitions['taskDefinitionArns']:
    # If task definition matches CredentialsFetcherTaskDefinition
    if task_definition_template_name in task_definition:
        print(task_definition)
        # Run a task with a task definition
        task = ecs_client.run_task(
            cluster=cluster_name,
            taskDefinition=task_definition,
            count=1,
            launchType='EC2',
            networkConfiguration={
                'awsvpcConfiguration': {
                'subnets': subnet_ids,
                'securityGroups': [security_group_id],
            }
            }
        )
        print("Started task " + str(task))
