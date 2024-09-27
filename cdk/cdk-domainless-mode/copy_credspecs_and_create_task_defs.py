import boto3
import json

# Open the input file
with open('data.json', 'r') as file:
    # Load the JSON data
    data = json.load(file)

directory_name = data["directory_name"]
netbios_name = data["netbios_name"]
number_of_gmsa_accounts = data["number_of_gmsa_accounts"]
s3_bucket = data["s3_bucket"]
task_definition_template_name = data["task_definition_template_name"]
stack_name = data["stack_name"]

credspec_template = """
{
  "CmsPlugins": ["ActiveDirectory"],
  "DomainJoinConfig": {
    "Sid": "S-1-5-21-2421564706-1737585382-3854682907",
    "MachineAccountName": "GMSA_NAME",
    "Guid": "6a91814c-e151-4fb0-96f0-f517566fc883",
    "DnsTreeName": "DOMAINNAME",
    "DnsName": "DOMAINNAME",
    "NetBiosName": "NETBIOS_NAME"
  },
  "ActiveDirectoryConfig": {
    "GroupManagedServiceAccounts": [
      {
        "Name": "GMSA_NAME",
        "Scope": "DOMAINNAME"
      },
      {
        "Name": "GMSA_NAME",
        "Scope": "NETBIOS_NAME"
      }
    ],
    "HostAccountConfig": {
      "PortableCcgVersion": "1",
      "PluginGUID": "{859E1386-BDB4-49E8-85C7-3070B13920E1}",
      "PluginInput": {
        "CredentialArn": "GMSA_SECRET_ARN"
      }
    }
  }
}
"""

credspec_template = credspec_template.replace("DOMAINNAME", directory_name)
credspec_template = credspec_template.replace("NETBIOS_NAME", netbios_name)

secrets_manager_client = boto3.client('secretsmanager')
secret_id = "aws/directoryservice/" + netbios_name + "/gmsa"
# get secrets manager arn from secret name
print("Secret id = " + secret_id)
gmsa_secret_arn = secrets_manager_client.get_secret_value(SecretId=secret_id)['ARN']
credspec_template = credspec_template.replace("GMSA_SECRET_ARN", gmsa_secret_arn)

for i in range(1, number_of_gmsa_accounts + 1):
    credspec_template.replace("GMSA_NAME", f"GMSA{i}")

aws_profile_name = data["aws_profile_name"]

boto3.setup_default_session(profile_name=aws_profile_name)

# list iam roles with a given name
list_roles = boto3.client('iam').list_roles(MaxItems=1000)
for role in list_roles['Roles']:
    print(role['RoleName'])
for role in list_roles['Roles']:
    role_name = role['RoleName']
    if 'CredentialsFetcher-ECSTaskExecutionRolegMSA' == role_name:
        ecs_task_execution_role_arn = role['Arn']
        break

# list ECS task definitions
ecs_client = boto3.client('ecs')

# task_definition_prefix = 'ecs-task-definition'
# Call the list_task_definitions method with a prefix filter

task_definition_arn = ""
task_definition = ""
response = ecs_client.list_task_definitions()
# Check if any task definitions match the prefix
if 'taskDefinitionArns' in response:
    task_definitions = response['taskDefinitionArns']
    if task_definitions == []:
        print("No task definitions found")
        exit()
    for arn in task_definitions:
        if task_definition_template_name in arn:
            matching_task_definitions = arn
            # Get task definition details
            task_definition = ecs_client.describe_task_definition(taskDefinition=arn)
            task_definition_arn = arn
            break
else:
    print(f"No task definitions found matching '{response}'")
    exit()

# Get ecs cluster
ecs_clusters = ecs_client.list_clusters()
ecs_cluster_arn = ""
ecs_cluster_instance = ""
ecs_cluster_name = "Credentials-fetcher-ecs-load-test"
for cluster_arn in ecs_clusters['clusterArns']:
    cluster_name = cluster_arn.split('/')[1]
    if cluster_name == ecs_cluster_name:
        ecs_cluster_arn = cluster_arn
        # Get instance-id attached running ecs cluster
        ecs_cluster_instance_arn = ecs_client.list_container_instances(cluster=ecs_cluster_arn)['containerInstanceArns'][0]
        break

task_definition_orig = task_definition
print(task_definition)
for i in range(1, number_of_gmsa_accounts + 1):
    task_definition = task_definition_orig
    credspec_template = credspec_template.replace("GMSA_NAME", f"WebApp0{i}")
    credspec = json.loads(credspec_template)
    credspec_str = json.dumps(credspec)
    # copy credspec to S3 folder
    s3_client = boto3.client('s3')
    bucket_location = ""
    bucket_arn = ""
    s3_key = ""
    try:
        # put credspec_str into s3 bucket
        s3_key = f"WebApp0{i}_credspec.json"
        print("Putting object")
        s3_client.put_object(Body=credspec_str, Bucket=s3_bucket, Key=f'WebApp0{i}_credspec.json')
        bucket_location = s3_client.get_bucket_location(Bucket=s3_bucket)
        bucket_arn = f"arn:aws:s3:::{s3_bucket}"
    except Exception as e:
        print(e)
    
    #print(task_definition)
    task_definition = task_definition["taskDefinition"]
    task_definition["compatibilities"].append("FARGATE")

    container_defs = task_definition['containerDefinitions']
    pretty_json = json.dumps(container_defs, indent=4)
    print(pretty_json)
    for container_def in container_defs:
        credspec = container_def['credentialSpecs']
        # Remove entry with key 'credentialspecdomainless'
        credspec_without_key = []
        for d in credspec:
            if 'credentialspecdomainless' not in d:
                credspec_without_key.append(d)
        credspec = credspec_without_key
        print(credspec)
        credspec.append("credentialspecdomainless:" + bucket_arn + "/" + s3_key)
        container_def['credentialSpecs'] = credspec
        attributes = task_definition['requiresAttributes']
        attribute = {}
        attribute["name"] = "ecs.capability.gmsa-domainless"
        attribute["targetId"] = ecs_cluster_arn
        attributes.append(attribute)
        family = task_definition['family'] + "-" + str(i)
        ecs_client.register_task_definition(family=family, 
                                        taskRoleArn=ecs_task_execution_role_arn,
                                        executionRoleArn=ecs_task_execution_role_arn,
                                        networkMode=task_definition['networkMode'],
                                        containerDefinitions=container_defs,
                                        requiresCompatibilities=["EC2", "FARGATE"],
                                        runtimePlatform={'cpuArchitecture': 'X86_64', 'operatingSystemFamily' : 'LINUX'},
                                        cpu=task_definition['cpu'],
                                        memory=task_definition['memory'])
        #print(ecs_cluster_arn)

