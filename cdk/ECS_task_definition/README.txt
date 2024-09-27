Before running start_stack.sh:
1) Build Dockerfile and push to your ECR at AWS_ACCOUNT_NUMBER.dkr.ecr.us-west-1.amazonaws.com/my-mssql-tools:latest, make sure to replace AWS_ACCOUNT_NUMBER with your AWS account number.
2) Replace AWS_ACCOUNT_NUMBER and S3_CREDSPEC_LOCATION in CredentialsfetcherADStackCredentialsFetcherTaskDefinitiontemplate.json
3) Use CredentialsfetcherADStackCredentialsFetcherTaskDefinitiontemplate.json to create an ECS task definition EC2 console.
