AWS_ACCOUNT_NUMBER=
REGION=

docker build -t mssql-tools .

ECR_LOGIN="$AWS_ACCOUNT_NUMBER".dkr.ecr."$REGION".amazonaws.com
aws ecr get-login-password --region us-west-1 | docker login --username AWS --password-stdin $ECR_LOCATION

TAG=$(docker images | grep "^mssql-tools" | awk '{print $3}')

ECR_LOCATION="$AWS_ACCOUNT_NUMBER".dkr.ecr."$REGION".amazonaws.com/my-mssql-tools:latest
docker tag "$TAG" "$ECR_LOCATION"
docker push "$ECR_LOCATION"
