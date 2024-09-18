#!/bin/sh

echo "Please edit the file to add your AWS account number below"
cdk bootstrap --trust=<Add your AWS account> --cloudformation-execution-policies=arn:aws:iam::aws:policy/AdministratorAccess --verbose && cdk deploy
