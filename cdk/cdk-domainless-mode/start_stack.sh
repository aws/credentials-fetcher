#!/bin/sh

echo "Please edit the file to add your AWS account number below"
cdk bootstrap aws://XXXXXXXXXXXX/us-west-1 --trust=XXXXXXXXXXXX --cloudformation-execution-policies=arn:aws:iam::aws:policy/AdministratorAccess --verbose && cdk synth && cdk deploy
