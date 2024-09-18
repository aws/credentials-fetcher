#!/bin/sh

echo "Please edit the file to add your AWS account number below"
cdk bootstrap aws://<Add your AWS account number here>/us-west-1 --trust=<Add your AWS account number here> --cloudformation-execution-policies=arn:aws:iam::aws:policy/AdministratorAccess --verbose && cdk synth && cdk deploy
