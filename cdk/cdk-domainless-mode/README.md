What this CDK does:
CDK automation to run Linux gMSA in ECS with EC2 instance in domainless mode . This CDK can be used to test RPMs for AL2023.

This CDK does the following:
Creates directory in Directory Service (Active Directory)
Launch Windows instance, domain-join with Active Directory and create gMSA accounts
Create ECS cluster
Launch ECS-optimized Linux instance and attaches to ECS cluster
Runs a couple of tasks in the ECS-optimized Linux instance using gMSA in domainless mode.

Disclaimer
This CDK and scripts are only for test, please modify as needed.

Pre-requisites
Please take a look at data.json for default values.
1) Create secret in Secrets Manager as per https://docs.aws.amazon.com/AmazonECS/latest/developerguide/linux-gmsa.html#linux-gmsa-setup with the following values:
   This is the same secret in data.json.
   ```
    Secret key  Secret value
    username    standarduser01
    password    p@ssw0rd
    domainName  activedirectory1.com
    ```
2) 'default' AWS profile with administrator access is needed, a separate/burner AWS account would suffice.

Steps to run tasks in ECS with Credentials-fetcher.

3) Create a virtual env
        Go to cdk directory

        ```
        $ cd cdk/
        ```
        To manually create a virtualenv on MacOS and Linux:

        ```
        $ python3 -m venv .venv
        ```

        After the init process completes and the virtualenv is created, you can use the following
        step to activate your virtualenv.

        ```
        $ source .venv/bin/activate
        ```

        Once the virtualenv is activated, you can install the required dependencies.

        ```
        $ pip install -r requirements.txt
        ```

        Install AWS cdk

        ```
        $ brew install aws-cdk
        ```

5) Run start_stack.sh (this is a bash script) to create a CloudFormation stack
   2.1) Update start_stack.sh with your aws account number

   2.2) This creates Managed Active Directory, launches Windows instance and domain-joins it and creates the gMSA accounts, launches an ECS-optimized Linux instance, creates a new ECS cluster and attaches it to ECS cluster.
    ```
    (.venv) cdk % ./start_stack.sh
        [10:29:46] CDK toolkit version: 2.156.0 (build 2966832)
        [10:29:46] Command line arguments: {
        _: [ 'bootstrap' ],
    ```

7) Run copy_credspecs_and_create_task_defs.py to create and copy credspecs to S3 bucket and also to register ECS task definitions.
    ```
     (.venv) cdk % python3 copy_credspecs_and_create_task_defs.py
    ```

8) After CloudFormation stack is complete, launch tasks using run_tasks.py. (You can install a test RPM into the ECS intance here, if you like)
    ```
        (.venv) samiull@6cb1339dd38d cdk % python3 run_tasks.py
    ```
9) Done: You can see the tasks in EC2 Console


