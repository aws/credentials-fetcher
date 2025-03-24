## Overview
CDK automation to run Linux gMSA in ECS with EC2 instance in non domain-joined mode.

#### This CDK does the following:
- Create directory in Directory Service (Active Directory)
- Launch Windows instance, domain-join it with Active Directory and create gMSA accounts
- Create ECS cluster
- Launch ECS-optimized Linux instance and attach to ECS cluster
- Run ECS tasks in the ECS-optimized Linux instances using gMSA in non domain-joined mode.

##### Disclaimer: This CDK and scripts are only for test, please modify as needed.

### Setup

Create the following environment variables: 
1. AWS_REGION
2. S3_PREFIX
3. KEY_PAIR_NAME
4. PREFIX_LIST

- Please take a look at data.json for default values.
- If you're testing a new RPM, upload it in the S3 bucket.
- Ensure you have docker running in the background.

1. Update data.json, and make sure there are no values with "xxxxxxxx"

2. `default` AWS profile with administrator access is needed, a separate/burner AWS account would suffice.

3. Create a virtual environment 
```
# Go to cdk directory

$ cd cdk/

# To manually create a virtualenv on MacOS and Linux:

$ python3 -m venv .venv

# After the init process completes and the virtualenv is created, you can use the following step to activate your virtualenv.

$ source .venv/bin/activate

Once the virtualenv is activated, you can install the required dependencies.

$ cd cdk-domainless-mode
$ pip install -r requirements.txt

Install AWS cdk

$ brew install aws-cdk
```

4. Run start_stack.sh (this is a bash script) to create a CloudFormation stack.
   
   4.1 Update start_stack.sh with your aws account number

   4.2 This creates Managed Active Directory, launches Windows instance and domain-joins it and creates the gMSA accounts, launches an ECS-optimized Linux instance, creates a new ECS cluster and attaches it to ECS cluster.
    ```
    $ cd tests
    (.venv) tests % ./start_stack.sh
        [10:29:46] CDK toolkit version: 2.156.0 (build 2966832)
        [10:29:46] Command line arguments: {
        _: [ 'bootstrap' ],
    ```
   
5. Run End-To-End SQL test with Credentials Fetcher ECS Domainless Setup
   ```
      (.venv) tests % python3 run_e2e_test.py
   ```
6. Done! If everything worked as expected, you should see an output like this in the terminal:
    ```
            EmpID EmpName Designation DepartmentJoiningDate
    ----------- -------------------------------------------------- -------------------------------------------------- -------------------------------------------------------------------------
    1 CHIN YEN LAB ASSISTANT LAB2022-03-05 03:57:09.967
    2 MIKE PEARL SENIOR ACCOUNTANT ACCOUNTS2022-03-05 03:57:09.967
    3 GREEN FIELD ACCOUNTANT ACCOUNTS2022-03-05 03:57:09.967
    4 DEWANE PAUL PROGRAMMER IT2022-03-05 03:57:09.967
    5 MATTS SR. PROGRAMMER IT2022-03-05 03:57:09.967
    6 PLANK OTO ACCOUNTANT ACCOUNTS2022-03-05 03:57:09.967

    (6 rows affected)
    ```



