#!/usr/sbin python3

#
# This code is intended for invocation from the credentials-fetcher daemon
# (https://github.com/aws/credentials-fetcher)
#
# The input is a kerberos secret which is converted to a kubernetes secret
# Mounting a kubernetes secret into a pod is done using kubernetes (https://kubernetes.io/docs/concepts/configuration/secret/)
# TBD: Optionally, apply the kube secret during gmsa renewal so that the pod gets
# the updated secret seamlessly
# See yaml examples of secret and pod in the credentials-fetcher code-base.
#
# Example invocation:
#  sudo python3 credentials_fetcher_krbsecret_to_kubesecret.py -s secret-1.yaml -k /var/credentials-fetcher/krbdir/434d760fade0559999d6/WebApp01/krb5cc
#  Note: In above example, secret-1.yaml is modified with a new base64 secret.
#

import json
import os
import subprocess
import yaml
from base64 import b64encode
from yaml import SafeLoader
import sys, getopt
import syslog
import stat

def check_kubectl_permissions():
  kubectl_location = subprocess.run(["which", "kubectl"], capture_output=True)
  mode = os.stat(kubectl_location.stdout.decode().strip()).st_mode
  if mode & stat.S_IWOTH:
    syslog("***ERROR***: kubectl is writeable by non-owner")
    sys.exit(1)

def main(argv):

    kube_secrets_yaml_file = ''
    krb_ticket_file = ''
    opts, args = getopt.getopt(argv,"hs:k:",["kube_secrets_yaml_file=","krb_ticket_file="])

    for opt, arg in opts:
        if opt == '-h':
            syslog.syslog ('credentials_fetcher_krbsecret_to_kubesecret.py -s <kube_secrets_yaml_file> -k <krb_ticket_file>')
            sys.exit(1)
        elif opt in ("-s", "--kube_secrets_yaml_file"):
            kube_secrets_yaml_file = arg
        elif opt in ("-k", "--krb_ticket_file"):
            krb_ticket_file = arg

    msg = 'kube secrets file is '+ kube_secrets_yaml_file
    syslog.syslog(msg)
    msg = 'krb ticket file is ' + krb_ticket_file
    syslog.syslog(msg)
    if not kube_secrets_yaml_file or not krb_ticket_file:
        syslog.syslog("Please run with -h to see usage")
        sys.exit(1)

    try:
       f = open(kube_secrets_yaml_file, "r")
       yaml_string = f.read()
       f.close()

       python_dict = yaml.load(yaml_string, Loader=SafeLoader)
       json_string = json.dumps(python_dict)
       #syslog.syslog("json string = ")
       #syslog.syslog(json_string)
       json_dict = json.loads(json_string)
       #f=open("/var/credentials-fetcher/krbdir/434d760fade0559999d6/WebApp01/krb5cc","rb")

       f = open(krb_ticket_file,"rb")
       krb_ticket = f.read()
       f.close()

       base64_enc_string = b64encode(krb_ticket).decode("utf-8")
       #syslog.syslog(base64_enc_string)
       json_dict["data"]["password"] = str(base64_enc_string)
       json_string = json.dumps(json_dict)
       python_dict = json.loads(json_string)
       f = open(kube_secrets_yaml_file, "w")
       yaml.dump(python_dict, f)
       f.close()
       msg = "secret pod yaml file saved as " + kube_secrets_yaml_file
       syslog.syslog(msg)
    except Exception as err:
       syslog("***ERROR***: Unexpected {err=}, {type(err)=}")
       sys.exit(1)

    check_kubectl_permissions()

    args = ["kubectl", "--kubeconfig", "/root/.kube/config", "get", "nodes"]
    completion = subprocess.run(args, capture_output=True)
    syslog.syslog(str(completion))

    args = ["kubectl", "--kubeconfig", "/root/.kube/config", "apply", "-f", kube_secrets_yaml_file]
    completion = subprocess.run(args, capture_output=True)
    syslog.syslog(str(completion))

if __name__ == "__main__":
    main(sys.argv[1:])
    # Best effort
    sys.exit(1)
