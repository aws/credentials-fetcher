import json
import os
import yaml
from base64 import b64encode
from yaml import SafeLoader
import sys, getopt

#  sudo python3 credentials_fetcher_krbsecret_to_kubesecret.py -s secret-1.yaml -k /var/credentials-fetcher/krbdir/434d760fade0559999d6/WebApp01/krb5cc
def main(argv):
    kube_secrets_yaml_file = ''
    krb_ticket_file = ''
    opts, args = getopt.getopt(argv,"hs:k:",["kube_secrets_yaml_file=","krb_ticket_file="])
    for opt, arg in opts:
        if opt == '-h':
            print ('credentials_fetcher_krbsecret_to_kubesecret.py -s <kube_secrets_yaml_file> -k <krb_ticket_file>')
            sys.exit()
        elif opt in ("-s", "--kube_secrets_yaml_file"):
            kube_secrets_yaml_file = arg
        elif opt in ("-k", "--krb_ticket_file"):
            krb_ticket_file = arg
    print('kube secrets file is ', kube_secrets_yaml_file)
    print('krb ticket file is ', krb_ticket_file)
    if not kube_secrets_yaml_file or not krb_ticket_file:
        print("Please run with -h to see usage")
        sys.exit(1)

    f = open(kube_secrets_yaml_file, "r")
    yaml_string = f.read()
    f.close()
    print("The YAML string is:")
    print(yaml_string)
    python_dict=yaml.load(yaml_string, Loader=SafeLoader)
    json_string=json.dumps(python_dict)
    json_dict = json.loads(json_string)
    #f=open("/var/credentials-fetcher/krbdir/434d760fade0559999d6/WebApp01/krb5cc","rb")
    f=open(krb_ticket_file,"rb")
    krb_ticket = f.read()
    f.close()
    base64_enc_string = b64encode(krb_ticket).decode("utf-8")
    #print(base64_enc_string)
    json_dict["data"]["password"] = str(base64_enc_string)
    json_string=json.dumps(json_dict)
    python_dict=json.loads(json_string)
    f=open(kube_secrets_yaml_file,"w")
    yaml.dump(python_dict,f)
    f.close()
    print("secret pod yaml file saved" + kube_secrets_yaml_file)
    #command = "./kubectl apply -f " + yaml_string
    #f = os.popen(command)
    #line = f.readline()
    #status = f.close()
    #if status:
    #       print("exit status = " + str(os.waitstatus_to_exitcode(status)))


if __name__ == "__main__":
    main(sys.argv[1:])
