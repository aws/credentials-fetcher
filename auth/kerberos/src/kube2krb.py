import json
import yaml
from base64 import b64encode
from yaml import SafeLoader
import sys, getopt
f = open(sys.argv[1], "r")
yaml_string = f.read()
f.close()
python_dict=yaml.load(yaml_string, Loader=SafeLoader)
json_string=json.dumps(python_dict)
json_dict = json.loads(json_string)
f=open(sys.argv[2],"rb")
krb_ticket = f.read()
f.close()
base64_enc_string = b64encode(krb_ticket).decode("utf-8")
json_dict["data"]["password"] = str(base64_enc_string)
json_string=json.dumps(json_dict)
yaml_out = yaml.dump(json_dict)
f = open(sys.argv[1], "w")
f.write(yaml_out)
