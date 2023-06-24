import base64
import json
import os
import re
import subprocess
import sys


def create_secret(secrets, namespace):
    command = ["kubectl", "create", "secret", "generic", secrets["name"], "-n", namespace]
    secret_type = secrets["type"] if "type" in secret else "Opaque"
    command.append("--type={}".format(secret_type))
    for key, value in secrets["data"].items():
        command.append("--from-literal={0}={1}".format(key, value))
    subprocess.run(command)


# Check environment variables are present
if "SECRET_FILE" not in os.environ or "SOPS_AGE_KEY_FILE" not in os.environ or "KUBECONFIG" not in os.environ:
    print("Must provide required variables in environment", file=sys.stderr)
    exit(1)

secret_file = os.environ["SECRET_FILE"]
sops_age_key_file = os.environ["SOPS_AGE_KEY_FILE"]

# parse the decryption key
pattern = r"^# public key:\s*([a-zA-Z0-9]+)$"
decryption_key = ""
with open(sops_age_key_file, "r") as reader:
    content = reader.readlines()[1]
    match = re.search(pattern, content)
    decryption_key = match.group(1)
sops_output = subprocess.check_output(["sops", "--decrypt", "--age", decryption_key, secret_file])


# Read and parse the JSON file
json_data = sops_output.decode("utf-8")
secrets = json.loads(json_data)["secrets"]

# Create secret in specified namespaces
for secret in secrets:
    name = secret["name"]
    namespaces = secret.get("namespaces", [])
    passed_data = secret["data"]

    # Create secret in specified namespaces
    for namespace in namespaces:
        # Check if namespace already exists else create it
        get_namespace = subprocess.call(
            ["kubectl", "get", "namespace", namespace],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        namespace_exists = get_namespace == 0

        if not namespace_exists:
            subprocess.run(["kubectl", "create", "namespace", namespace])

        # If secret doesn't exits create it
        existing_secret = subprocess.run(
            ["kubectl", "get", "secret", name, "-n", namespace, "--output=json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if existing_secret.returncode != 0:
            create_secret(secret, namespace)
            continue

        # If secrets already exits then compare, delete previous one and replace with
        #  new one if changed else do nothing decode data
        existing_data = json.loads(existing_secret.stdout.decode("utf-8"))["data"]
        decoded_data = {}
        for key, value in existing_data.items():
            decoded_data[key] = base64.b64decode(value).decode("utf-8")
        existing_decoded_data = decoded_data

        if existing_decoded_data == passed_data:
            print("Secret '{0}' in namespace '{1}' already exists & hasn't changed.".format(name, namespace))
        else:
            # Secret has changed, delete old one and replace it with new one
            subprocess.run(["kubectl", "delete", "secret", name, "-n", namespace, "--ignore-not-found"])
            create_secret(secret, namespace)
