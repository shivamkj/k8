#!/bin/bash

# Required to Install jq & ggrep: brew install jq & brew install ggrep

# Check environment variables are present
if [[ -z "$SECRET_FILE" || -z "$SOPS_AGE_KEY_FILE" ]]; then
    echo "Must provide required variables in environment" 1>&2
    exit 1
fi

json_file=$SECRET_FILE

sops --decrypt --age $(cat $SOPS_AGE_KEY_FILE | ggrep -oP "public key: \K(.*)") -i $json_file

# Read and parse the JSON file
json_data=$(cat "$json_file")

# Extract secret information from the JSON data
secrets=$(echo "$json_data" | jq -r '.secrets[] | @base64')

# Create secret in specified namespaces
for secret in $secrets; do
    decoded_secret=$(echo "$secret" | base64 --decode)
    name=$(echo "$decoded_secret" | jq -r '.name')
    namespaces=$(echo "$decoded_secret" | jq -r '.namespaces[]?')
    data=$(echo "$decoded_secret" | jq -r '.data')
    
    # Create secret in specified namespaces
    for namespace in $namespaces; do
        # Check if namespace already exists else create it
        if ! kubectl get namespace "$namespace" &>/dev/null; then
            kubectl create namespace "$namespace"
        fi
        
        for key in $(echo "$data" | jq -r 'keys[]'); do
            
            # Check if the secret already exists
            existing_secret=$(kubectl get secret "$name" -n "$namespace" --output=json 2>/dev/null)
            
            if [[ -z "$existing_secret" ]]; then
                # Secret doesn't exist, create it
                value=$(echo "$data" | jq -r ".$key")
                kubectl create secret generic "$name" --from-literal="$key"="$value" -n "$namespace"
            else
                # Secret exists, check if it has changed
                encoded_data=$(echo "$existing_secret" | jq -r ".data.$key")
                existing_data=$(echo "$encoded_data" | base64 --decode)
                passed_data=$(echo "$data" | jq -r ".$key")
                
                if [[ "$existing_data" != "$passed_data" ]]; then
                    # Secret has changed, delete old one and replace it with new one
                    kubectl delete secret $name -n "$namespace" --ignore-not-found
                    kubectl create secret generic "$name" --from-literal="$key"="$passed_data" -n "$namespace"
                else
                    # Secret hasn't changed, do nothing
                    echo "Secret '$name' in namespace '$namespace' already exists and hasn't changed. Skipping..."
                fi
            fi
            
        done
    done
done

sops --encrypt --age $(cat $SOPS_AGE_KEY_FILE | ggrep -oP "public key: \K(.*)") -i $json_file
