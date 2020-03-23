#!/bin/sh

# Author:  Carlos Machado
# Date:    2019-07-31
#
# Author:   DevOps Team La Redoute
# Date: 16.12.2019
#
# Purpose: Initializes

#############
# MAIN CODE #
#############

cacert='/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
bearer_token="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
namespace="$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)"

#vault_port=$(echo "${VAULT_ADDR}" | sed -r 's#^https?://(.+):(\d+)#\2#')

# create gilab policy
##gitlab_policy_name="gitlab"
##vault policy write ${gitlab_policy_name} /policies/${gitlab_policy_name}.hcl
    
# enable appRole auth method, required for gitlab
vault auth enable -description="Application Role Credentials" approle
    
# create gitlab appRole
##gitlab_role=${gitlab_policy_name}
##vault write auth/approle/role/${gitlab_role} \
##    token_ttl=10m \
##    token_max_ttl=15m \
##   period=0 \
##    bind_secret_id=true \
##    policies=default,${gitlab_policy_name}
    
# update gitlab appRole ID to a known value. Eases automation.
##gitlab_role_id="gitlab-approle-id"
##vault write auth/approle/role/${gitlab_role}/role-id role_id=${gitlab_role_id}
    
# generate new secret id
##secret_id_json=$(vault write -f auth/approle/role/${gitlab_role}/secret-id -format=json)
##secret_id=$(echo "${secret_id_json}" | jq -r '.data.secret_id' | base64 | tr -d '\n')

# publish approle secret id as a k8s secret
##gitlab_secret_name="gitlab-vault-approle"
#####k8s_secret_create_cm_secret_id "${namespace}" "${gitlab_secret_name}" "${secret_id}"
    
# tune default secret secrets engine for v2 (versioned secrets)
echo "[INFO] tune default secret secrets engine for v2 (versioned secrets)"
vault secrets enable -path="secret" -version=2 secret

# Enable audit to stdout
echo "[INFO] Enable audit to stdout"
vault audit enable -path="file" -description="STDOUT Audit Device" file file_path="stdout"

# Enable LDAP auth method
echo "[INFO] Enable LDAP auth method"
vault auth enable -description="siege.red LDAP Credentials" ldap

# Enable Kubernetes auth method
echo "[INFO] Enable Kubernetes auth method"
vault auth enable -description="Kubernetes Service Account Credentials" kubernetes

export VAULT_TOKEN=${token}

# inject policies
##echo "[INFO] Injecting policies..."
##for path in $(find /policies -type f -name '*.hcl'); do
##  policy_name=$(basename ${path} .hcl)
##  vault policy write "${policy_name}" "${path}"
##done 

# mapping policies
##echo "[INFO] Mapping policies..."
##/root/scripts/policy-mapping.sh

# configure LDAP
echo "[INFO] Configuring LDAP..."
# load ldap env variables
##source /config/ldap/ldap.conf
vault write auth/ldap/config \
    url="${LDAP_URL}" \
    userdn="${LDAP_USERDN}" \
    groupdn="${LDAP_GROUPDN}" \
    groupfilter="${LDAP_GROUPFILTER}" \
    groupattr="${LDAP_GROUPATTR}" \
    upndomain="${LDAP_UPNDOMAIN}" \
    insecure_tls="${LDAP_INSECURE_TLS}" \
    starttls="${LDAP_STARTTLS}"

# configure Kubernetes auth
echo "[INFO] Configuring Kubernetes..."
vault write auth/kubernetes/config \
    token_reviewer_jwt="${bearer_token}" \
    kubernetes_host="https://kubernetes.default.svc.cluster.local" \
    kubernetes_ca_cert=@${cacert}

# vault_generate_intermediate_ca "pki_int_kafka" "Kafka Intermediate Certificate Authority" "21912h" "87648h"
# vault write pki_int_kafka/roles/kafka-server allowed_domains=streaming allow_subdomains=true max_ttl=1    
echo "[INFO] Done."

#exec /bin/sh -c "trap : TERM INT; (while true; do sleep 1000; done) & wait"