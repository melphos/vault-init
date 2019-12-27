#!/bin/sh

# Author:  Carlos Machado
# Date:    2018-12-26
# Purpose: Initializes or unseals vault.

CURL_VERBOSE=""

#############
# FUNCTIONS #
#############

vault_audit_enable_file() {
    root_token="$1"
    path="$2"
    file_path="$3"
    description="$4"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X PUT -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/sys/audit/${path} 2> /dev/null <<-EOF
        {
            "type": "file",
            "description": "${description}",
            "options": {
                "file_path": "${file_path}"
            }
        }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_auth_enable() {
    root_token="$1"
    auth="$2"
    description="$3"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/sys/auth/${auth} 2> /dev/null <<-EOF
        {
            "type": "${auth}",
            "description": "${description}"
        }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_auth_approle_create_certmanager() {
    root_token="$1"
    role="cert-manager"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/auth/approle/role/${role} 2> /dev/null <<-EOF
        {
            "token_ttl": "10m",
            "token_max_ttl": "15m",
            "policies": [
                "default", "cert-manager"
            ],
            "period": "0",
            "bind_secret_id": true
        }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_auth_approle_role_id() {
    root_token="$1"
    role="$2"
    role_id="$3"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/auth/approle/role/${role}/role-id 2> /dev/null <<-EOF
        { "role_id": "${role_id}" }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_auth_approle_create_secret() {
    root_token="$1"
    role="$2"
    secret_id_json=''

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/auth/approle/role/${role}/secret-id 2> /dev/null <<-EOF
        {}
EOF
        )
        secret_id_json=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
    echo "${secret_id_json}"
}

vault_auth_kubernetes_config() {
    root_token="$1"
    token_reviewer_jwt="$2"
    kubernetes_host="$3"
    kubernetes_ca_cert_file="$4"

    kubernetes_ca_cert=$(awk '{printf "%s\\n", $0}' ${kubernetes_ca_cert_file})
    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/auth/kubernetes/config 2> /dev/null <<-EOF
        {
            "kubernetes_host": "${kubernetes_host}",
            "kubernetes_ca_cert": "${kubernetes_ca_cert}",
            "token_reviewer_jwt": "${token_reviewer_jwt}"
        }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_auth_ldap_config() {
    root_token="$1"
    ldap_conf_path="$2"

    source ${ldap_conf_path}
    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/auth/ldap/config 2> /dev/null <<-EOF
        {
            "url": "${LDAP_URL}",
            "starttls": ${LDAP_STARTTLS},
            "insecure_tls": ${LDAP_INSECURE_TLS},
            "binddn": "${LDAP_BINDDN}",
            "bindpass": "${LDAP_BINDPASS}",
            "userdn": "${LDAP_USERDN}",
            "userattr": "${LDAP_USERATTR}",
            "groupdn": "${LDAP_GROUPDN}",
            "groupfilter": "${LDAP_GROUPFILTER}",
            "groupattr": "${LDAP_GROUPATTR}",
            "upndomain": "${LDAP_UPNDOMAIN}"
        }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_init_status() {
    status_json=''

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" ${VAULT_ADDR}/v1/sys/init 2> /dev/null)
        status_json=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
    echo "${status_json}"
}

vault_policy_create() {
    root_token="$1"
    policy_name="$2"
    policy="$3"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X PUT -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/sys/policies/acl/${policy_name} 2> /dev/null <<-EOF
        { "policy": "${policy}" }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_secret_enable_pki() {
    root_token="$1"
    secret_path="$2"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/sys/mounts/${secret_path} 2> /dev/null <<-EOF
        {
            "type": "pki",
            "config": {
                "default_lease_ttl": "43824h",
                "max_lease_ttl": "175296h"
            }
        }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_secret_pki_config_ca() {
    root_token="$1"
    secret_path="$2"
    pem="$3"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/${secret_path}/config/ca 2> /dev/null <<-EOF
        { "pem_bundle": "${pem}" }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_secret_pki_config_urls() {
    root_token="$1"
    secret_path="$2"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/${secret_path}/config/urls 2> /dev/null <<-EOF
        {
            "issuing_certificates": "${VAULT_API_ADDR}/v1/${secret_path}/ca",
            "crl_distribution_points": "${VAULT_API_ADDR}/v1/${secret_path}/crl"
        }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_secret_pki_create_role() {
    root_token="$1"
    path="$2"
    role="$3"
    allowed="$4"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/${path}/roles/${role} 2> /dev/null <<-EOF
        {
            "organization": "LaRedoute",
            "ou": "ITSQD",
            "allowed_domains": "${allowed}",
            "allow_bare_domains": true,
            "allow_subdomains": true,
            "max_ttl": "43824h"
        }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_secret_kv_tune_v2() {
    root_token="$1"
    secret="$2"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X POST -d @- -H "X-Vault-Token: ${root_token}" ${VAULT_ADDR}/v1/sys/mounts/${secret}/tune 2> /dev/null <<-EOF
        {
            "options": {
                "version": "2"
            }
        }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_operator_init() {
    secret_shares="$1"
    secret_threshold="$2"
    init_json=''

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X PUT -d @- ${VAULT_ADDR}/v1/sys/init 2> /dev/null <<-EOF
        { "secret_shares": ${secret_shares}, "secret_threshold": ${secret_threshold} }
EOF
        )
        init_json=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
    echo "${init_json}"
}

vault_operator_unseal() {
    key="$1"

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" -X PUT -d @- ${VAULT_ADDR}/v1/sys/unseal 2> /dev/null <<-EOF
            { "key": "${key}" }
EOF
        )
        body=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
}

vault_seal_status() {
    status_json=''

    while true; do
        response=$(curl ${CURL_VERBOSE} --cacert "${VAULT_CACERT}" --write-out "HTTP_STATUS:%{http_code}" ${VAULT_ADDR}/v1/sys/seal-status 2> /dev/null)
        status_json=$(echo "${response}" | sed -e 's/HTTP_STATUS\:.*//g')
        status=$(echo "${response}" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')
        [ $status -ge 400 ] || break
        sleep 1
    done
    echo "${status_json}"
}

#############
# MAIN CODE #
#############

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 [allowed_domains],..." >&2
    exit 1
fi
allowed_domains="$1"

root_ca_key=$(awk '{printf "%s\\n", $0}' /root/rootca/tls.key)
root_ca_crt=$(awk '{printf "%s\\n", $0}' /root/rootca/tls.crt)
int_ca_key=$(awk '{printf "%s\\n", $0}' /root/intca/tls.key)
int_ca_crt=$(awk '{printf "%s\\n", $0}' /root/intca/tls.crt)
root_pem="${root_ca_key}${root_ca_crt}"
int_pem="${int_ca_key}${int_ca_crt}${root_ca_crt}"

unseal_key1=''
unseal_key2=''
unseal_key3=''
unseal_key4=''
unseal_key5=''
root_token=''

cacert='/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
bearer_token="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
namespace="$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)"

vault_port=$(echo "${VAULT_ADDR}" | sed -r 's#^https?://(.+):(\d+)#\2#')
# wait for consul to start
until nc -z consul-vault-backend 8300; do
  sleep 1
done 
# wait for vault to start
until netstat -ntl | grep LISTEN | grep ${vault_port}; do 
    sleep 1
done
# get vault init status
echo "[INFO] Getting Vault init status..."
status_json=$(vault_init_status)
vault_init=$(echo "${status_json}" | jq '.initialized')
echo "[INFO] Initialized = ${vault_init}..."
if [ "${vault_init}" = 'false' ]; then
    echo "[INFO] Initializing Vault..."
    init_json=$(vault_operator_init 5 3)

    vault_init='true'
    echo "[INFO] Unsealling Vault..."
    unseal_key1=$(echo "${init_json}" | jq -r '.keys[0]')
    unseal_key2=$(echo "${init_json}" | jq -r '.keys[1]')
    unseal_key3=$(echo "${init_json}" | jq -r '.keys[2]')
    unseal_key4=$(echo "${init_json}" | jq -r '.keys[3]')
    unseal_key5=$(echo "${init_json}" | jq -r '.keys[4]')
    root_token=$(echo "${init_json}" | jq -r '.root_token')
    for k in "${unseal_key1}" "${unseal_key2}" "${unseal_key3}"; do
        vault_operator_unseal "$k"
    done
    # save unseal keys to a k8s secret
    echo "[INFO] Creating 'vault-unseal-keys' secret for unseal keys..."
    curl ${CURL_VERBOSE} -X POST -d @- --cacert "${cacert}" \
    -H "Authorization: Bearer ${bearer_token}" \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' https://kubernetes.default/api/v1/namespaces/${namespace}/secrets 2> /dev/null <<-EOF
    {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {
            "name": "vault-unseal-keys"
        },
        "stringData": {
            "key1": "${unseal_key1}",
            "key2": "${unseal_key2}",
            "key3": "${unseal_key3}",
            "key4": "${unseal_key4}",
            "key5": "${unseal_key5}"
        },
        "type": "Opaque"
    }
EOF
    # also save root token to a k8s secret
    echo "[INFO] Creating 'vault-root-token' secret for root token..."
    curl ${CURL_VERBOSE} -X POST -d @- --cacert "${cacert}" \
    -H "Authorization: Bearer ${bearer_token}" \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' https://kubernetes.default/api/v1/namespaces/${namespace}/secrets 2> /dev/null <<-EOF
    {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {
            "name": "vault-root-token"
        },
        "stringData": {
            "value": "${root_token}"
        },
        "type": "Opaque"
    }
EOF
    # enable Vault PKI
    vault_secret_enable_pki "${root_token}" "pki"

    # inject Vault Root CA certificates
    vault_secret_pki_config_ca "${root_token}" "pki" "${root_pem}"
    
    # configure CA and CRL URLs
    vault_secret_pki_config_urls "${root_token}" "pki"
    
    # enable Vault intermediate PKI
    vault_secret_enable_pki "${root_token}" "pki_int"

    # inject Vault Intermediate CA certificates
    vault_secret_pki_config_ca "${root_token}" "pki_int" "${int_pem}"

    # configure CA and CRL URLs
    vault_secret_pki_config_urls "${root_token}" "pki_int"

    # if all went well, by now root and intermediate CA private certificates can be removed (cleared) from k8s secrets.
    #
    #
    # Setup for cert-manager.
    # create issuer role
    vault_secret_pki_create_role "${root_token}" "pki_int" "cluster-siege-red" "${allowed_domains}"
    
    # create cert-manager policy
    cat > cm_policy.hcl <<-EOF
    path "pki_int/*" {
        capabilities = ["create", "read", "update", "delete", "list", "sudo"]
    }
EOF
    cm_policy=$(base64 cm_policy.hcl | tr -d '\n')
    vault_policy_create "${root_token}" "cert-manager" "${cm_policy}"
    
    # enable appRole auth method
    vault_auth_enable "${root_token}" "approle" "Application Role Credentials"
    
    # create cert-manager appRole
    vault_auth_approle_create_certmanager "${root_token}"
    
    # update cert-manager appRole ID to a known value. Eases automation.
    vault_auth_approle_role_id "${root_token}" "cert-manager" "cert-manager-approle-id"
    
    # generate new secret id
    vault_auth_approle_create_secret "${root_token}" "cert-manager"
    secret_id=$(echo "${secret_id_json}" | jq -r '.data.secret_id' | base64 | tr -d '\n')

    # publish approle secret id as a k8s secret
    curl ${CURL_VERBOSE} -X POST -d @- --cacert "${cacert}" \
    -H "Authorization: Bearer ${bearer_token}" \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' https://kubernetes.default/api/v1/namespaces/${namespace}/secrets 2> /dev/null <<-EOF
    {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {
            "name": "cert-manager-vault-approle"
        },
        "data": {
            "secretId": "${secret_id}"
        },
        "type": "Opaque"
    }
EOF
    # Create a cert-manager ClusterIssuer for Vault
    ca_bundle=$(base64 "${VAULT_CACERT}" | tr -d '\n')
    curl ${CURL_VERBOSE} -X POST -d @- --cacert "${cacert}" \
    -H "Authorization: Bearer ${bearer_token}" \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' https://kubernetes.default/apis/certmanager.k8s.io/v1alpha1/clusterissuers <<-EOF
    {
        "kind": "ClusterIssuer",
        "apiVersion": "certmanager.k8s.io/v1alpha1",
        "metadata": {
            "name": "vault-issuer"
        },
        "spec": {
            "vault": {
                "caBundle": "${ca_bundle}",
                "path": "pki_int/sign/cluster-siege-red",
                "server": "${VAULT_API_ADDR}",
                "auth": {
                    "appRole": {
                        "path": "approle",
                        "roleId": "cert-manager-approle-id",
                        "secretRef": {
                            "name": "cert-manager-vault-approle",
                            "key": "secretId"
                        }
                    }
                }
            }
        }
    }
EOF
    #
    #
    # tune default kv secrets engine for v2 (versioned secrets)
    vault_secret_kv_tune_v2 "${root_token}" "secret"

    #
    # Enable audit to stdout
    vault_audit_enable_file "${root_token}" "file" "stdout" "STDOUT Audit Device"

    #
    # Enable LDAP auth method
    vault_auth_enable "${root_token}" "ldap" "siege.red LDAP Credentials"

    #
    # Enable Kubernetes auth method
    vault_auth_enable "${root_token}" "kubernetes" "Kubernetes Service Account Credentials"
fi
if [ "${vault_init}" = 'true' ]; then
    echo "[INFO] Getting seal status..."
    status_json=$(vault_seal_status)
    vault_sealed=$(echo "${status_json}" | jq '.sealed')
    if [ "${vault_sealed}" = 'true' ]; then
        echo "[INFO] Sealed = true. Unsealling Vault..."
        keys_json=$(curl ${CURL_VERBOSE} --cacert "${cacert}" \
            -H "Authorization: Bearer ${bearer_token}" \
            -H 'Accept: application/json' \
            https://kubernetes.default/api/v1/namespaces/${namespace}/secrets/vault-unseal-keys 2> /dev/null)
        unseal_key1=$(echo "${keys_json}" | jq -r '.data.key1' | base64 -d)
        unseal_key2=$(echo "${keys_json}" | jq -r '.data.key2' | base64 -d)
        unseal_key3=$(echo "${keys_json}" | jq -r '.data.key3' | base64 -d)
        unseal_key4=$(echo "${keys_json}" | jq -r '.data.key4' | base64 -d)
        unseal_key5=$(echo "${keys_json}" | jq -r '.data.key5' | base64 -d)
        for k in "${unseal_key1}" "${unseal_key2}" "${unseal_key3}"; do
            vault_operator_unseal "${k}"
        done
        echo "[INFO] Vault is now unsealed."

        # get root token to setup more stuff on Vault
        token_json=$(curl ${CURL_VERBOSE} --cacert "${cacert}" \
            -H "Authorization: Bearer ${bearer_token}" \
            -H 'Accept: application/json' \
            https://kubernetes.default/api/v1/namespaces/${namespace}/secrets/vault-root-token 2> /dev/null)
        token=$(echo "${token_json}" | jq -r '.data.value' | base64 -d)

        # inject policies
        echo "[INFO] Injecting policies..."
        for path in $(find /root/policies -type f -name '*.hcl'); do
          file_without_ext=$(basename ${path} .hcl)
          policy=$(base64 "${path}" | tr -d '\n')
          vault_policy_create "${token}" "${file_without_ext}" "${policy}"
          echo "  [INFO] Injected ${file_without_ext}."
        done

        # configure LDAP
        echo "[INFO] Configuring LDAP..."
        vault_auth_ldap_config "${token}" '/root/ldap/ldap.conf'

        # configure Kubernetes auth
        echo "[INFO] Configuring Kubernetes..."
        vault_auth_kubernetes_config "${token}" "${bearer_token}" "https://kubernetes.default" "${cacert}"

        echo "[INFO] Done."

    elif [ "${vault_sealed}" = 'false' ]; then
        echo "[INFO] Vault is already unsealed."
    else
        echo "[WARN] Unknown vault sealed status."
    fi
else
    echo "[WARN] Unknown vault initialized status."
fi
exec /bin/sh -c "trap : TERM INT; (while true; do sleep 1000; done) & wait"