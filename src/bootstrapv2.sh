#!/bin/sh

# Author:  Carlos Machado
# Date:    2019-07-31
#
# Author:   DevOps Team La Redoute
# Date: 16.12.2019
#
# Purpose: Initializes

#############
# FUNCTIONS #
#############

k8s_kubeconfig_create() {
    local cacert="$1"
    local bearer_token="$2"

    local cacert_data=$(base64 "${cacert}" | tr -d '\n')
    mkdir -p ~/.kube
    cat > ~/.kube/config <<-EOF
    apiVersion: v1
    clusters:
      - cluster:
          certificate-authority-data: "${cacert_data}"
          server: https://kubernetes.default:443
        name: k8s
    contexts:
      - context:
          cluster: k8s
          user: k8s-user
        name: k8s
    current-context: k8s
    kind: Config
    preferences: {}
    users:
      - name: k8s-user
        user:
          token: "${bearer_token}"
EOF
}

k8s_secret_create_cm_secret_id() {
    local namespace="$1"
    local secret_name="$2"
    local secret_id="$3"

    cat <<-EOF | kubectl apply -n ${namespace} -f -
    kind: Secret
    apiVersion: v1
    metadata:
      name: "${secret_name}"
    data:
      secretId: "${secret_id}"
    type: Opaque
EOF
}

k8s_clusterissuer_create_vault_issuer() {
    local path="$1"
    local role_id="$2"
    local secret_name="$3"
    local ca_bundle=$(base64 "${VAULT_CACERT}" | tr -d '\n')

    cat <<-EOF | kubectl apply -n ${namespace} -f -
    kind: ClusterIssuer
    apiVersion: certmanager.k8s.io/v1alpha1
    metadata: 
      name: vault-issuer
    spec:
      vault: 
        caBundle: "${ca_bundle}"
        path: "${path}"
        server: "${VAULT_API_ADDR}"
        auth:
          appRole:
            path: approle
            roleId: "${role_id}"
            secretRef:
              name: "${secret_name}"
              key: secretId
EOF
}

vault_generate_intermediate_ca() {
    local path="$1"
    local common_name="$2"
    local default_lease_ttl="$3"
    local max_lease_ttl="$4"

    # enable PKI secrets engine at specified path
    vault secrets enable \
        -path="${path}" \
        -default-lease-ttl="${default_lease_ttl}" \
        -max-lease-ttl="${max_lease_ttl}" \
        pki
    # generate CSR
    vault write -format=json \
        ${path}/intermediate/generate/internal \
        common_name="${common_name}" \
        ttl="${max_lease_ttl}" | jq -r '.data.csr' > /tmp/intermediate.csr
    # Request root CA (pki) to sign the intermediate CA certificate
    vault write -format=json \
        pki/root/sign-intermediate \
        csr=@/tmp/intermediate.csr \
        format=pem_bundle \
        ttl="${max_lease_ttl}" | jq -r '.data | .certificate,.issuing_ca' > /tmp/intermediate.crt
    # store the signed intermediate CA certificate 
    vault write ${path}/intermediate/set-signed certificate=@/tmp/intermediate.crt
    # configure CA and CRL URLs
    vault write ${path}/config/urls \
        issuing_certificates="${VAULT_API_ADDR}/v1/${path}/ca" \
        crl_distribution_points="${VAULT_API_ADDR}/v1/${path}/crl"
}

#############
# MAIN CODE #
#############

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 [allowed_domains],..." >&2
    exit 1
fi
allowed_domains="$1"

cacert='/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
bearer_token="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
namespace="$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)"

k8s_kubeconfig_create "${cacert}" "${bearer_token}"

vault_port=$(echo "${VAULT_ADDR}" | sed -r 's#^https?://(.+):(\d+)#\2#')
    # enable Vault PKI
    vault secrets enable -path="pki" -default-lease-ttl="43824h" -max-lease-ttl="175296h" pki

    # inject Vault Root CA certificates    
    root_pem="/tmp/rootca-bundle.pem"
    cat /root/rootca/tls.key /root/rootca/tls.crt > ${root_pem}
    vault write pki/config/ca pem_bundle=@${root_pem}
    rm -f ${root_pem}
    
    # configure CA and CRL URLs
    vault write pki/config/urls \
        issuing_certificates="${VAULT_API_ADDR}/v1/pki/ca" \
        crl_distribution_points="${VAULT_API_ADDR}/v1/pki/crl"
    
    # enable Vault intermediate PKI
    vault secrets enable -path="pki_int" -default-lease-ttl="43824h" -max-lease-ttl="175296h" pki

    # inject Vault Intermediate CA certificates
    int_pem="/tmp/intca-bundle.pem"
    cat /root/intca/tls.key /root/intca/tls.crt > ${int_pem}
    vault write pki_int/config/ca pem_bundle=@${int_pem}
    rm -f ${int_pem}

    # configure CA and CRL URLs
    vault write pki_int/config/urls \
        issuing_certificates="${VAULT_API_ADDR}/v1/pki_int/ca" \
        crl_distribution_points="${VAULT_API_ADDR}/v1/pki_int/crl"
    
    # if all went well, by now root and intermediate CA private certificates can be removed (cleared) from k8s secrets.
    #
    #
    # Setup for cert-manager.
    # create issuer role
    vault write pki_int/roles/cluster-siege-red \
        organization="LaRedoute" \
        ou="ITSQD" \
        allowed_domains="${allowed_domains}" \
        allow_subdomains="true" \
        allow_bare_domains="true" \
        max_ttl="43824h"
    
    # create cert-manager policy
    cm_policy_name="cert-manager"
    vault policy write ${cm_policy_name} /root/policies/${cm_policy_name}.hcl
    
    # enable appRole auth method, required for cert-manager
    vault auth enable -description="Application Role Credentials" approle
    
    # create cert-manager appRole
    cm_role=${cm_policy_name}
    vault write auth/approle/role/${cm_role} \
        token_ttl=10m \
        token_max_ttl=15m \
        period=0 \
        bind_secret_id=true \
        policies=default,${cm_policy_name}
    
    # update cert-manager appRole ID to a known value. Eases automation.
    cm_role_id="cert-manager-approle-id"
    vault write auth/approle/role/${cm_role}/role-id role_id=${cm_role_id}
    
    # generate new secret id
    secret_id_json=$(vault write -f auth/approle/role/${cm_role}/secret-id -format=json)
    secret_id=$(echo "${secret_id_json}" | jq -r '.data.secret_id' | base64 | tr -d '\n')

    # publish approle secret id as a k8s secret
    cm_secret_name="cert-manager-vault-approle"
    k8s_secret_create_cm_secret_id "${namespace}" "${cm_secret_name}" "${secret_id}"
    
    # Create a cert-manager ClusterIssuer for Vault
    k8s_clusterissuer_create_vault_issuer "pki_int/sign/cluster-siege-red" "${cm_role_id}" "${cm_secret_name}"
        
    #
    #
    # tune default kv secrets engine for v2 (versioned secrets)
    vault secrets enable -path="secret" -version=2 kv

    #
    # Enable audit to stdout
    vault audit enable -path="file" -description="STDOUT Audit Device" file file_path="stdout"

    #
    # Enable LDAP auth method
    vault auth enable -description="siege.red LDAP Credentials" ldap

    # UPDATE
    # Enable Kubernetes auth method
    vault auth enable -description="Kubernetes Service Account Credentials" kubernetes

        export VAULT_TOKEN=${token}

        # inject policies
        echo "[INFO] Injecting policies..."
        for path in $(find /root/policies -type f -name '*.hcl'); do
          policy_name=$(basename ${path} .hcl)
          vault policy write "${policy_name}" "${path}"
        done

        # mapping policies
        echo "[INFO] Mapping policies..."
        /root/scripts/policy-mapping.sh

        # configure LDAP
        echo "[INFO] Configuring LDAP..."
        # load ldap env variables
        source /root/ldap/ldap.conf
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
            kubernetes_host="https://kubernetes.default" \
            kubernetes_ca_cert=@${cacert}

        # vault_generate_intermediate_ca "pki_int_kafka" "Kafka Intermediate Certificate Authority" "21912h" "87648h"
        # vault write pki_int_kafka/roles/kafka-server allowed_domains=streaming allow_subdomains=true max_ttl=1h

        echo "[INFO] Done."
    fi
else
    echo "[WARN] Unknown vault initialized status."
fi
exec /bin/sh -c "trap : TERM INT; (while true; do sleep 1000; done) & wait"