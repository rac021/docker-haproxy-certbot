#!/usr/bin/env bash

set -euo pipefail

# automation of certificate renewal for let's encrypt and haproxy
# - checks all certificates under /etc/letsencrypt/live and renews
#   those about to expire in less than X weeks
# - creates haproxy.pem files in /etc/haproxy/certs/
# - soft-restarts haproxy to apply new certificates
# - generates self-signed certificates for IP addresses
# usage:
# sudo ./cert-renewal-haproxy.sh

################################################################################
### global settings
################################################################################

LE_CLIENT="certbot"
HAPROXY_RELOAD_CMD="supervisorctl signal HUP haproxy"
HAPROXY_SOFTSTOP_CMD="supervisorctl signal USR1 haproxy"
WEBROOT="/jail"
LOGFILE=""  # Enable logging to a file if needed

# Number of days before expiration to renew certificates
RENEWAL_THRESHOLD_DAYS=7  # Change this value as needed for self-signed certs and Let's Encrypt

################################################################################
### FUNCTIONS
################################################################################

# Function to check if the argument is an IP address (IPv4 only)
is_ip() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

# Function to issue a certificate using Certbot
function issueCert {
    $LE_CLIENT certonly --text --webroot --webroot-path ${WEBROOT} --renew-by-default --agree-tos --key-type ecdsa --email ${EMAIL} ${1} &>/dev/null
    return $?
}

# Function to generate a new self-signed certificate for an IP address
function generate_new_self_signed_cert {
    local ip="$1"
    mkdir -p "/etc/letsencrypt/live/${ip}"
    openssl req -x509 -nodes -newkey rsa:2048 \
                -keyout "/etc/letsencrypt/live/${ip}/privkey.pem"   \
                -out    "/etc/letsencrypt/live/${ip}/fullchain.pem" \
                -days 365 -subj "/CN=${ip}"
}

# Function to log errors
function logger_error {
    if [ -n "${LOGFILE}" ]; then
        echo "[error] ${1}\n" >> ${LOGFILE}
    fi
    >&2 echo "[error] ${1}"
}

# Function to log information
function logger_info {
    if [ -n "${LOGFILE}" ]; then
        echo "[info] ${1}\n" >> ${LOGFILE}
    else
        echo "[info] ${1}"
    fi
}

# Check if a self-signed certificate needs renewal
should_renew_cert() {
    local cert_path="$1"
    # Check if the certificate is about to expire in less than RENEWAL_THRESHOLD_DAYS
    if ! openssl x509 -noout -checkend $((RENEWAL_THRESHOLD_DAYS * 86400)) -in "${cert_path}"; then
        return 0  # true, it should be renewed
    else
        return 1  # false, no need to renew
    fi
}

################################################################################
### MAIN
################################################################################

le_cert_root="/etc/letsencrypt/live"

if [ ! -d ${le_cert_root} ]; then
    logger_error "${le_cert_root} does not exist!"
    exit 1
fi

# Check certificate expiration and run certificate issue requests
# for those that expire in under the renewal threshold
renewed_certs=()
exitcode=0

while IFS= read -r -d '' cert; do
    
    subject="$(openssl x509 -noout -subject -in "${cert}" | grep -o -E 'CN = [^ ,]+' | tr -d 'CN = ')"
    subjectaltnames="$(openssl x509 -noout -text -in "${cert}" | sed -n '/X509v3 Subject Alternative Name/{n;p}' | sed 's/\s//g' | tr -d 'DNS:' | sed 's/,/ /g')"
    
    # Check if the subject is an IP address
    if is_ip "${subject}"; then
        # Check if the self-signed certificate is about to expire
        if should_renew_cert "${cert}"; then
            # Generate a new self-signed certificate for the IP address
            generate_new_self_signed_cert "${subject}"
            renewed_certs+=("$subject")
            logger_info "renewed self-signed certificate for ${subject}"
        else
            logger_info "self-signed certificate for ${subject} does not need renewal"
        fi
    else
        # Check if certificate is about to expire
        if should_renew_cert "${cert}"; then
            domains="-d ${subject}"
            for name in ${subjectaltnames}; do
                if [ "${name}" != "${subject}" ]; then
                    domains="${domains} -d ${name}"
                fi
            done
            issueCert "${domains}"
            if [ $? -ne 0 ]; then
                logger_error "failed to renew certificate ! Check /var/log/letsencrypt/letsencrypt.log !"
                exitcode=1
            else
                renewed_certs+=("$subject")
                logger_info "renewed certificate for ${subject}"
            fi
        else
            logger_info "none of the certificates requires renewal"
        fi
    fi
done < <(find /etc/haproxy/certs/ -name '*.pem' -print0)

# Create haproxy.pem file(s) for renewed certificates
for domain in ${renewed_certs[@]}; do
    cat ${le_cert_root}/${domain}/privkey.pem ${le_cert_root}/${domain}/fullchain.pem | tee /etc/haproxy/certs/haproxy-${domain}.pem >/dev/null
    if [ $? -ne 0 ]; then
        logger_error "failed to create haproxy.pem file !"
        exit 1
    fi
done

# Soft-stop (and implicit restart) of haproxy
if [ "${#renewed_certs[@]}" -gt 0 ]; then
    $HAPROXY_SOFTSTOP_CMD
    if [ $? -ne 0 ]; then
        logger_error "failed to stop haproxy !"
        exit 1
    fi
fi

exit ${exitcode}
