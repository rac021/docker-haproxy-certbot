#!/usr/bin/env bash

# Function to check if the argument is an IP address (IPv4 only)
is_ip() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

# Check if CERT1 or CERT variables are set
if [ -n "$CERT1" ] || [ -n "$CERT" ]; then
    if [ "$STAGING" = true ]; then
        for certname in ${!CERT*}; do
            if is_ip "${!certname}"; then
                # Generate a self-signed certificate if certname is an IP address
                echo
                echo "Create a Self-Signed Certificate for the IP : ${!certname}"
                mkdir -p /etc/letsencrypt/live/${!certname}
                openssl req -x509 -nodes -newkey rsa:2048  \
                            -keyout "/etc/letsencrypt/live/${!certname}/privkey.pem"   \
                            -out    "/etc/letsencrypt/live/${!certname}/fullchain.pem" \
                            -days 365 -subj "/CN=${!certname}"
                echo
            else
                # Use certbot for a domain name
                certbot certonly --no-self-upgrade -n --text --standalone \
                                 --preferred-challenges http-01 \
                                 --staging --key-type ecdsa     \
                                 -d "${!certname}" --keep --expand --agree-tos --email "$EMAIL" \
                    || exit 2
            fi
        done
    else
        for certname in ${!CERT*}; do
            if is_ip "${!certname}"; then
                # Generate a self-signed certificate if certname is an IP address
                echo
                echo "Create a Self-Signed Certificate for the IP : ${!certname}"
                mkdir -p /etc/letsencrypt/live/${!certname}
                openssl req -x509 -nodes -newkey rsa:2048 \
                            -keyout "/etc/letsencrypt/live/${!certname}/privkey.pem"   \
                            -out    "/etc/letsencrypt/live/${!certname}/fullchain.pem" \
                            -days 365 -subj "/CN=${!certname}"
                echo
            else
                # Use certbot for a domain name
                certbot certonly --no-self-upgrade -n --text --standalone \
                                 --preferred-challenges http-01 --key-type ecdsa \
                                 -d "${!certname}" --keep --expand --agree-tos --email "$EMAIL" \
                                 || exit 1
            fi
        done
    fi

    # Create the certs directory if it doesn't exist
    mkdir -p /etc/haproxy/certs
    # Concatenate key and certificate files for each site and output to HAProxy certs directory
    for site in `ls -1 /etc/letsencrypt/live | grep -v ^README$`; do
        cat /etc/letsencrypt/live/$site/privkey.pem   \
            /etc/letsencrypt/live/$site/fullchain.pem \
            | tee /etc/haproxy/certs/haproxy-"$site".pem >/dev/null
    done
fi

exit 0
