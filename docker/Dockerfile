FROM ubuntu:14.10

ENV DEBIAN_FRONTEND noninteractive

# Prerequisites
RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d && \
    apt-get update && apt-get install -y \
    ssl-cert \
    postfix \
    dovecot-imapd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


# CA configuration - https://jamielinux.com/docs/openssl-certificate-authority/introduction.html
ADD ./ca/intermediate.openssl.cnf /root/ca/intermediate/openssl.cnf
ADD ./ca/root.openssl.cnf /root/ca/openssl.cnf
RUN echo "Setup Root CA" \
    && mkdir -p /root/ca/certs /root/ca/crl /root/ca/newcerts /root/ca/private \
    && chmod 700  /root/ca/private \
    && touch /root/ca/index.txt \
    && echo 1000 >/root/ca/serial \
    && echo Generating Root Key \
    && openssl genrsa -aes256 -passout pass:insecure-root -out /root/ca/private/ca.key.pem 4096 \
    && chmod 400 /root/ca/private/ca.key.pem  \
    && echo Generating Root Certificate  \
    && openssl req -config /root/ca/openssl.cnf \
            -key /root/ca/private/ca.key.pem -passin pass:insecure-root -new -x509 -days 7300 \
            -sha256 -extensions v3_ca \
            -out /root/ca/certs/ca.cert.pem \
            -subj '/CN=ca.example.org/O=Insecure CA/C=US/ST=NY' \
    && echo "Generate Intermediate Pair" \
    && mkdir -p /root/ca/intermediate/certs /root/ca/intermediate/crl /root/ca/intermediate/newcerts /root/ca/intermediate/private \
                /root/ca/intermediate/csr \
    && chmod 700  /root/ca/intermediate/private \
    && touch /root/ca/intermediate/index.txt \
    && echo 1000 >/root/ca/intermediate/serial \
    && echo 1000 > /root/ca/intermediate/crlnumber \
    && echo Generating Intermediate Key \
    && openssl genrsa -aes256 -passout pass:insecure-intermediate -out /root/ca/intermediate/private/intermediate.key.pem 4096 \
    && chmod 400 /root/ca/intermediate/private/intermediate.key.pem  \
    && echo Generating Intermediate Certificate  \
    && openssl req -config /root/ca/intermediate/openssl.cnf -new -sha256  -passin pass:insecure-intermediate -passout pass:"" \
        -key /root/ca/intermediate/private/intermediate.key.pem \
        -out /root/ca/intermediate/csr/intermediate.csr.pem \
        -subj '/CN=intermediate.ca.example.org/O=Insecure CA/C=US/ST=NY' \
    && echo "Sign Intermediate Certificate" \
    && openssl ca -batch -config /root/ca/openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 \
        -in /root/ca/intermediate/csr/intermediate.csr.pem -passin pass:insecure-root \
        -out /root/ca/intermediate/certs/intermediate.cert.pem \
    && chmod 444 /root/ca/intermediate/certs/intermediate.cert.pem \
    && echo "Generate Certificate Chain" \
    && cat /root/ca/intermediate/certs/intermediate.cert.pem \
            /root/ca/certs/ca.cert.pem > /root/ca/intermediate/certs/ca-chain.cert.pem \
    && chmod 444 /root/ca/intermediate/certs/ca-chain.cert.pem \
    && echo "Generate IMAP Keys" \
    && openssl genrsa -out /root/ca/intermediate/private/imap.example.org.key.pem 2048 \
    && chmod 400 /root/ca/intermediate/private/imap.example.org.key.pem \
    && openssl req -config /root/ca/intermediate/openssl.cnf \
        -key /root/ca/intermediate/private/imap.example.org.key.pem \
        -new -sha256 -out /root/ca/intermediate/csr/imap.example.org.csr.pem \
        -subj '/CN=imap.example.org/O=Insecure MDA/C=US/ST=NY' \
    && openssl ca -config /root/ca/intermediate/openssl.cnf \
        -extensions server_cert -days 375 -notext -md sha256 -passin pass:insecure-intermediate \
        -in /root/ca/intermediate/csr/imap.example.org.csr.pem \
        -out /root/ca/intermediate/certs/imap.example.org.cert.pem \
    && chmod 444 /root/ca/intermediate/certs/imap.example.org.cert.pem \
    && echo "Generate SMTP Keys" \
    && openssl genrsa -out /root/ca/intermediate/private/smtp.example.org.key.pem 2048 \
    && chmod 400 /root/ca/intermediate/private/smtp.example.org.key.pem \
    && openssl req -config /root/ca/intermediate/openssl.cnf \
        -key /root/ca/intermediate/private/smtp.example.org.key.pem \
        -new -sha256 -out /root/ca/intermediate/csr/smtp.example.org.csr.pem \
        -subj '/CN=smtp.example.org/O=Insecure MDA/C=US/ST=NY' \
    && openssl ca -config /root/ca/intermediate/openssl.cnf \
        -extensions server_cert -days 375 -notext -md sha256 -passin pass:insecure-intermediate \
        -in /root/ca/intermediate/csr/smtp.example.org.csr.pem \
        -out /root/ca/intermediate/certs/smtp.example.org.cert.pem \
    && chmod 444 /root/ca/intermediate/certs/smtp.example.org.cert.pem


# Postfix configuration
ADD ./config/postfix.main.cf /etc/postfix/main.cf
ADD ./config/postfix.master.cf.append /etc/postfix/master-additional.cf
RUN cat /etc/postfix/master-additional.cf >> /etc/postfix/master.cf

# Dovecot configuration
COPY ./config/dovecot.mail /etc/dovecot/conf.d/10-mail.conf
COPY ./config/dovecot.ssl /etc/dovecot/conf.d/10-ssl.conf
COPY ./config/dovecot.auth /etc/dovecot/conf.d/10-auth.conf
COPY ./config/dovecot.master /etc/dovecot/conf.d/10-master.conf
COPY ./config/dovecot.lda /etc/dovecot/conf.d/15-lda.conf
COPY ./config/dovecot.imap /etc/dovecot/conf.d/20-imap.conf
COPY ./config/example/passwords /etc/dovecot/passwd

# Uncomment to add verbose logging
COPY ./config/dovecot.logging /etc/dovecot/conf.d/10-logging.conf
COPY ./config/rsyslog.conf /etc/rsyslog.conf

# Nice place for your settings
VOLUME ["/mail_settings"]

# Copy boot scripts
COPY boot /
RUN chmod 755 /boot


# Volume to store email
VOLUME ["/vmail"]

# Add user vmail that owndocks mail
RUN groupadd -g 5000 vmail  \
    && useradd -g vmail -u 5000 vmail -d /vmail -m  \
    && adduser dovecot vmail \
    && chown vmail:vmail /vmail \
    && chmod 1775 /vmail

EXPOSE 25 143 587
ENTRYPOINT /boot; service postfix start; service dovecot start; rsyslogd -n
