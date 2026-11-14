cd /root/opencti/docker

# CHANGE THIS: the three values below
OPENCTI_IP='10.0.1.70'
ADMIN_EMAIL='<ADMIN_EMAIL>'
ADMIN_PASSWORD='<ADMIN_PASSWORD>'

cat > .env << EOF
OPENCTI_HOST=${OPENCTI_IP}
OPENCTI_PORT=8080
OPENCTI_EXTERNAL_SCHEME=http
OPENCTI_ADMIN_EMAIL=${ADMIN_EMAIL}
OPENCTI_ADMIN_PASSWORD=${ADMIN_PASSWORD}
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
OPENCTI_HEALTHCHECK_ACCESS_KEY=$(cat /proc/sys/kernel/random/uuid)
OPENCTI_ENCRYPTION_KEY=$(openssl rand -base64 32)
PLATFORM_REGISTRATION_TOKEN=$(openssl rand -hex 32)

MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=$(openssl rand -base64 32)
OPENSEARCH_ADMIN_PASSWORD=$(openssl rand -hex 16)
SMTP_HOSTNAME=localhost
ELASTIC_MEMORY_SIZE=4G

XTM_COMPOSER_ID=$(cat /proc/sys/kernel/random/uuid)
COMPOSE_PROJECT_NAME=opencti

CONNECTOR_EXPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_CSV_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_TXT_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_DOCUMENT_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_FILE_YARA_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_EXTERNAL_REFERENCE_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_ANALYSIS_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_OPENCTI_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_MITRE_ID=$(cat /proc/sys/kernel/random/uuid)

# XTM One is not used in this lab. These values only stop "variable is not set" warnings.
XTM_ONE_EXTERNAL_SCHEME=http
XTM_ONE_HOST=localhost
XTM_ONE_PORT=4000
XTM_ONE_ADMIN_EMAIL=notused@example.com
XTM_ONE_ADMIN_PASSWORD=notused
XTM_ONE_SECRET_KEY=notused
XTM_ONE_POSTGRES_USER=notused
XTM_ONE_POSTGRES_PASSWORD=notused
EOF
chmod 600 .env
