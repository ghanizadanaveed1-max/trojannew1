#!/bin/bash
set -e
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
clear
echo -e "${CYAN}${BOLD}GHANIZADA MULTI-PROTOCOL • CLOUD RUN${RESET}"
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" = "(unset)" ]; then read -rp "Project ID: " PROJECT_ID; gcloud config set project "$PROJECT_ID"; fi
read -rp "Region [us-central1]: " REGION; REGION=${REGION:-us-central1}
read -rp "Service name [ghanizada-trojan]: " SERVICE_NAME; SERVICE_NAME=${SERVICE_NAME:-ghanizada-trojan}
echo "[1] 1 vCPU / 1Gi"; echo "[2] 2 vCPU / 4Gi (recommended)"; echo "[3] 4 vCPU / 8Gi"; read -rp "Choice [2]: " CHOICE; CHOICE=${CHOICE:-2}
case "$CHOICE" in 1) CPU=1; MEMORY=1Gi;; 3) CPU=4; MEMORY=8Gi;; *) CPU=2; MEMORY=4Gi;; esac
for API in run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com; do gcloud services enable "$API" --project="$PROJECT_ID" >/dev/null; done
IMAGE="gcr.io/$PROJECT_ID/$SERVICE_NAME"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo -e "${YELLOW}Building image from: $SCRIPT_DIR${RESET}"

if [ ! -f "$SCRIPT_DIR/Dockerfile" ]; then
  echo -e "${RED}[!] Dockerfile not found in $SCRIPT_DIR${RESET}"
  echo "Make sure Dockerfile is in the same folder as deploy.sh."
  exit 1
fi

if [ ! -f "$SCRIPT_DIR/server.py" ] || [ ! -f "$SCRIPT_DIR/config.json" ]; then
  echo -e "${RED}[!] Required project files are missing.${RESET}"
  echo "Expected Dockerfile, server.py, and config.json beside deploy.sh."
  exit 1
fi
gcloud builds submit "$SCRIPT_DIR" --tag "$IMAGE" --project="$PROJECT_ID"
ADMIN_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
echo -e "${YELLOW}Deploying user-manager service...${RESET}"
gcloud run deploy "$SERVICE_NAME" --image "$IMAGE" --platform managed --region "$REGION" --allow-unauthenticated --port 8080 --cpu "$CPU" --memory "$MEMORY" --timeout 3600 --min-instances 0 --max-instances 1 --set-env-vars "SNI=firebase-settings.crashlytics.com,OWNER_KEY=$ADMIN_KEY" --project "$PROJECT_ID"
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" --project "$PROJECT_ID" --format='value(status.url)')
HOST=${SERVICE_URL#https://}
cat > /tmp/ghanizada-links.txt <<EOL
Dashboard: $SERVICE_URL
Admin key: $ADMIN_KEY
Host: $HOST
Port: 443
Trojan path: /ws/Ghanizada
VLESS path: /ws/VLESS-Ghanizada
VMess path: /ws/VMess-Ghanizada
Users: none pre-configured
EOL
echo; echo -e "${GREEN}${BOLD}DEPLOYMENT SUCCESSFUL${RESET}"; echo "================================"; echo "Dashboard: $SERVICE_URL"; echo "Host:      $HOST"; echo "Port:      443"; echo "Trojan:    /ws/Ghanizada"; echo "VLESS:     /ws/VLESS-Ghanizada"; echo "VMess:     /ws/VMess-Ghanizada"; echo "SSH/Stunnel: NOT EXPOSED ON CLOUD RUN (raw TCP)"; echo "================================"; echo; cat /tmp/ghanizada-links.txt
