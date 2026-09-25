# Ghanizada Cloud Run User Manager

This version does **not** ship with any Trojan, VLESS, or VMess users.

After deployment, open the Cloud Run dashboard and log in with the **Admin key** printed by `deploy.sh`.

## Website features
- Create Trojan, VLESS, or VMess users.
- Automatically generate password/UUID when the credential field is blank.
- Edit username and credential.
- Delete users.
- Show each user's import URI and QR code.
- Show total users and recently active users.
- Changes rebuild the Xray user lists and restart Xray automatically.

## Important
The user database is stored in the Cloud Run instance's writable filesystem. Cloud Run storage is ephemeral, so for production persistence across instance replacement/redeployment, move the user database to a persistent service such as Cloud SQL or Firestore.

The dashboard's activity indicator means **recent Xray access-log activity (about 90 seconds)**; it is not a guaranteed count of currently open TCP/WebSocket sessions.

SSH + Stunnel is not exposed because Cloud Run's public service endpoint is HTTPS/WebSocket rather than a general raw-TCP SSH endpoint.

## Deploy
```bash
chmod +x deploy.sh
./deploy.sh
```

The deployment script explicitly submits the project directory to Cloud Build, avoiding the previous source-path error.
