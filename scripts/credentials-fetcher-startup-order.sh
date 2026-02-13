#!/usr/bin/env sh

# Forces `ecs.service` to depend on `credentials-fetcher.service`
#
# This works around known issues where gMSA tasks fail to start if the ECS agent
# starts before credentials-fetcher,
#
# This script is intended to be run as part of the instance userdata script

echo "Creating drop-in file for ecs.service..."
mkdir /usr/lib/systemd/system/ecs.service.d
cat > /usr/lib/systemd/system/ecs.service.d/require-credentials-fetcher.conf <<EOF
[Unit]
Wants=credentials-fetcher.service
After=credentials-fetcher.service

[Service]
ExecStartPre=/bin/bash -c 'until [ -S /var/credentials-fetcher/socket/credentials_fetcher.sock ]; do sleep 1; done'
EOF
echo "Done! The ECS agent service will now start credentials-fetcher as a requirement. Restarting ECS agent if already running."
systemctl daemon-reload
systemctl is-active --quiet ecs.service 2>/dev/null && systemctl restart ecs.service || :
