# Deploying Credentials Fetcher as a Systemd Service

This directory contains the systemd service file for running Credentials Fetcher as a systemd service.

## Installation Steps

1. Build the credentials-fetcher binary:
   ```
   cd /workplace/muskanl/CredentialsFetcherV2WS/src/CredentialsFetcherV2
   brazil-build
   ```

2. Copy the binary to a system location:
   ```
   sudo cp ./build/bin/credentials-fetcher /usr/local/bin/
   sudo chmod +x /usr/local/bin/credentials-fetcher
   ```

3. Copy the service file to systemd directory:
   ```
   sudo cp ./deploy/credentials-fetcher.service /etc/systemd/system/
   ```

4. Reload systemd to recognize the new service:
   ```
   sudo systemctl daemon-reload
   ```

5. Enable the service to start on boot:
   ```
   sudo systemctl enable credentials-fetcher.service
   ```

6. Start the service:
   ```
   sudo systemctl start credentials-fetcher.service
   ```

## Monitoring and Management

- Check service status:
  ```
  sudo systemctl status credentials-fetcher.service
  ```

- View logs:
  ```
  sudo journalctl -u credentials-fetcher.service -f
  ```

- Stop the service:
  ```
  sudo systemctl stop credentials-fetcher.service
  ```

- Restart the service:
  ```
  sudo systemctl restart credentials-fetcher.service
  ```

## Troubleshooting

If you encounter issues with the systemd watchdog integration:

1. Ensure the binary is properly built with systemd support
2. Check that the `coreos/go-systemd` package is properly imported
3. Verify that the service is running with the correct permissions
4. Check the logs for any specific error messages
