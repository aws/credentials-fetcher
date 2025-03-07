## Stress Test

This credentials-fetcher stress test validates the shutdown path including gRPC shutdown using repeated add and delete grpc APIs and daemon restarts in a loop. This test checks robustness of the credentials-fetcher daemon, ensuring that it can withstand network interruptions, broken connections, or system reboots without leaving behind unnecessary objects and always cleaning up after itself.

#### Steps to run this test

1. Follow the setup instructions [here](https://github.com/aws/credentials-fetcher/blob/mainline/cdk/cdk-domainless-mode/test-scripts/README.md).
2. Create a tmux session `tmux new -s client1`. Run the client with `bash client.sh`
3. Repeat Step 2 as many times as needed (ex: 3 clients for a t3.medium instance). This creates unique clients that call the credentials-fetcher daemon.
4. To ensure robustness from the server side, create another tmux session `tmux new -s server`, and run the server-restart script as `bash server-restart.sh` This script restarts the daemon every 30 seconds while the client is still calling it.
5. Run `journalctl | grep -i assert` to check that there are no failed ASSERTs.



