while :
do
  systemctl stop credentials-fetcher.service
  sleep 2
  systemctl start credentials-fetcher.service
  sleep 30
  echo "Restarted credentials fetcher after 30 seconds..."
done