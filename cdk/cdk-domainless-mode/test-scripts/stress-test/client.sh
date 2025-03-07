while true; 
do
    python3 ../add_delete_kerberos_leases.py
    echo "Script exited, restarting in 2 seconds..."
    sleep 2
done