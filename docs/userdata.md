# Configuring userdata for credentials-fetcher

Currently, there is a known issue where the startup order between `ecs.service` and `credentials-fetcher.service` matters. If `ecs.service` starts before `credentials-fetcher.service`, then gMSA tasks will fail to start due to a socket error.

If we ensure that `credentials-fetcher.service` starts first, then the socket will work when the ECS agent tries to use it.

To do this, we ship a script that will place a drop-in file for `ecs.service`, which forces the `ecs.service` unit to consider `credentials-fetcher.service` as a dependency, and is intended to be called from your userdata script during startup, after installing the `credentials-fetcher` package.

You can call this from your userdata as follows:
```
/usr/libexec/credentials-fetcher-startup-order.sh
```

After running this script, any time ~ecs.service~ is started in the future, ~credentials-fetcher.service~ is guaranteed to start first.

# Removing the dependency

If you wish to no longer have this dependency relationship in place, you can simply remove the drop-in file:
```
rm /usr/lib/systemd/system/ecs.service.d/require-credentials-fetcher.conf

if [ -z "$( ls -A '/usr/lib/systemd/system/ecs.service.d' )" ]; then
    rm -rf /usr/lib/systemd/system/ecs.service.d
fi
```
