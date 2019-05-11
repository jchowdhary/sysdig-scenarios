Docker best practices recommend running just one process per container. This has a significant security impact because you know exactly which processes you expect to see running.

You know that your _Nginx_ containers should only be executing the _nginx_ process. Anything else is an indicator of an anomaly.

Let's download a new version of the configuration file for this example:

`sudo -s
cd /etc/falco
curl https://raw.githubusercontent.com/katacoda-scenarios/sysdig-scenarios/master/falco/sysdig-falco/assets/falco_rules_step3.yaml -o falco_rules.yaml`{{execute}}

Now, pay attention to the following rule in the file:

```yaml
# Our nginx containers should only be running the 'nginx' process
- rule: Unauthorized process on nginx containers
  desc: There is a process running in the nginx container that is not described in the template
  condition: spawned_process and container and container.image startswith nginx and not proc.name in (nginx)
  output: Unauthorized process (%proc.cmdline) running in (%container.id)
  priority: WARNING
```

Let's dissect the triggering conditions for this rule:

- `spawned_process` (a macro: a new process was executed (execve-ed) succesfully)
- `container` (a macro: the namespace where it was executed belongs to a container and not the host)
- `container.image startswith nginx` (a container property: the image name so you can have an authorized process lists for each one)
- `not proc.name in (nginx)` (the list of allowed processes names)

To apply the new configuration file we will restart the Sysdig Falco container: `docker restart falco`{{execute}}.

Now we need to run a new _Nginx_ container:

`docker run -d -P --name example2 nginx`{{execute}}

And run anything in the _example2_ container, _ls_ for example:

`docker exec -it example2 ls`{{execute}}

If we look at the log with `tail /var/log/falco_events.log`{{execute}} you will be able to read:

```log
18:38:43.364877988: Warning Unauthorized process (ls ) running in (604aa46610dd)
```

Good catch! The Sysdig Falco notification shows that it recognized an unexpected process.
