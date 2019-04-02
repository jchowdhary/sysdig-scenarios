After the attacker abused the usernames/passwords he obtained, we are assigned the task of finding out what happened, and when did it happen.

Fortunately, we took precautions in step 1, when we installed Falco with a few relevant rules.

`more custom_rules.yaml`{{execute HOST1}}

Notice than among the conditions of our rules we make use of k8s metadata:
`k8s.ns.name=ping and k8s.deployment.name=ping`

You can find all the available fields in the [documentation](https://github.com/draios/sysdig/wiki/Sysdig-User-Guide#all-supported-filters).

We can get the answers we need by taking a look at the logs generated by Falco:

`kubectl logs --selector app=falco`{{execute HOST1}}