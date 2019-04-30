Next let's create a `kubeless` namespace and deploy kubeless.

`export RELEASE=$(curl -s https://api.github.com/repos/kubeless/kubeless/releases/latest | grep tag_name | cut -d '"' -f 4)
kubectl create ns kubeless
kubectl create -f https://github.com/kubeless/kubeless/releases/download/$RELEASE/kubeless-$RELEASE.yaml`{{execute}}

You can see:

- the pods created:  
  `kubectl get pods -n kubeless`{{execute}}
- the deployment:  
  `kubectl get deployment -n kubeless`{{execute}}
- and the _functions_ Custom Resource Definition:  
  `kubectl get customresourcedefinition`{{execute}}

Finally, install the Kubeless CLI:

`export OS=$(uname -s| tr '[:upper:]' '[:lower:]')
curl -OL https://github.com/kubeless/kubeless/releases/download/$RELEASE/kubeless_$OS-amd64.zip
unzip kubeless_$OS-amd64.zip
sudo mv bundles/kubeless_$OS-amd64/kubeless /usr/local/bin/`{{execute}}