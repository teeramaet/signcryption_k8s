# First run the web application

python -u "d:\AdmissionControllerProject\web\flask-form\app.py

# Then go to

http://127.0.0.1:8080

# Start a docker desktop

# Create cluster with minikube

# Goto Mutation webhook directory

cd mutationWebhook\kubernetes-mutating-webhook\kubernetes_files

minikube start --driver docker

# Apply everything

kubectl apply -f deployment.yaml

kubectl apply -f service.yaml

kubectl apply -f secret.yaml

kubectl apply -f mutate-config.yaml

# Check the status of the pod and the name of the pod

kubectl get pods

# Wait for the pod to be running

# Apply the test

kubectl -apply -f final-test.yaml

# See the logs

kubectl logs (name_of_the mutation_pod)

# Check whether the field is correctly mutate

kubectl get deployment,sts,daemonset, secret -o custom-columns='NAME:.metadata.name, SELECTOR:.metadata.digitalSignature'

kubectl get deployment,sts,daemonset, secret -o custom-columns='NAME:.metadata.name, SELECTOR:.metadata.yamlFile'

kubectl get deployment,sts,daemonset, secret -o custom-columns='NAME:.metadata.name, SELECTOR:.metadata.mutate-pub-key'

# Check whether the decryption process is done correctly

go to testEncryption.py and replace the string with your string that you get from
kubectl get deployment,sts,daemonset, secret -o custom-columns='NAME:.metadata.name, SELECTOR:.data

# Let's move to validation part

minikube delete
minikube start --driver docker

# Goto Validation webhook directory

cd validationWebhook\kubernetes-validating-webhook\kubernetes-manifests

# Apply everything

kubectl apply -f webhook-deploy.yaml

kubectl apply -f webhook-secret.yaml

kubectl apply -f webhook-service.yaml

kubectl apply -f webhook-config.yaml

# Wait for the pod to be running

# Apply the test

kubectl -apply -f final-test.yaml
