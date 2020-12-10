NetApp StorageGRID utility to list bucket contents combined with node info. Either a single object can be listed (this just requires API accees to the grid) or a wildcard search can be performed (this requires both API and S3 access). The wildcard can either be an asterisk ("*") or a regular expression. Node info includes node placement information (the nodes that hold copies for replicated objects or the nodes that hold EC segments).

Requires the Boto3 SDK which can be installed via ````pip````.

Login to the admin node:

````
$ ./sgcli.py -l -a admin-node
````

List the contents of bucket "data" with node placement info:
````
$ ./sgcli.py -a admin-node -p awsprofile -e https://s3.company.com:10443 -o "data/*"
````