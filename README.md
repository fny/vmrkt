# vmrkt 🚀

Launch one-off EC2 instances with a single command.

Note: this tool is intended to be used from its folder for now.

You can launch EC2 instances with the following created automagically:

    - A key pair for SSH access
    - A security group with your specified ingres and egres ports
    - An EC2 instance associated with the key pair and security group
    - An elastic IP associated with the instance and linked to a Route53 record

## Usage

```
Usage: ./vmrkt [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  destroy  Destroy the VM with the given name.
  info     Get information about the VM with the given name.
  launch   Launch a new VM with the given name.
  list     List all VMs based on the keys folder.
  restart  Restart the VM with the given name.
  run      Run a command on all hosts.
  ssh      SSH into the VM with the given name.
  start    Start the VM with the given name.
  stop     Stop the VM with the given name.
  upload   Upload a file to the VM to the specified host.
```

For example, you can launch a VM with the default AMI by running the following:

```
./vmrkt launch rkt-example.yourdomain.com --type t2.micro --ingress 22,443,80
```

Then run it:

```
./vmrkt run example # searches for first matching host in your keys, use regex too
./vmrkt ssh example
```

And destroy it:

```
./vmrkt destroy example rkt-example.yourdomain.com # requires complete name
```

The scripts directory is a collection of useful scripts that can be run on the VMs.

## Installation

You need Python v3.12+. Then `poetry install` to install the dependencies.
This will *not* install everything into a virtual environment. If you really
want to do that, you can edit the pyproject file.


After that make sure AWS credentials are setup properly. You can do this by running
`aws configure` and entering your access key and secret key. Then make sure you have TLDs
in Route 53 that you can use.

Your user must have the following permissions:

 - Private Keys: create, read, delete
 - Security groups: read, create, delete
 - EC2 instances: create, start, stop, terminate
 - Elastic IPs: read, create, delete
 - Route53 records: read, create, delete

## Wishlist

- [ ] Create a pipx command using .config/rkt as a home
- [ ] Allow for more complex instance configurations
- [ ] Creation from a configuration files
- [ ] Support for other cloud providers
