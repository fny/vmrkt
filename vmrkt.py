import os
import sys
import textwrap
import time
import traceback
from typing import Optional

import boto3
import boto3.session
import paramiko
from pydantic import BaseModel

session = boto3.Session(region_name="us-east-1")
ec2 = session.client("ec2")
ec2_resource = session.resource("ec2")
route53 = session.client("route53")


class EC2Settings(BaseModel):
    image_id: str
    instance_type: str
    inbound_ports: list[int]
    outbound_ports: list[int]
    ubuntu_version: str


class ResourceNotFound(Exception):
    pass


def remove_host_from_known_hosts(hostname_or_ip: str):
    # Define the path to the known_hosts file
    known_hosts_path = os.path.expanduser("~/.ssh/known_hosts")

    # Check if the known_hosts file exists
    if not os.path.exists(known_hosts_path):
        return

    # Read the contents of the known_hosts file
    with open(known_hosts_path, "r") as file:
        lines = file.readlines()

    # Check if the host is in the file and remove the corresponding line(s)
    updated_lines = [line for line in lines if hostname_or_ip not in line]

    # If the number of lines changed, the host was found and removed
    if len(updated_lines) != len(lines):
        # Create a backup of the original file
        backup_path = known_hosts_path + ".bak"
        with open(backup_path, "w") as backup_file:
            backup_file.writelines(lines)
        print(f"Backup created at {backup_path}")

        # Write the updated lines back to the known_hosts file
        with open(known_hosts_path, "w") as file:
            file.writelines(updated_lines)
        print(f"Removed {hostname_or_ip} from the known_hosts file.")


class SSHConnection:
    _instances = {}

    @staticmethod
    def create_instance(hostname: str, key_file: Optional[str] = None):
        if hostname not in SSHConnection._instances:
            SSHConnection._instances[hostname] = SSHConnection(hostname, key_file)
        return SSHConnection._instances[hostname]

    def __init__(self, hostname: str, key_file: Optional[str] = None):
        if hostname in self._instances:
            return
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.hostname = hostname
        self.key_file = key_file or f"keys/{hostname}.pem"
        self.ssh.connect(hostname, username="ubuntu", key_filename=self.key_file)

    def run_commands(self, commands: str):
        commands = "\n".join(commands) if isinstance(commands, list) else commands
        commands = textwrap.dedent(commands).strip()
        commands = commands.split("\n")
        # Execute the pyenv installation commands
        for command in commands:
            print(f"$ {command}")
            stdin, stdout, stderr = self.ssh.exec_command(command)
            # Continuously read from stdout and stderr
            while True:
                # Read a line from stdout
                stdout_line = stdout.readline()
                if stdout_line:
                    # Handle lines with carriage return (loading bars, etc.)
                    if "\r" in stdout_line:
                        sys.stdout.write("\r" + stdout_line.strip())
                        sys.stdout.flush()
                    else:
                        print(stdout_line.strip())

                # Read a line from stderr
                stderr_line = stderr.readline()
                if stderr_line:
                    if "\r" in stderr_line:
                        sys.stderr.write("\r" + stderr_line.strip())
                        sys.stderr.flush()
                    else:
                        print(stderr_line.strip(), file=sys.stderr)

                # Check if the command has finished
                if stdout.channel.exit_status_ready():
                    break

            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                print(f"Command exited with status: {exit_status}")
                break

    def close(self):
        self.ssh.close()


#
# Helpers
#


def _split_domain(domain: str) -> tuple[str, str]:
    split = domain.split(".")

    tld = ".".join(split[-2:])
    subdomain = split[0]
    return subdomain, tld


#
# Misc
#


def get_ubuntu_ami_id(version):
    # Search for Ubuntu AMIs for x86_64 architecture with the specified version
    response = ec2.describe_images(
        Filters=[
            {
                "Name": "name",
                "Values": [f"ubuntu/images/hvm-ssd/ubuntu-amd64-server-*"],
            },  # AMI name pattern for the specified Ubuntu version
            {"Name": "architecture", "Values": ["x86_64"]},  # Architecture type
            {"Name": "virtualization-type", "Values": ["hvm"]},  # Virtualization type
            {"Name": "root-device-type", "Values": ["ebs"]},  # Root device type
        ],
        Owners=["099720109477"],  # Canonical's AWS account ID (owner of Ubuntu AMIs)
    )
    try:
        return sorted(response["Images"], key=lambda x: x["CreationDate"])[-1][
            "ImageId"
        ]
    except Exception as e:
        raise ResourceNotFound(f"AMI for Ubuntu {version} not found")


#
# Key Pair
#


def get_key_pair(name: str) -> dict:
    try:
        response = ec2.describe_key_pairs(KeyNames=[name])
        return response["KeyPairs"][0]
    except Exception as e:
        raise ResourceNotFound(f"Key pair {name} not found")


def create_key_pair(name: str):
    pem_file = f"keys/{name}.pem"
    key_pair = ec2.create_key_pair(KeyName=name)

    with open(pem_file, "w") as file:
        file.write(key_pair["KeyMaterial"])

    os.chmod(pem_file, 0o400)

    print(f"Key pair created and saved as {pem_file}")


def delete_key_pair(name: str):
    try:
        os.remove(f"keys/{name}.pem")
    except FileNotFoundError:
        pass
    get_key_pair(name)
    try:
        return ec2.delete_key_pair(KeyName=name)
    except Exception:
        raise ResourceNotFound(f"Key pair {name} not found")


#
# Security Group
#


def create_security_group(name: str, ingress: list[int] = [], egress: list[int] = []):
    response = ec2.create_security_group(
        GroupName=name, Description=f"ec2rkt security group for {name}"
    )

    security_group_id = response["GroupId"]

    # Use the security group ID to create a SecurityGroup object
    security_group = ec2_resource.SecurityGroup(security_group_id)

    in_ip_permissions = []
    for port in ingress:
        in_ip_permissions.append(
            {
                "FromPort": port,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {"CidrIp": "0.0.0.0/0", "Description": "SSH Access"},
                ],
                "ToPort": port,
            }
        )

    out_ip_permissions = []
    for port in egress:
        permissions = {
            "FromPort": int(port),
            "IpProtocol": "tcp",
            "IpRanges": [
                {"CidrIp": "0.0.0.0/0"},
            ],
            "ToPort": int(port),
        }
    if port == -1:
        permissions["FromPort"] = 0
        permissions["ToPort"] = 65535
        out_ip_permissions = [permissions]
    else:
        out_ip_permissions.append(permissions)

    security_group.authorize_ingress(IpPermissions=in_ip_permissions)
    security_group.authorize_egress(IpPermissions=out_ip_permissions)
    return security_group


def get_security_group(name: str) -> dict:
    try:
        response = ec2.describe_security_groups(GroupNames=[name])
        return response["SecurityGroups"][0]
    except Exception as e:
        raise ResourceNotFound(f"Security group {name} not found")


def delete_security_group(name: str) -> dict:
    group_id = get_security_group(name)["GroupId"]
    return ec2.delete_security_group(GroupId=group_id)


#
# Elastic IP
#


def create_elastic_ip(name: str) -> dict:
    allocation = ec2.allocate_address(
        Domain="vpc"
    )  # 'vpc' is the most common domain for VPC-based Elastic IPs
    allocation_id = allocation["AllocationId"]

    # Tag the Elastic IP with the provided name
    ec2.create_tags(Resources=[allocation_id], Tags=[{"Key": "Name", "Value": name}])
    return allocation


def get_elastic_ip(name: str) -> dict:
    try:
        response = ec2.describe_addresses(
            Filters=[{"Name": "tag:Name", "Values": [name]}]
        )
        return response["Addresses"][0]
    except IndexError:
        raise ResourceNotFound(f"Elastic IP {name} not found")


def delete_elastic_ip(name: str) -> dict:
    allocation_id = get_elastic_ip(name)["AllocationId"]
    return ec2.release_address(AllocationId=allocation_id)


#
# DNS
#


def create_dns_record(
    domain: str,
    ip_address: str,
    ttl=300,
) -> dict:
    hosted_zone_id = get_hosted_zone_id(domain)

    return route53.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            "Comment": "Create A record for subdomain",
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": domain,
                        "Type": "A",
                        "TTL": ttl,
                        "ResourceRecords": [{"Value": ip_address}],
                    },
                }
            ],
        },
    )


def get_hosted_zone_id(domain: str) -> str:
    tld = _split_domain(domain)[1]
    response = route53.list_hosted_zones_by_name(DNSName=tld)
    for zone in response["HostedZones"]:
        if zone["Name"] == tld + ".":
            return zone["Id"]
    raise ResourceNotFound(f"Hosted zone for domain {tld} not found")


def get_dns_record(hostname: str) -> dict:
    _, tld = _split_domain(hostname)
    hosted_zone_id = get_hosted_zone_id(tld)
    response = route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    for record in response["ResourceRecordSets"]:
        if record["Name"] == hostname + ".":
            return record
    raise ResourceNotFound(f"DNS record for {hostname} not found")


def delete_dns_record(hostname: str) -> dict:
    _, tld = _split_domain(hostname)
    hosted_zone_id = get_hosted_zone_id(tld)

    record = get_dns_record(hostname)

    return route53.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            "Comment": "Delete A record for subdomain",
            "Changes": [
                {
                    "Action": "DELETE",
                    "ResourceRecordSet": {
                        "Name": record["Name"],
                        "Type": record["Type"],
                        "TTL": record["TTL"],
                        "ResourceRecords": record["ResourceRecords"],
                    },
                }
            ],
        },
    )


#
# EC2
#


def get_ec2_instance(name: str) -> dict:
    response = ec2.describe_instances(Filters=[{"Name": "tag:Name", "Values": [name]}])
    try:
        return response["Reservations"][0]["Instances"][0]
    except Exception as e:
        raise ResourceNotFound(f"EC2 instance {name} not found")


def get_ec2_instance_ids(name: str) -> list[str]:
    try:
        response = ec2.describe_instances(
            Filters=[{"Name": "tag:Name", "Values": [name]}]
        )
    except Exception as e:
        raise ResourceNotFound(f"EC2 instance {name} not found")
    ids = []
    try:
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                ids.append(instance["InstanceId"])
        return ids
    except Exception as e:
        raise e


def delete_ec2_instance(name: str) -> dict:
    instance_id = get_ec2_instance(name)["InstanceId"]
    return ec2.terminate_instances(InstanceIds=[instance_id])


def delete_ec2_instances(name: str) -> dict:
    instance_ids = get_ec2_instance_ids(name)
    filtered_ids = [id for id in instance_ids if not is_in_state(id, "terminated")]
    if len(filtered_ids) == 0:
        return {}
    return ec2.terminate_instances(InstanceIds=filtered_ids)


def create_ec2_instance(
    name: str,
    ami_id: str,
    instance_type: str,
    ingress: list[int],
    egress: list[int],
    disk_size: int,
):
    security_group = create_security_group(name, ingress, egress)

    return ec2_resource.create_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MaxCount=1,
        MinCount=1,
        KeyName=name,
        SecurityGroupIds=[security_group.group_id],
        BlockDeviceMappings=[
            {
                "DeviceName": "/dev/sda1",  # Default root device
                "Ebs": {
                    "VolumeSize": disk_size,  # Specify disk size in GB
                    "DeleteOnTermination": True,
                    "VolumeType": "gp2",  # General Purpose SSD
                },
            }
        ],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": name}],
            }
        ],
    )[0]


#
# rkt
#


def create_rkt(
    hostname: str,
    instance_type: str,
    disk_size: int,
    ami_id: str,
    ingress: list[int],
    egress: list[int],
):
    remove_host_from_known_hosts(hostname)
    create_key_pair(hostname)

    instance = create_ec2_instance(
        hostname, ami_id, instance_type, ingress, egress, disk_size
    )
    print("Created EC2 instance, waiting for it to start")

    wait_for_state(instance.instance_id, "running")

    elastic_ip = create_elastic_ip(hostname)
    print("Created Elastic IP")
    ec2.associate_address(
        InstanceId=instance.instance_id,
        AllocationId=elastic_ip["AllocationId"],
    )
    print("Associated Elastic IP with EC2 instance")
    create_dns_record(hostname, elastic_ip["PublicIp"])
    print("Created subdomain")


def destroy_rkt(hostname: str):
    try:
        delete_key_pair(hostname)
        remove_host_from_known_hosts(hostname)
        print("Deleted key pair")
    except ResourceNotFound:
        print("Key pair already deleted")
    except Exception as e:
        # print(traceback.format_exc())
        print("Failed to delete key pair:", type(e).__name__, e)
    try:
        delete_elastic_ip(hostname)
        print("Deleted Elastic IP")
    except ResourceNotFound:
        print("Elastic IP already deleted")
    except Exception as e:
        print(traceback.format_exc())
        print("Failed to delete Elastic IP:", e)
    try:
        delete_dns_record(hostname)
        print("Deleted DNS record")
    except ResourceNotFound:
        print("DNS record already deleted")
    except Exception as e:
        # print(traceback.format_exc())
        print("Failed to delete DNS record:", type(e).__name__, e)
    try:
        ids = get_ec2_instance_ids(hostname)
        if not ids or all(
            id == "terminated" for id in get_instance_states(ids).values()
        ):
            print("All EC2 instances already terminated")
        else:
            delete_ec2_instances(hostname)
            for id in ids:
                wait_for_state(id, "terminated")
            print("Deleted EC2 instance")
    except Exception as e:
        # print(traceback.format_exc())
        print("Failed to delete EC2 instance:", type(e).__name__, e)
    try:
        delete_security_group(hostname)
        print("Deleted security group")
    except ResourceNotFound as e:
        print("Security group already deleted")
    except Exception as e:
        # print(traceback.format_exc())
        print("Failed to delete security group:", type(e).__name__, e)


def rkt_info(name: str) -> dict:
    try:
        instance = get_ec2_instance(name)
    except ResourceNotFound as e:
        instance = None

    try:
        security_group = get_security_group(name)
    except ResourceNotFound as e:
        security_group = None

    try:
        elastic_ip = get_elastic_ip(name)
    except ResourceNotFound as e:
        elastic_ip = None

    try:
        subdomain = get_dns_record(name)
    except ResourceNotFound as e:
        subdomain = None

    return {
        "instance": instance,
        "security_group": security_group,
        "elastic_ip": elastic_ip,
        "subdomain": subdomain,
    }


def start_instance(name: str) -> dict:
    name, _ = _split_domain(name)
    instance_id = get_ec2_instance(name)["InstanceId"]
    response = ec2.start_instances(InstanceIds=[instance_id])
    return response


def stop_instance(name: str) -> dict:
    instance_id = get_ec2_instance(name)["InstanceId"]
    response = ec2.stop_instances(InstanceIds=[instance_id])
    return response


def restart_instance(name: str) -> dict:
    instance_id = get_ec2_instance(name)["InstanceId"]
    response = ec2.reboot_instances(InstanceIds=[instance_id])
    return response


def get_instance_state(instance_id: str) -> str:
    response = ec2.describe_instance_status(InstanceIds=[instance_id])
    response = ec2.describe_instances(InstanceIds=[instance_id])
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            return instance["State"]["Name"]
    raise ResourceNotFound(f"Instance {instance_id} not found")


def get_instance_states(instance_ids: list[str]) -> dict:
    response = ec2.describe_instance_status(InstanceIds=instance_ids)
    instance_states = {}
    for instance_status in response["InstanceStatuses"]:
        instance_id = instance_status["InstanceId"]
        state = instance_status["InstanceState"]["Name"]
        instance_states[instance_id] = state
    return instance_states


def is_in_state(instance_id: str, desired_state: str) -> bool:
    try:
        state = get_instance_state(instance_id)
        return desired_state == state
    except ResourceNotFound:
        return desired_state == "terminated"


def wait_for_state(instance_id: str, desired_state: str) -> None:
    message_printed = False
    while not is_in_state(instance_id, desired_state):
        state = get_instance_state(instance_id)

        if not message_printed:
            print(f"Instance {instance_id} is {state}. Waiting for {desired_state}...")
        message_printed = True
        time.sleep(1)
    print(f"Instance {instance_id} is {desired_state}")


#
# Commands
#


def run_commands(hostname: str, commands: str | list[str]) -> None:
    SSHConnection(hostname).run_commands(commands)
