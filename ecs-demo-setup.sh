#!/bin/bash
#
# Script to setup an AWS ECS environment 
#

# this is pretty self contained, it makes a few assumptions
# 
# 1. You have an IAM user setup
# 2. You are in eu-west1 region
# 3. You know the ami value, it will default to the  eu-west value for 
#     now, but that will fail for you in other regions. You can override
#     this with the AWS_AMI environment variable

CURL=curl
AWS=aws
JQ=jq

AWS_EB=${AWS_EB:-eb}    
AWS_AMI=${AWS_AMI:-ami-519a0a26}
AWS_VPC_CIDR=${AWS_VPC_CIDR:-10.0.0.0/16}
AWS_VPC_SUBNET_CIDR=${AWS_VPC_CIDR:-10.0.1.0/24}
ECSDEMO_CIDR=${ECSDEMO_CIDR:-0.0.0.0/0}
ECSDEMO_GROUPNAME=${ECSDEMO_GROUPNAME:-aws_ecs}
ECSDEMO_HOSTCOUNT=${ECSDEMO_HOSTCOUNT:-1}
ECSDEMO_IAM=${ECSDEMO_IAM:-ECSContainerDemo}
ECSDEMO_VPC=${ECSDEMO_VPC:-weavedemo}

SSH_OPTS=${SSH_OPTS:-"-o StrictHostKeyChecking=no"}
DIRNAME=`dirname $0`

if [ $DIRNAME = "." ]; then
    DIRNAME=`pwd`
fi

MY_KEY=$DIRNAME/$ECSDEMO_GROUPNAME-key.pem
ECSDEMO_ENVFILE=$DIRNAME/weavedemo.env
KEYPAIR=$ECSDEMO_GROUPNAME-key
MY_R_FILTER="Name=instance-state-name,Values=running"
MY_G_FILTER="Name=instance.group-name,Values=$ECSDEMO_GROUPNAME"
MY_SSH="ssh -i $MY_KEY"
HOSTCOUNT=0

echo "Checking for required tools"
echo ""
type -P "$AWS" >/dev/null 2>&1 && echo -e "Found aws cli" || { echo -e "aws not found, exiting"; exit 1; }
type -P "$CURL" >/dev/null 2>&1 && echo "Found curl" || { echo -e "curl not found, exiting"; exit 1; }
type -P "$JQ" >/dev/null 2>&1 && echo "Found jq" || { echo -e "jq not found, exiting"; exit 1; }
echo ""

REGION=$(aws configure list | grep region | awk '{print $2}')

# so we have a couple of things to do
# 1. Check for an IAM Policy for ECS, create one if its not there
# 2. 

# grab our IP 
echo "Getting our IP for our security group"
MY_IP=$(curl -s http://checkip.amazonaws.com)

# we need an IAM policy in place

echo ""
echo "Checking for IAM Policy $ECSDEMO_IAM"

IAM_MATCH=`printf '.Policies[] | select(.PolicyName == "%s" )' $ECSDEMO_IAM`
THIS_POLICY=$(aws iam list-policies --scope Local | jq -r '.Policies[].PolicyName' | grep $ECSDEMO_IAM)

if [ ! -z $THIS_POLICY ]; then
    echo "Found IAM policy $ECSDEMO_IAM"
else
    echo "Creating an IAM Policy for ECS"
    aws ec2 create-policy --policy-name $ECSDEMO_IAM --cli-input-json $DIRNAME/iam-ecs-policy.json
fi

# get the policy again, and gets its ARN, we need it when we launch our instance

THIS_IAM_POLICY=$(aws iam list-policies --scope Local | jq -r '.Policies[].PolicyName' | grep $ECSDEMO_IAM)
THIS_IAM_POLICY_ARN=$(aws iam list-policies --scope Local | jq "$IAM_MATCH" | jq -r '.Arn')

echo ""
echo "Checking for VPC $ECSDEMO_VPC"

VPC_MATCH=`printf '.Vpcs[] | select(.Tags[0].Value == "%s" )' $ECSDEMO_VPC`
THIS_VPC=$(aws ec2 describe-vpcs --output json | jq "$VPC_MATCH" | jq -r '.VpcId')

if [ ! -z $THIS_VPC ]; then 
    echo "Found vpc $ECSDEMO_VPC"
else
    echo "Creating $ECSDEMO_VPC vpc with cidr block $AWS_VPC_CIDR"
    THIS_VPC=$(aws ec2 create-vpc --cidr-block $AWS_VPC_CIDR | jq -r '.Vpc.VpcId')
    echo "Tagging VPC"
    aws ec2 create-tags --resources $THIS_VPC --tags Key=demo,Value=$ECSDEMO_VPC
    echo "Creating Subnet on the VPC $AWS_VPC_SUBNET_CIDR"
    THIS_SUBNET=$(aws ec2 create-subnet --vpc-id $THIS_VPC --cidr-block $AWS_VPC_SUBNET_CIDR | jq -r '.Subnet.SubnetId') 
    echo "Creating Internet Gateway"
    THIS_IG=$(aws ec2 create-internet-gateway | jq -r '.InternetGateway.InternetGatewayId')
    echo "Attaching Internet Gateway $THIS_IG to VPC $THIS_VPC"
    aws ec2 attach-internet-gateway --internet-gateway-id $THIS_IG --vpc-id $THIS_VPC  
    echo "Creating route table associated with VPC $THIS_VPC"
    THIS_RT=$(aws ec2 create-route-table --vpc-id $THIS_VPC | jq -r '.RouteTable.RouteTableId')
    echo "Adding route 0.0.0.0/0 to $THIS_RT"
    aws ec2 create-route --route-table-id $THIS_RT --destination-cidr-block 0.0.0.0/0 --gateway-id $THIS_IG 
    echo "Associating route table $THIS_RT with subnet $THIS_SUBNET" 
    aws ec2 associate-route-table --route-table-id $THIS_RT --subnet-id $THIS_SUBNET
fi

# Get our subnet id

THIS_SUBNET_ID=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$THIS_VPC" | jq -r '.Subnets[].SubnetId')

THIS_DEMO=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$ECSDEMO_GROUPNAME" | jq -r '.SecurityGroups[].GroupName')

echo ""
echo "Checking for security group $ECSDEMO_GROUPNAME"

if [ ! -z $THIS_DEMO ]; then
    echo "You appear to have a $ECSDEMO_GROUPNAME group setup on AWS already"
else
    echo "Creating security group $ECSDEMO_GROUPNAME"
    aws ec2 create-security-group --vpc-id $THIS_VPC --group-name $ECSDEMO_GROUPNAME --description "Weave Demo"
fi

THIS_GROUPID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$ECSDEMO_GROUPNAME" | jq -r '.SecurityGroups[].GroupId')

echo ""
echo "Update security group, limit ssh to $MY_IP/32, enable http, https and udp and tcp on port 6783"
aws ec2 authorize-security-group-ingress --group-id $THIS_GROUPID --protocol tcp --port 22 --cidr $MY_IP/32
aws ec2 authorize-security-group-ingress --group-id $THIS_GROUPID --protocol tcp --port 80 --cidr $ECSDEMO_CIDR
aws ec2 authorize-security-group-ingress --group-id $THIS_GROUPID --protocol tcp --port 443 --cidr $ECSDEMO_CIDR
aws ec2 authorize-security-group-ingress --group-id $THIS_GROUPID --protocol tcp --port 6783 --cidr $ECSDEMO_CIDR
aws ec2 authorize-security-group-ingress --group-id $THIS_GROUPID --protocol udp --port 6783 --cidr $ECSDEMO_CIDR

echo ""
echo "Generate our keypair"

aws ec2 create-key-pair --key-name $KEYPAIR --query 'KeyMaterial' --output text > $MY_KEY

echo ""
echo "Launch instance"

## Todo ecsDemoRole is just something we have setup, need to confirm its in place
:
AWS_INSTANCE_IDS=$(aws ec2 run-instances --image-id $AWS_AMI --count $ECSDEMO_HOSTCOUNT --instance-type t2.micro --key-name $KEYPAIR --security-group-ids $THIS_GROUPID --subnet-id $THIS_SUBNET_ID --associate-public-ip-address --iam-instance-profile Name=ecsDemoRole | jq -r '.Instances[].InstanceId') 

echo "Getting public IP"
echo "Sleep for 30 seconds to allow addresses to be allocated (we have seen delays here)"
sleep 30

for i in $AWS_INSTANCE_IDS; do
    THIS_IP=$(aws ec2 describe-instances --instance-ids $i | jq -r '.Reservations[].Instances[].PublicIpAddress')
    echo $THIS_IP
done | tee /tmp/demo-ecs-aws-ips.txt

