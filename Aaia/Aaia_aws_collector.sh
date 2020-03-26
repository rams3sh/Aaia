#!/bin/sh

#Usage:- ./Aaia_aws_collector.sh <profile_name> 
# For profile names , you can refer to credentials file within aws folder 

#Capturing the Profile name as part of variable to reference within the functions 
#as the function can have local scope arguments

profile=`echo $1`

mkdir offline_data 2>/dev/null
mkdir ./offline_data/aws 2>/dev/null
mkdir ./offline_data/aws/$profile 2> /dev/null
mkdir ./offline_data/aws/$profile/iam 2>/dev/null
mkdir ./offline_data/aws/$profile/sts 2>/dev/null

#Generating Credential Report , this will be exported by end of all the commands
python3 -m awscli iam generate-credential-report --profile $profile >/dev/null

echo "[*] Running STS get-caller-identity!!"
python3 -m awscli sts get-caller-identity --profile $profile > ./offline_data/aws/$profile/sts/sts-get-caller-identity.json
echo "[*] Running IAM get-account-authorization-details!!"
python3 -m awscli iam get-account-authorization-details --profile $profile > ./offline_data/aws/$profile/iam/iam-get-account-authorization-details.json
echo "[*] Running IAM list-users!!"
python3 -m awscli iam list-users --profile $profile > ./offline_data/aws/$profile/iam/iam-list-users.json
echo "[*] Running IAM get-user!!"
#Creating directory for iam-get-user to store each user's get-user details
mkdir ./offline_data/aws/$profile/iam/iam-get-user 2>/dev/null
for user in `cat ./offline_data/aws/$profile/iam/iam-list-users.json | jq '.Users[].UserName' | cut -d '"' -f2`;do
	python3 -m awscli iam get-user --user-name $user --profile $profile>./offline_data/aws/$profile/iam/iam-get-user/$user
done
echo "[*] Running IAM list-groups!!"
python3 -m awscli iam list-groups --profile $profile >./offline_data/aws/$profile/iam/iam-list-groups.json
echo "[*] Running IAM list-roles!!"
python3 -m awscli iam list-roles --profile $profile >./offline_data/aws/$profile/iam/iam-list-roles.json
echo "[*] Running IAM get-role!!"
#Creating directory for iam-get-role to store each role's get-role details
mkdir ./offline_data/aws/$profile/iam/iam-get-role 2>/dev/null
for role in `cat ./offline_data/aws/$profile/iam/iam-list-roles.json | jq '.Roles[].RoleName' | cut -d '"' -f2`;do
        python3 -m awscli iam get-role --role-name $role --profile $profile>./offline_data/aws/$profile/iam/iam-get-role/$role
done
echo "[*] Running IAM get-policy!!"
#Creating directory for iam-get-policy to store each policy's get-policy details
mkdir ./offline_data/aws/$profile/iam/iam-get-policy 2>/dev/null
for policyArn in `cat ./offline_data/aws/$profile/iam/iam-get-account-authorization-details.json | jq '.Policies[].Arn' | cut -d '"' -f2`;do
        policyname=`echo $policyArn | rev | cut -d"/" -f1 | rev`
	python3 -m awscli iam get-policy --policy-arn $policyArn --profile $profile>./offline_data/aws/$profile/iam/iam-get-policy/$policyname
done

echo "[*] Running IAM get-account-password-policy!!"
python3 -m awscli iam get-account-password-policy --profile $profile > ./offline_data/aws/$profile/iam/iam-get-account-password-policy.json
echo "[*] Running IAM get-account-summary!!"
python3 -m awscli iam get-account-summary --profile $profile > ./offline_data/aws/$profile/iam/iam-get-account-summary.json
echo "[*] Running IAM list-account-aliases!!"
python3 -m awscli iam list-account-aliases --profile $profile > ./offline_data/aws/$profile/iam/iam-list-account-aliases.json
echo "[*] Running IAM get-credential-report!!"
python3 -m awscli iam get-credential-report --profile $profile > ./offline_data/aws/$profile/iam/iam-get-credential-report.json



#Function to get details for recursive OU Structure
identifyOU(){
		local parentid=`echo $1 | cut -d '"' -f2`
		
		#Making Directory Structure in the form of OU structure
		mkdir $2/$parentid 2>/dev/null

		#Current Path
		local path=`echo $2/$parentid`
		
		#Getting the Account List under the given OU
		echo "[*] Running ORGANIZATIONS list-accounts-for-parent under the OU -"$1
		python3 -m awscli organizations list-accounts-for-parent --parent-id $parentid  --profile $profile >$path/organizations-list-accounts-for-parent.json
		
		#Getting the Sub-OUs under the Parent OU
		echo "[*] Running ORGANIZATIONS list-organizational-units-for-parent for the OU -"$1
		python3 -m awscli organizations list-organizational-units-for-parent --parent-id $parentid --profile $profile > $path/organizations-list-organizational-units-for-parent.json
		
        for ou in `cat $path/organizations-list-organizational-units-for-parent.json | jq '.OrganizationalUnits[].Id'`;do
            identifyOU $ou $path
		done
}



#Creating Organizations folder under the profile folder for maintaining the OU structure
mkdir ./offline_data/aws/$profile/organizations 2>/dev/null
#Creating ou_tree folder under the organizations folder for maintaining the OU structure
mkdir ./offline_data/aws/$profile/organizations/ou_tree 2>/dev/null

echo "[*] Running ORGANIZATIONS  describe-organization!!"
python3 -m awscli organizations describe-organization --profile $profile > ./offline_data/aws/$profile/organizations/organizations-describe-organization.json

echo "[*] Running ORGANIZATIONS  list-roots!!"
python3 -m awscli organizations list-roots --profile $profile > ./offline_data/aws/$profile/organizations/organizations-list-roots.json

echo "[*] Running ORGANIZATIONS  list-accounts!!"
python3 -m awscli organizations list-accounts --profile $profile > ./offline_data/aws/$profile/organizations/organizations-list-accounts.json

#Getting the tags attached to the Accounts
echo "[*] Running ORGANIZATIONS list-tags-for-resource for Accounts under OU -"$1
mkdir ./offline_data/aws/$profile/organizations/organizations-list-tags-for-resource 2>/dev/null
for account in `cat ./offline_data/aws/$profile/organizations/organizations-list-accounts.json | jq '.Accounts[].Id'`;do
	id=`echo $account | cut -d '"' -f2`
	python3 -m awscli organizations list-tags-for-resource --resource-id $id --profile $profile >./offline_data/aws/$profile/organizations/organizations-list-tags-for-resource/$id
done

echo "[*] Running ORGANIZATIONS  list-policies!!"
python3 -m awscli organizations list-policies --filter SERVICE_CONTROL_POLICY --profile $profile > ./offline_data/aws/$profile/organizations/organizations-list-policies.json

#Finding targets of the corresponding policy
mkdir ./offline_data/aws/$profile/organizations/organizations-list-targets-for-policy 2>/dev/null
echo "[*] Running ORGANIZATIONS  list-targets-for-policy for corresponding policy!!"
for policy in `cat ./offline_data/aws/$profile/organizations/organizations-list-policies.json | jq '.Policies[].Id' `;do
	id=`echo $policy | cut -d '"' -f2`
	python3 -m awscli organizations list-targets-for-policy --policy-id $id  --profile $profile> ./offline_data/aws/$profile/organizations/organizations-list-targets-for-policy/$id
done

#Describing Policy of the corresponding policy
mkdir ./offline_data/aws/$profile/organizations/organizations-describe-policy 2>/dev/null
echo "[*] Running ORGANIZATIONS  describe-policy for corresponding policy!!"
for policy in `cat ./offline_data/aws/$profile/organizations/organizations-list-policies.json | jq '.Policies[].Id' `;do
	id=`echo $policy | cut -d '"' -f2`
	python3 -m awscli organizations describe-policy --policy-id $id --profile $profile > ./offline_data/aws/$profile/organizations/organizations-describe-policy/$id
done

echo "[*] Running ORGANIZATIONS list-aws-service-access-for-organization !!"
python3 -m awscli organizations list-aws-service-access-for-organization --profile $profile > ./offline_data/aws/$profile/organizations/organizations-list-aws-service-access-for-organization.json

echo "[*] Running ORGANIZATIONS list-organizational-units-for-parent for the Root !!"
for root in `cat ./offline_data/aws/$1/organizations/organizations-list-roots.json | jq '.Roots[].Id' `;do
	root_path=`echo ./offline_data/aws/$1/organizations/ou_tree`
    identifyOU $root $root_path
done


