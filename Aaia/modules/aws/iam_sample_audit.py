
from neo4j.v1 import GraphDatabase
from policyuniverse.policy import Policy

__description__="sample module for auditing iam using Aaia"

audit_cyphers={
 "audit":
	[
		{
		"Query": "match(A:AWSUser) where not (A)-[:Member_Of]->(:AWSGroup) and not (A.UserName='root') with distinct A.UserName as UserName,A.AccountNo  as AccountID,A.AccessKey1Active as AccessKey1Active,A.AccessKey1LastUsedDate as AccessKey1LastUsedDate,A.AccessKey2Active as AccessKey2Active,A.AccessKey2LastUsedDate as AccessKey2LastUsedDate,A.Tags as Tags match (B:AWSAccount) where B.AccountNo=AccountID return UserName,AccountID,B.AccountAlias as AccountName, AccessKey1Active,AccessKey1LastUsedDate,AccessKey2Active,AccessKey2LastUsedDate,Tags",
		
		"Description":"List of Users without Group"
		}
	,
	
		{
		"Query": "match(A:AWSGroup) where not ()-[:Member_Of]->(A) with distinct A.AccountNo as AccountID,A.GroupName as GroupName  match (B:AWSAccount) where B.AccountNo=AccountID return GroupName,AccountID,B.AccountAlias as AccountName",
		
		"Description":"List of Groups without Users"
		}
	,
		
	
	{
		"Query": "match(A:AWSUser) where A.AccessKey1Active = 'true' or A.AccessKey2Active ='true' with distinct A.UserName as UserName,A.AccountNo  as AccountID,A.AccessKey1Active as AccessKey1Active,A.AccessKey1LastUsedDate as AccessKey1LastUsedDate,A.AccessKey2Active as AccessKey2Active,A.AccessKey2LastUsedDate as AccessKey2LastUsedDate,A.Tags as Tags match (B:AWSAccount) where B.AccountNo=AccountID return UserName,AccountID,B.AccountAlias as AccountName,AccessKey1Active,AccessKey1LastUsedDate,AccessKey2Active, AccessKey2LastUsedDate,Tags ",
		
		"Description":"List of users with Active User Keys and day of last rotation "
		}
	,
	
	{
		"Query": "match (P)-[:AWSPolicyAttachment]->()-[D:AWSPolicyStatement]->(R) where D.Action='*' and D.ActionKey='Action' and R.Arn='*' with distinct P.Arn as EntityArn ,P.AccountNo  as AccountID,labels(P) as Type ,D.Condition as Condition ,P.Tags as Tags match (B:AWSAccount) where B.AccountNo=AccountID return  EntityArn,AccountID,B.AccountAlias as AccountName,Type,Condition,Tags",
		
		"Description":"IAM Entities with Admin Permissions"
		}
	,
	
	{
		"Query": "match (A:AWSUser),(policy:AWSPolicy) where (A)-[:AWSPolicyAttachment]->(policy) with distinct A.UserName as UserName,A.AccountNo  as AccountID,labels(policy) as PolicyType,policy.Arn as PolicyArn,policy.PolicyName as PolicyName,A.Tags as Tags match (B:AWSAccount) where B.AccountNo=AccountID return UserName,AccountID,B.AccountAlias as AccountName,PolicyType,PolicyArn,PolicyName,Tags ",
		
		"Description":"Users with direct policy attached"
	}
		
	,
	{
		"Query": "match (user:AWSUser) with user.AccountNo as AccountID,user.Arn as UserArn,user.UserName as UserName,user.Tags as Tags match (B:AWSAccount) where B.AccountNo=AccountID return AccountID,B.AccountAlias as AccountName,UserArn,UserName,Tags",
		
		"Description":"Analysing Users and Tags"
		}
	,
	{
		"Query": "match (policy:AWSPolicy) where not ()-[*]->(policy) with distinct policy.AccountNo as AccountID,policy.Arn as PolicyArn match (B:AWSAccount) where B.AccountNo=AccountID return AccountID,B.AccountAlias as AccountName,PolicyArn",
		
		"Description":"Unused Managed Policies"
	},
	{	"Query": "match (principal:AWSPolicyPrincipal)<-[*]-(role:AWSRole) where principal.Arn =~ '[A-Z0-9]{20,21}' with principal.Arn as PrincipalArn,principal.AccountNo as PrincipalAccountID, role.AccountNo as AccountID, role.Arn as SourceRoleArn match (B:AWSAccount) where B.AccountNo=AccountID return PrincipalArn,PrincipalAccountID,AccountID,B.AccountAlias as AccountName,SourceRoleArn",
		
		"Description":"Policies with Stale / Deleted Policy Principals "
	},
	{	"Query": "match (user:AWSUser) where user.MfaActive='false' with user.UserName as UserName,user.AccountNo as AccountID,user.Arn as UserArn,user.Tags as Tags match (B:AWSAccount) where B.AccountNo=AccountID return UserName,AccountID,B.AccountAlias as AccountName,UserArn,Tags",
		
		"Description":"Users without MFA"
	},
	{	"Query": "match(A:AWSRole) with distinct A.RoleName as RoleName,A.Arn as RoleArn,A.AccountNo  as AccountID match (B:AWSAccount) where B.AccountNo=AccountID return RoleName,RoleArn,AccountID,B.AccountAlias as AccountName",
		
		"Description":"Roles present in AWS Environment"
	}
		
	]
}

def neo4jSessionDriver(config):
	neo4j_uri=config['neo4j_conf']['neo4j_uri']
	neo4j_user=config['neo4j_conf']['neo4j_user']
	neo4j_password=config['neo4j_conf']['neo4j_password']
	neo4j_auth = (neo4j_user, neo4j_password)
	neo4j_driver = GraphDatabase.driver( neo4j_uri, auth=neo4j_auth, encrypted=False)
	
	return(neo4j_driver)

def help():
	pass

def recordToText(record):
	temp_string=""
	for key in record.keys():
		if key=="Actions":

			#Creating a temporary policy_template
			#since policy universe expects a policy object to be passed to it
			#The action identified from Aaia DB will be passed to this template 
			#which will be used to process further to get the summary using policy universe
			policy_template={
								"Statement": [{
									"Action": ["s3:put*", "sqs:get*", "sns:*"],
									"Resource": "*",
									"Effect": "Allow"
									}]
							}
			actions=record[key].replace(" ","").split(",")
			policy_template['Statement'][0]['Action']=actions
			policy=Policy(policy_template)
			for service, summary_action in policy.action_summary().items():
				temp_string+="{"+str(service)+"-"+str(summary_action).replace("{","").replace("}","")+"},"
			
			temp_string+="`"

		else:
			temp_string+=str(record[key])+"`"
	
	return(temp_string.rstrip("`"))

def main(config,args):
	neo4j_driver=neo4jSessionDriver(config)

	with neo4j_driver.session() as neo4j_session:
		for cypher in audit_cyphers['audit']:
		
			#Counter to print the column title
			#This variable will get reset after every new audit check
			first_run=True
			print("\n"+cypher['Description'],"\n")
			output=neo4j_session.run(cypher['Query'])
			for record in output:
			#The column title will print only the first time.
				if first_run:
					temp_title=""
					for key in record.keys():
						temp_title+=key+"`"
					print(temp_title)
					#Resetting the counter to avaoid printing the column titles at every loop
					first_run=False
				rec=recordToText(record)
				print(rec)
			print("\n")
