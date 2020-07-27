from neo4j import GraphDatabase
from collections import OrderedDict
import pyjq
import json
import logging
from policyuniverse import arn
import re
import os
import base64
from io import StringIO
import csv
import sys
from lib.aws_common import getPolicyDocumentDetails,getPolicyStatementDetails


__description__="loads the aws iam details into neo4j instance"

logging.basicConfig()
logger=logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def customCamelcase(string):
	#Changes the snakcase to camel case and replaces the first character with the capital version of it
	#https://stackoverflow.com/a/54931135
	camel_case=re.sub(r'_([a-z])', lambda x: x.group(1).upper(), string)
	ret=camel_case[0].upper()+camel_case[1::]
	return ret.replace("_","")

def getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery):
	logger.debug("[*] Getting AWS data from '%s' for AWS Account '%s' for jq Query '%s'",data_path+account_name+'/iam/iam-get-account-authorization-details.json',account_name,jqQuery)
	with open(os.path.join(data_path,account_name,'iam','iam-get-account-authorization-details.json'),'r') as filein:
		file_content=json.loads(filein.read())
	logger.debug("[*] Completed getting AWS data from '%s' for AWS Account '%s' for jq Query '%s'",data_path+account_name+'/iam/iam-get-account-authorization-details.json',account_name,jqQuery)
	return pyjq.all(jqQuery,file_content)

def getAWSManagedPolicies(data_path,account_name):
	jqQuery='.Policies[] | {Arn : .Arn, AttachmentCount: .AttachmentCount, CreateDate: .CreateDate,  DefaultVersionId: .DefaultVersionId,IsAttachable: .IsAttachable,Path: .Path, PermissionsBoundaryUsageCount: .PermissionsBoundaryUsageCount, PolicyId: .PolicyId, PolicyName: .PolicyName, UpdateDate: .UpdateDate}'
	
	data=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery)
	
	#IAM Account Authorization Details does not have Descriptionof the policy.
	#Hence taking it from iam-get-policy
	
	jqQuery='.Policy.Description'
	for policy_data in data:
	
		with open (os.path.join(data_path,account_name,'iam',"iam-get-policy",policy_data['Arn'].split("/")[-1])) as filein:
			file_content=json.loads(filein.read())
		policy_description=pyjq.all(jqQuery,file_content)
		if policy_description[0]:
			policy_data.__setitem__('Description',policy_description[0])
		else:
			policy_data.__setitem__('Description',"")
	
	return data

def getAWSManagedPolicyVersions(data_path,account_name,policy_arn):
	jqQuery='.Policies[] | select (.Arn == \"'+policy_arn+'\") .PolicyVersionList[]'
	
	data=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery)
	return data

	
def loadAWSManagedPolicies(neo4j_session,data_path,account_name):
	logger.info("[*] Loading AWS Managed Policies into neo4j instance for AWS account '%s'",account_name)
	ingest_aws_managed_policies='''merge (A:AWSPolicy  {Arn :$Arn } ) 
								on create set A.AccountNo= $AccountNo,
								A.AttachmentCount=$AttachmentCount,
								A.CreateDate=datetime($CreateDate), 
								A.DefaultVersionId=$DefaultVersionId, 
								A.IsAttachable=$IsAttachable,
								A.Path =$Path, 
								A.PermissionsBoundaryUsageCount=$PermissionsBoundaryUsageCount,
								A.PolicyId=$PolicyId, 
								A.PolicyName=$PolicyName, 
								A.Description=$Description,
								A.UpdateDate=datetime($UpdateDate)
								on match set A.AccountNo=$AccountNo,
								A.AttachmentCount=$AttachmentCount,
								A.CreateDate=datetime($CreateDate), 
								A.DefaultVersionId=$DefaultVersionId, 
								A.IsAttachable=$IsAttachable,
								A.Path =$Path, 
								A.PermissionsBoundaryUsageCount=$PermissionsBoundaryUsageCount,
								A.PolicyId=$PolicyId, 
								A.PolicyName=$PolicyName, 
								A.UpdateDate=datetime($UpdateDate)'''
						
	managed_policies=getAWSManagedPolicies(data_path,account_name)
	
	for policy in managed_policies:
		#Creating AWS Managed Policy Nodes
		neo4j_session.run(ingest_aws_managed_policies,Arn=policy['Arn'],AccountNo=policy['Arn'].split(":")[4],AttachmentCount=policy['AttachmentCount'],CreateDate=policy['CreateDate'],DefaultVersionId=policy['DefaultVersionId'],IsAttachable=policy['IsAttachable'],Path=policy['Path'],PermissionsBoundaryUsageCount=policy['PermissionsBoundaryUsageCount'],PolicyId=policy['PolicyId'],PolicyName=policy['PolicyName'],Description=policy['Description'],UpdateDate=policy['UpdateDate'])
		
		
		#Creating the Relationships between Policy Nodes and respective Resources (resources will be created if not present)
		ingest_policy_statements='''	
								merge (C {Arn:$ResourceArn}) set C:AWSPolicyResource  
								with C match (B:AWSPolicy),(C:AWSPolicyResource) 
								where B.Arn=$Arn and C.Arn=$ResourceArn with B,C 
								merge (B)-[A:AWSPolicyStatement {VersionId:$VersionId}]->(C) 
								on create set 
								A.SourcePolicyArn=$Arn,
								A.VersionCreateDate=datetime($VersionCreateDate),
								A.IsDefaultVersion=$IsDefaultVersion,
								A.VersionId=$VersionId,
								A.DocumentVersion=$DocumentVersion,
								A.DocumentId=$DocumentId,
								A.Effect=$Effect ,
								A.ActionKey=$ActionKey,
								A.Action=$Action,
								A.Condition=$Condition,
								A.Sid=$Sid,
								A.ResourceKey=$ResourceKey,
								A.Resource=$Resource,
								A.Principal=$Principal,
								A.PrincipalKey=$PrincipalKey,
								A.Aaia_ExpandedAction=$Aaia_ExpandedAction
								on match set 
								A.SourcePolicyArn=$Arn,
								A.VersionCreateDate=datetime($VersionCreateDate),
								A.IsDefaultVersion=$IsDefaultVersion,
								A.VersionId=$VersionId,
								A.DocumentVersion=$DocumentVersion,
								A.DocumentId=$DocumentId,
								A.Effect=$Effect ,
								A.ActionKey=$ActionKey,
								A.Action=$Action,
								A.Condition=$Condition,
								A.Sid=$Sid,
								A.ResourceKey=$ResourceKey,
								A.Resource=$Resource,
								A.Principal=$Principal,
								A.PrincipalKey=$PrincipalKey,
								A.Aaia_ExpandedAction=$Aaia_ExpandedAction
								'''
		#Getting the Policy Versions of each AWS Managed Policy
		aws_managed_policy_version_list=getAWSManagedPolicyVersions(data_path,account_name,policy['Arn'])
		
		for policy_version in aws_managed_policy_version_list:
			policy_version_createdate=policy_version['CreateDate']
			policy_version_isdefaultversion=policy_version['IsDefaultVersion']
			policy_version_versionid=policy_version['VersionId']
			policy_document_details=getPolicyDocumentDetails(policy_version['Document'])
		
			for statement in policy_document_details['Statement']:
				policy_statement_details=getPolicyStatementDetails(statement)
				
				#Since empty Principal / Action / Resource is returned as set 
				#Stringifying it in query run below will result in value as 'set()'.
				#The following is to avoid it
				statement_principal=policy_statement_details['Principal']
				statement_action=policy_statement_details['Action']
				statement_resource=policy_statement_details['Resource']
				if statement_principal==set():
					statement_principal=""
				if statement_action==set():
					statement_action=""
				if statement_resource==set():
					statement_resource=""
					
				for resource in policy_statement_details['Resource']:
									
					neo4j_session.run(ingest_policy_statements,Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],ResourceArn=resource,Arn=policy['Arn'],VersionId=policy_version_versionid,VersionCreateDate=policy_version_createdate,IsDefaultVersion=policy_version_isdefaultversion,DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("[","").replace("]","").replace("{","").replace("}","").replace("'",""),Condition=str(policy_statement_details['Condition']),Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("[","").replace("]","").replace("{","").replace("}","").replace("'",""),Principal=str(statement_principal).replace("[","").replace("]","").replace("{","").replace("}","").replace("'",""),PrincipalKey=policy_statement_details['PrincipalKey'])
			
			if policy_version_isdefaultversion==True:
				managed_policy_document_info_update_query='''merge (A:AWSPolicy {Arn:$Arn})  
															set A.DefaultDocumentId=$DocumentId,
															A.DefaultDocumentVersion=$DocumentVersion
															'''
				neo4j_session.run(managed_policy_document_info_update_query,Arn=policy['Arn'],DocumentId=policy_document_details['Id'],DocumentVersion=policy_document_details['Version'])
				
	
	logger.info("[*] Completed loading AWS Managed Policies into neo4j instance for AWS account '%s'",account_name)


def getPermissionBoundaryPolicyArn(data_path,account_name,iam_resource_type,principal_name):
	jqQuery="."+iam_resource_type+".PermissionsBoundary.PermissionsBoundaryArn?"
	with open(os.path.join(data_path,account_name,'iam','iam-get-'+iam_resource_type.lower(),principal_name),'r') as filein:
		data=json.loads(filein.read())
	policy_arn=pyjq.all(jqQuery,data)
	if policy_arn==[None]:
		policy_arn=None
	return(policy_arn)	

def loadPermissionBoundary(neo4j_session,data_path,account_name,principal_arn):

	#Permissions Boundary are Managed Policies
	#Hence does'nt require processing of any policy document
	#It is just a matter of creating a relationship to an existing AWSManagedPolicy Node
	if principal_arn.__contains__("user/"):
		principal_name=principal_arn.split("/")[-1]
		policy_arns=getPermissionBoundaryPolicyArn(data_path,account_name,"User",principal_name)
		load_permission_boundary='''match (user:AWSUser) where user.Arn=$PrincipalArn with user
									match (policy:AWSPolicy) where policy.Arn=$PolicyArn with user,policy
									merge (user)-[:AWSPolicyAttachment]->(policy)'''
	elif principal_arn.__contains__("role/"):
		principal_name=principal_arn.split("/")[-1]
		policy_arns=getPermissionBoundaryPolicyArn(data_path,account_name,"Role",principal_name)
		load_permission_boundary='''match (role:AWSRole) where role.Arn=$PrincipalArn with role
									match (policy:AWSPolicy) where policy.Arn=$PolicyArn with role,policy
									merge (role)-[:AWSPolicyAttachment]->(policy)'''
	if policy_arns:
		# getPermissionBoundaryPolicyArn returns the policy_arn in list. Wuld keep it as list so as to support 
		# multiple managed policies being kept as boundary policy (if supported) in future. Hence "for" loop.
		# Either ways there is'nt much harm in keeping this as is.
		for policy_arn in policy_arns:
			neo4j_session.run(load_permission_boundary,PrincipalArn=principal_arn,PolicyArn=policy_arn)

def getAWSUsers(data_path,account_name):
	logger.debug("[*] Getting AWS User data from '%s' for AWS Account '%s'",data_path+account_name+'/iam/iam-list-users.json',account_name) 

	data=OrderedDict()
	# #For every user in iam-list-users, get the UserName,ARN,UserId,CreateDate,PasswordLastUsed,Path properties
	# #and append to the data variable
	
	#Reason for using iam-list-users instead of iam-account-authorization-details is because it has PasswordLastUsed information which is not present in the latter.
	
	with open(os.path.join(data_path,account_name,'iam','iam-list-users.json'),'r') as filein:
		file_content=json.loads(filein.read())
				
	jqQuery='.Users[] | { UserName : .UserName, Arn: .Arn, UserId: .UserId, CreateDate: .CreateDate, PasswordLastUsed: .PasswordLastUsed,Tags : .Tags, Path: .Path}'
	
	data=pyjq.all(jqQuery,file_content)
	
	#iam-list-users does not have tags as part of the details. Hence this is being taken from 
	#iam-account-authorization-details and inserted as part of the OrderedDictionary
	
	jqQuery='.UserDetailList[] | select(.UserName == "<Replace_UserName>") | .Tags[]'
	for user_data in data:
		user_tags=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery.replace("<Replace_UserName>",user_data['UserName']))
		user_data.__setitem__('Tags',str(json.dumps(user_tags)))

	logger.debug("[*] Completed getting AWS User data from '%s' for AWS Account '%s'",data_path+account_name+'/iam/iam-list-users.json',account_name) 

	return data

def getCredentialReportDetails(data_path,account_name,user_arn):
		with open(os.path.join(data_path,account_name,'iam','iam-get-credential-report.json'),'r') as filein:
			file_content=json.loads(filein.read())
		
		credential_report=base64.b64decode(file_content['Content'])
		#Converting Bytes to String
		credential_report=credential_report.decode("utf-8")
		data=StringIO(credential_report)   
		reader = csv.DictReader(data, delimiter=',')
		
		for row in reader:
			if row['arn']==user_arn:
				record=OrderedDict()
				for key in row.keys():
					if key in ['user_creation_time','password_last_used','password_last_changed','password_next_rotation','access_key_1_last_rotated','access_key_1_last_used_date','access_key_2_last_rotated','access_key_2_last_used_date','cert_1_last_rotated','cert_2_last_rotated']:
					#For root user , password_enabled,password_last_changed,password_next_rotation is always not_supported . 
					#Hence included it in the below condition 
					#password_last_used is "no_information" , if the user has never logged in using the password
					#In case the value is N/A , it means the user does not have that password / access key depending on context
					#Source:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html

						if row[key]=="N/A" or row[key]=="not_supported" or row[key]=="no_information":
							record.__setitem__(customCamelcase(key),row[key])
						else:
							#By default AWS has +00:00 offset in ISO 8601 time format. This technically
							#means there is no additional offset to the existing time.
							#Since we cant have a cypher query with datetime function to modify the time
							#due to possibility of non-date values as mentioned in the above if condition
							#we are converting it into an UTC format here by using the below hack

							utc_format=row[key].split("+")[0]+"Z"
							record.__setitem__(customCamelcase(key),utc_format)
					else:
						record.__setitem__(customCamelcase(key),row[key])

				return record
				
def loadAWSUserNodes(neo4j_session,data_path,account_name):
	logger.info("[*] Loading AWS Users into neo4j instance for AWS account '%s'",account_name)

	#Unlike cypher queries in other functions , we do not use datetime here
	#as we get many non-date values in some keys such as password_last_changed etc.
	#The values range from 'N/A','no_information','not_supported' and normal ISO 8601 date format
	#Source : https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
	#Hence the date format is already processed and returned as part of the getAWSUserNodes function

	#Creating User Nodes
	ingest_aws_users='''merge (A:AWSUser {Arn :$Arn}) 
						on match set A.UserName=$UserName, 
						A.AccountNo=$AccountNo, 
						A.UserId=$UserId,
						A.CreateDate=$CreateDate, 
						A.PasswordLastUsed=$PasswordLastUsed,
						A.Tags=$Tags, 
						A.Path=$Path,
						A.PasswordEnabled=$PasswordEnabled,
						A.PasswordLastChanged=$PasswordLastChanged,
						A.PasswordNextRotation=$PasswordNextRotation,
						A.MfaActive=$MfaActive,
						A.AccessKey1Active=$AccessKey1Active,
						A.AccessKey1LastRotated=$AccessKey1LastRotated,
						A.AccessKey1LastUsedDate=$AccessKey1LastUsedDate,
						A.AccessKey1LastUsedRegion=$AccessKey1LastUsedRegion,
						A.AccessKey1LastUsedService=$AccessKey1LastUsedService,
						A.AccessKey2Active=$AccessKey2Active,
						A.AccessKey2LastRotated=$AccessKey2LastRotated,
						A.AccessKey2LastUsedDate=$AccessKey2LastUsedDate,
						A.AccessKey2LastUsedRegion=$AccessKey2LastUsedRegion,
						A.AccessKey2LastUsedService=$AccessKey2LastUsedService,
						A.Cert1Active=$Cert1Active,
						A.Cert1LastRotated=$Cert1LastRotated,
						A.Cert2Active=$Cert2Active,
						A.Cert2LastRotated=$Cert2LastRotated
						on create set A.UserName=$UserName, 
						A.AccountNo=$AccountNo, 
						A.UserId=$UserId,
						A.CreateDate=$CreateDate, 
						A.PasswordLastUsed=$PasswordLastUsed,
						A.Tags=$Tags, 
						A.Path=$Path,
						A.PasswordEnabled=$PasswordEnabled,
						A.PasswordLastChanged=$PasswordLastChanged,
						A.PasswordNextRotation=$PasswordNextRotation,
						A.MfaActive=$MfaActive,
						A.AccessKey1Active=$AccessKey1Active,
						A.AccessKey1LastRotated=$AccessKey1LastRotated,
						A.AccessKey1LastUsedDate=$AccessKey1LastUsedDate,
						A.AccessKey1LastUsedRegion=$AccessKey1LastUsedRegion,
						A.AccessKey1LastUsedService=$AccessKey1LastUsedService,
						A.AccessKey2Active=$AccessKey2Active,
						A.AccessKey2LastRotated=$AccessKey2LastRotated,
						A.AccessKey2LastUsedDate=$AccessKey2LastUsedDate,
						A.AccessKey2LastUsedRegion=$AccessKey2LastUsedRegion,
						A.AccessKey2LastUsedService=$AccessKey2LastUsedService,
						A.Cert1Active=$Cert1Active,
						A.Cert1LastRotated=$Cert1LastRotated,
						A.Cert2Active=$Cert2Active,
						A.Cert2LastRotated=$Cert2LastRotated'''

	#Getting the user data from collected json exports
	users_data=getAWSUsers(data_path,account_name)
	
	#For every record of users' data , create an user node with relevant properties in neo4j
	for user_data in users_data:
		logger.debug("[*] Loading of AWS User '%s' into neo4j for AWS account '%s' ",user_data['UserName'],account_name)
		credential_report_data=getCredentialReportDetails(data_path,account_name,user_data['Arn'])
		#Tags has been converted to json and then to string as neo4j does not support multiple values for a single 
		#key

		neo4j_session.run(ingest_aws_users,
						  UserName=user_data['UserName'],
						  AccountNo=str(user_data['Arn'].split(":")[4]),
						  Arn=user_data['Arn'],UserId=user_data['UserId'],
						  CreateDate=user_data['CreateDate'],
						  PasswordLastUsed=credential_report_data['PasswordLastUsed'],
						  Tags=str(json.dumps(user_data['Tags'])).replace("null",""),
						  Path=user_data['Path'],
						  PasswordEnabled=credential_report_data['PasswordEnabled'],
						  PasswordLastChanged=credential_report_data['PasswordLastChanged'],
						  PasswordNextRotation=credential_report_data['PasswordNextRotation'],
						  MfaActive=credential_report_data['MfaActive'],
						  AccessKey1Active=credential_report_data['AccessKey1Active'],
						  AccessKey1LastRotated=credential_report_data['AccessKey1LastRotated'],
						  AccessKey1LastUsedDate=credential_report_data['AccessKey1LastUsedDate'],
						  AccessKey1LastUsedRegion=credential_report_data['AccessKey1LastUsedRegion'],
						  AccessKey1LastUsedService=credential_report_data['AccessKey1LastUsedService'],
						  AccessKey2Active=credential_report_data['AccessKey2Active'],
						  AccessKey2LastRotated=credential_report_data['AccessKey2LastRotated'],
						  AccessKey2LastUsedDate=credential_report_data['AccessKey2LastUsedDate'],
						  AccessKey2LastUsedRegion=credential_report_data['AccessKey2LastUsedRegion'],
						  AccessKey2LastUsedService=credential_report_data['AccessKey2LastUsedService'],
						  Cert1Active=credential_report_data['Cert1Active'],
						  Cert1LastRotated=credential_report_data['Cert1LastRotated'],
						  Cert2Active=credential_report_data['Cert2Active'],
						  Cert2LastRotated=credential_report_data['Cert2LastRotated'])
		logger.debug("[*] Completed loading of AWS User '%s' into neo4j for AWS account '%s' ",user_data['UserName'],account_name)
		
		#Loading Permission Boundary (if it exists)
		loadPermissionBoundary(neo4j_session,data_path,account_name,user_data['Arn'])
		
	#Root user is not part of iam-list-users. This is part of Credential Report.
	#For the sake of completeness. Loading the root user separately.
	#Please note root user is never directly referenced as part of IAM Policies
	#By default root user is admin for the acount
	#Whenever root is referenced in AWS IAM Role Policy , it refers to entire AWS Account and the not root user.
	#This node will not have any relations apart from Belongs_to to the AWSACcount
	logger.debug("[*] Loading of AWS User '%s' into neo4j for AWS account 'root' ",account_name)
	account_number=getAWSAccountNo(data_path,account_name)
	root_arn="arn:aws:iam::"+str(account_number)+":root"
	credential_report_data=getCredentialReportDetails(data_path,account_name,root_arn)
	#Creating User Root
	ingest_aws_root_user='''merge (A:AWSUser:AWSRoot {Arn :$Arn}) 
						on match set A.UserName=$UserName, 
						A.AccountNo=$AccountNo, 
						A.UserId=$UserId,
						A.CreateDate=$CreateDate, 
						A.PasswordLastUsed=$PasswordLastUsed,
						A.Tags=$Tags, 
						A.Path=$Path,
						A.PasswordEnabled=$PasswordEnabled,
						A.PasswordLastChanged=$PasswordLastChanged,
						A.PasswordNextRotation=$PasswordNextRotation,
						A.MfaActive=$MfaActive,
						A.AccessKey1Active=$AccessKey1Active,
						A.AccessKey1LastRotated=$AccessKey1LastRotated,
						A.AccessKey1LastUsedDate=$AccessKey1LastUsedDate,
						A.AccessKey1LastUsedRegion=$AccessKey1LastUsedRegion,
						A.AccessKey1LastUsedService=$AccessKey1LastUsedService,
						A.AccessKey2Active=$AccessKey2Active,
						A.AccessKey2LastRotated=$AccessKey2LastRotated,
						A.AccessKey2LastUsedDate=$AccessKey2LastUsedDate,
						A.AccessKey2LastUsedRegion=$AccessKey2LastUsedRegion,
						A.AccessKey2LastUsedService=$AccessKey2LastUsedService,
						A.Cert1Active=$Cert1Active,
						A.Cert1LastRotated=$Cert1LastRotated,
						A.Cert2Active=$Cert2Active,
						A.Cert2LastRotated=$Cert2LastRotated
						on create set A.UserName=$UserName, 
						A.AccountNo=$AccountNo, 
						A.UserId=$UserId,
						A.CreateDate=$CreateDate, 
						A.PasswordLastUsed=$PasswordLastUsed,
						A.Tags=$Tags, 
						A.Path=$Path,
						A.PasswordEnabled=$PasswordEnabled,
						A.PasswordLastChanged=$PasswordLastChanged,
						A.PasswordNextRotation=$PasswordNextRotation,
						A.MfaActive=$MfaActive,
						A.AccessKey1Active=$AccessKey1Active,
						A.AccessKey1LastRotated=$AccessKey1LastRotated,
						A.AccessKey1LastUsedDate=$AccessKey1LastUsedDate,
						A.AccessKey1LastUsedRegion=$AccessKey1LastUsedRegion,
						A.AccessKey1LastUsedService=$AccessKey1LastUsedService,
						A.AccessKey2Active=$AccessKey2Active,
						A.AccessKey2LastRotated=$AccessKey2LastRotated,
						A.AccessKey2LastUsedDate=$AccessKey2LastUsedDate,
						A.AccessKey2LastUsedRegion=$AccessKey2LastUsedRegion,
						A.AccessKey2LastUsedService=$AccessKey2LastUsedService,
						A.Cert1Active=$Cert1Active,
						A.Cert1LastRotated=$Cert1LastRotated,
						A.Cert2Active=$Cert2Active,
						A.Cert2LastRotated=$Cert2LastRotated'''
	neo4j_session.run(ingest_aws_root_user,
		Arn=root_arn,
		UserName="root",
		AccountNo=account_number,
		UserId="",
		CreateDate=credential_report_data['UserCreationTime'],
		PasswordLastUsed=credential_report_data['PasswordLastUsed'],
		Tags="",
		Path="",
		PasswordEnabled=credential_report_data['PasswordEnabled'],
		PasswordLastChanged=credential_report_data['PasswordLastChanged'],
		PasswordNextRotation=credential_report_data['PasswordNextRotation'],
		MfaActive=credential_report_data['MfaActive'],
		AccessKey1Active=credential_report_data['AccessKey1Active'],
		AccessKey1LastRotated=credential_report_data['AccessKey1LastRotated'],
		AccessKey1LastUsedDate=credential_report_data['AccessKey1LastUsedDate'],
		AccessKey1LastUsedRegion=credential_report_data['AccessKey1LastUsedRegion'],
		AccessKey1LastUsedService=credential_report_data['AccessKey1LastUsedService'],
		AccessKey2Active=credential_report_data['AccessKey2Active'],
		AccessKey2LastRotated=credential_report_data['AccessKey2LastRotated'],
		AccessKey2LastUsedDate=credential_report_data['AccessKey2LastUsedDate'],
		AccessKey2LastUsedRegion=credential_report_data['AccessKey2LastUsedRegion'],
		AccessKey2LastUsedService=credential_report_data['AccessKey2LastUsedService'],
		Cert1Active=credential_report_data['Cert1Active'],
		Cert1LastRotated=credential_report_data['Cert1LastRotated'],
		Cert2Active=credential_report_data['Cert2Active'],
		Cert2LastRotated=credential_report_data['Cert2LastRotated'])
	logger.debug("[*] Completed loading of AWS User 'root' into neo4j for AWS account '%s' ",account_name)

	logger.info("[*] Completed loading of AWS Users into neo4j instance for AWS account '%s'", account_name)
						
def loadAWSManagedPolicyRelations(neo4j_session,data_path,account_name,iam_resource_type):

	logger.info("[*] Establishing "+iam_resource_type+" relations with AWS Managed Policies into neo4j instance for AWS account '%s'",account_name)
	ingest_aws_managed_policy_relations='''match (A:AWSPolicy) where A.Arn=$Arn 
										with A match (B) where B.Arn=$PrincipalArn 
										with A,B merge (B)-[:AWSPolicyAttachment]->(A)'''

	jqQuery=""
	if iam_resource_type=="Role":
		jqQuery='.RoleDetailList[] | .Arn'
	elif iam_resource_type=="Group":
		jqQuery='.GroupDetailList[] | .Arn'
	elif iam_resource_type=="User":
		jqQuery='.UserDetailList[] | .Arn'

	iam_resource_arns=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery)
	
	jqQuery=""	
	if iam_resource_type=="Role":
		jqQuery='.RoleDetailList[] | select(.Arn=="#Arn#") | .AttachedManagedPolicies[].PolicyArn'
	elif iam_resource_type=="Group":
		jqQuery='.GroupDetailList[] | select(.Arn=="#Arn#") | .AttachedManagedPolicies[].PolicyArn'
	elif iam_resource_type=="User":
		jqQuery='.UserDetailList[] | select(.Arn=="#Arn#") | .AttachedManagedPolicies[].PolicyArn'
		
		
	for iam_resource_arn in iam_resource_arns:
		attached_managed_policy_arns=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery.replace("#Arn#",iam_resource_arn))
		for arn in attached_managed_policy_arns:
			neo4j_session.run(ingest_aws_managed_policy_relations,Arn=arn,PrincipalArn=iam_resource_arn)
	logger.info("[*] Completed establishing "+iam_resource_type+" relations with AWS Managed Policies into neo4j instance for AWS account '%s'",account_name)

def getAWSInlinePolicies(data_path,account_name,iam_resource_type,resource_arn):
	jqQuery=""
	if iam_resource_type=="Role":
		jqQuery='.RoleDetailList[] | select(.Arn=="'+resource_arn+'") | .RolePolicyList[]?'
	elif iam_resource_type=="Group":
		jqQuery='.GroupDetailList[] | select(.Arn=="'+resource_arn+'") | .GroupPolicyList[]?'
	elif iam_resource_type=="User":
		jqQuery='.UserDetailList[] | select(.Arn=="'+resource_arn+'") | .UserPolicyList[]?'
	
	data=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery)
	return data	

	
def loadAWSInlinePolicies(neo4j_session,data_path,account_name,iam_resource_type):
	logger.info("[*] Loading AWS "+iam_resource_type+" Inline Policies into neo4j instance for AWS account '%s'",account_name)

	ingest_aws_inline_policies='''merge (A:AWSPolicy:AWSInlinePolicy 
								{PolicyName: $PolicyName,
								SourceResourceArn: $SourceResourceArn, 
								SourceResourceType: $SourceResourceType,
								DocumentVersion:$DocumentVersion,
								DocumentId:$DocumentId}) 
								with A merge (C {Arn: $ResourceArn}) set C:AWSPolicyResource 
								with A,C 
								merge (A)-[B:AWSPolicyStatement{
								DocumentVersion:$DocumentVersion,
								DocumentId: $DocumentId,
								Effect: $Effect ,
								ActionKey:$ActionKey,
								Action:$Action,
								Condition:$Condition,
								Sid:$Sid,
								ResourceKey:$ResourceKey,
								Resource:$Resource,
								Principal:$Principal,
								PrincipalKey:$PrincipalKey,
								Aaia_ExpandedAction: $Aaia_ExpandedAction}]->(C)
								'''
	#For Finding Resource Arns which has Inline Policy Applicable to it 
	jqQuery=""
	if iam_resource_type=="Role":
		jqQuery='.RoleDetailList[] | .Arn'
	elif iam_resource_type=="Group":
		jqQuery='.GroupDetailList[] | .Arn'
	elif iam_resource_type=="User":
		jqQuery='.UserDetailList[] | .Arn'
	
	#Getting the List of Arns of all resources of given resource type
	iam_resource_arns=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery)
	
	for iam_resource_arn in iam_resource_arns:
		inline_policies=getAWSInlinePolicies(data_path,account_name,iam_resource_type,iam_resource_arn)
		
		for inline_policy in inline_policies:
			policy_name=inline_policy['PolicyName']
			policy_document_details=getPolicyDocumentDetails(inline_policy['PolicyDocument'])
				
			for statement in policy_document_details['Statement']:
				policy_statement_details=getPolicyStatementDetails(statement)
				statement_principal=policy_statement_details['Principal']
				statement_action=policy_statement_details['Action']
				statement_resource=policy_statement_details['Resource']
				#Since empty Principal / Action / Resource is returned as set 
				#Stringifying it in query run below will result in value as 'set()'.
				#The following is to avoid it
				
				if statement_principal==set():
					statement_principal=""
				if statement_action==set():
					statement_action=""
				if statement_resource==set():
					statement_resource=""
				

				for resource in policy_statement_details['Resource']:
					neo4j_session.run(ingest_aws_inline_policies,Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],PolicyName=policy_name,SourceResourceArn=iam_resource_arn,SourceResourceType=iam_resource_type,ResourceArn=resource,DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("[","").replace("]","").replace("{","").replace("}","").replace("'",""),Condition=str(policy_statement_details['Condition']),Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("[","").replace("]","").replace("{","").replace("}","").replace("'",""),Principal=str(statement_principal).replace("[","").replace("]","").replace("{","").replace("}","").replace("'",""),PrincipalKey=policy_statement_details['PrincipalKey'])
		
		#Match all the inline policies with respective SourceResource Arns
		ingest_relationship_between_inlinePolicy_and_iamResourcearn='''match (A),(B:AWSInlinePolicy) where A.Arn = $Arn and B.SourceResourceArn=$Arn with A,B merge (A)-[:AWSPolicyAttachment]->(B) set B.AccountNo=A.AccountNo'''
	
		neo4j_session.run(ingest_relationship_between_inlinePolicy_and_iamResourcearn,Arn=iam_resource_arn)
		
	logger.info("[*] Completed loading AWS "+iam_resource_type+" Inline Policies into neo4j instance for AWS account '%s'",account_name)	


def getAWSGroups(data_path,account_name):
	logger.debug("[*] Getting AWS Group data for AWS Account '%s'",account_name) 
	jqQuery='.GroupDetailList[]'
	data=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery)
	logger.debug("[*] Completed getting AWS Group data for AWS Account '%s'",account_name) 
	return data
	
def loadAWSGroupNodes(neo4j_session,data_path,account_name):
	logger.info("[*] Loading AWS Groups into neo4j instance for AWS account '%s'",account_name)
	
	ingest_aws_groups='''merge (A:AWSGroup {Arn :$Arn}) 
	on match set A.GroupName=$GroupName, A.AccountNo=$AccountNo, A.GroupId=$GroupId,
	A.CreateDate=datetime($CreateDate), A.Path=$Path
	on create set A.GroupName=$GroupName, A.AccountNo=$AccountNo, A.GroupId=$GroupId,
	A.CreateDate=datetime($CreateDate), A.Path=$Path'''
	
	groups_data=getAWSGroups(data_path,account_name)
	
	for group_data in groups_data:
		neo4j_session.run(ingest_aws_groups,GroupName=group_data['GroupName'],AccountNo=str(group_data['Arn'].split(":")[4]),Arn=group_data['Arn'],GroupId=group_data['GroupId'],CreateDate=group_data['CreateDate'],Path=group_data['Path'])

	logger.info("[*] Completed loading AWS Groups into neo4j instance for AWS account '%s'",account_name)

def loadAWSUserGroupRelations(neo4j_session,data_path,account_name):
	logger.info("[*] Establishing AWS User-Group Relations into neo4j instance for AWS account '%s'",account_name)
	#Establishing Relations between Groups and Users
	ingest_aws_group_user_relations="match (A:AWSUser),(B:AWSGroup) where A.UserName=$UserName and B.GroupName=$GroupName and A.AccountNo=$AccountNo and B.AccountNo=$AccountNo with A,B merge (A)-[:Member_Of]->(B)"
	
	jqQuery=".UserDetailList[] | {UserName: .UserName, Arn: .Arn,Groups:.GroupList}"
	aws_user_group_relations=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery)
	for aws_user_group_relation in aws_user_group_relations:
		for group in aws_user_group_relation['Groups']:
			neo4j_session.run(ingest_aws_group_user_relations,
							  UserName=aws_user_group_relation['UserName'],
							  AccountNo=str(aws_user_group_relation['Arn'].split(":")[4]),
							  GroupName=group)
			
	logger.info("[*] Completed establishing AWS User-Group Relations into neo4j instance for AWS account '%s'",account_name)

def getAWSRoles(data_path,account_name):
	data=[]
	with open(os.path.join(data_path,account_name,'iam','iam-list-roles.json'),'r') as filein:
		role_json=json.loads(filein.read())
	data=pyjq.all('.Roles[] | { Arn: .Arn, CreateDate: .CreateDate, MaxSessionDuration: .MaxSessionDuration,Path: .Path, RoleId: .RoleId, RoleName: .RoleName, Description: .Description}',role_json)
	return data


def loadAWSRoleNodes(neo4j_session,data_path,account_name):
	logger.info("[*] Loading AWS Roles into neo4j instance for AWS account '%s'",account_name)
	
	ingest_aws_roles="merge (A:AWSRole {Arn: $Arn}) set A.AccountNo=$AccountNo, A.CreateDate= datetime($CreateDate),A.MaxSessionDuration=$MaxSessionDuration,A.Path= $Path, A.RoleId=$RoleId, A.RoleName=$RoleName,A.Description =$Description"
	
	roles_data=getAWSRoles(data_path,account_name)
	#Create Role Nodes
	for role_data in roles_data:
		neo4j_session.run(ingest_aws_roles,Arn=role_data['Arn'],AccountNo=role_data['Arn'].split(":")[4],CreateDate=role_data['CreateDate'],MaxSessionDuration=role_data['MaxSessionDuration'],Path=role_data['Path'],RoleId=role_data['RoleId'],RoleName=role_data['RoleName'],Description=role_data['Description'])
		
		#Loading Permission Boundary (if it exists)
		loadPermissionBoundary(neo4j_session,data_path,account_name,role_data['Arn'])
		
	logger.info("[*] Completed loading AWS Roles into neo4j instance for AWS account '%s'",account_name)

def getAssumeRolePolicy(data_path,account_name,role_arn):
	jqQuery='.RoleDetailList[] | select (.Arn=="#RoleArn#") | .AssumeRolePolicyDocument'
	data=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery.replace("#RoleArn#",role_arn))
	return data

def loadAWSRolePrincipalRelations(neo4j_session,data_path,account_name):
	logger.info("[*] Loading AWS Role Principal relation into neo4j instance for AWS account '%s'",account_name)
	
	roles_data=getAWSRoles(data_path,account_name)
	
	for role_data in roles_data:
		assume_role_policies=getAssumeRolePolicy(data_path,account_name,role_data['Arn'])
		for policy_document in assume_role_policies:
			policy_document_details=getPolicyDocumentDetails(policy_document)
			for statement in  policy_document_details['Statement']:
				policy_statement_details=getPolicyStatementDetails(statement)
				statement_principal=policy_statement_details['Principal']
				statement_action=policy_statement_details['Action']
				statement_resource=policy_statement_details['Resource']
				#Since empty Principal / Action / Resource is returned as set 
				#Stringifying it in query run below will result in value as 'set()'.
				#The following is to avoid it
				
				if statement_principal==set():
					statement_principal=""
				if statement_action==set():
					statement_action=""
				if statement_resource==set():
					statement_resource=""
				for key in policy_statement_details['Principal'].keys():
					if key =="AWS":
						for principal in policy_statement_details['Principal'][key]:
							if principal == "*":
								ingest_assume_role_principal='''
								merge (A {Arn:$PrincipalArn}) set A:AWSPolicyPrincipal
								with A match (B:AWSRole) where B.Arn=$RoleArn 
								with A,B merge 
								(D:AWSPolicy:AWSAssumeRolePolicy {Name: "AssumeRolePolicy",SourceRoleArn: $SourceRoleArn,DocumentVersion:$DocumentVersion,DocumentId:$DocumentId}) 
								with A,B,D merge (B)-[C:AWSPolicyAttachment]->(D) 
								with A,D merge (D)-[E:AWSPolicyStatement {Action:$Action}]->(A) 
								set  
								D.AccountNo=$AccountNo,
								A:AWSPolicyPrincipal,
								E.SourceRoleArn=$SourceRoleArn,
								E.DocumentVersion=$DocumentVersion,
								E.DocumentId=$DocumentId,
								E.Effect=$Effect ,
								E.ActionKey=$ActionKey,
								E.Action=$Action,
								E.Condition=$Condition,
								E.Sid=$Sid,
								E.ResourceKey=$ResourceKey,
								E.Resource=$Resource,
								E.Principal=$Principal,
								E.PrincipalKey=$PrincipalKey,
								E.Aaia_ExpandedAction=$Aaia_ExpandedAction'''
															
								neo4j_session.run(ingest_assume_role_principal,PrincipalArn=principal,RoleArn=role_data['Arn'],Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],AccountNo=role_data['Arn'].split(":")[4],SourceRoleArn=role_data['Arn'],DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Condition=policy_statement_details['Condition'],Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Principal=str(json.dumps(statement_principal)),PrincipalKey=policy_statement_details['PrincipalKey'])
							
							elif re.search("^[A-Z0-9]{21}$",principal):
							#In case RoleID/UserID is mentioned as principal
								empty_record=True
								finding_user_role_with_id='''match (A) where (("AWSUser" in labels(A)) or ("AWSRole" in labels(A))) and ((A.RoleId=$Id) or (A.UserId=$Id)) return A.Arn'''
								response=neo4j_session.run(finding_user_role_with_id,Id=principal)
								for record in response:
									empty_record=False
									identify_and_match_principal='''
									match(A) where A.Arn=$PrincipalArn 
									with A match (B:AWSRole) where
									B.Arn=$RoleArn with A,B
									merge 
									(D:AWSPolicy:AWSAssumeRolePolicy {Name: "AssumeRolePolicy",SourceRoleArn: $SourceRoleArn,DocumentVersion:$DocumentVersion,DocumentId:$DocumentId})
									with A,B,D merge (B)-[C:AWSPolicyAttachment]->(D) 
									with A,D merge (D)-[E:AWSPolicyStatement {Action:$Action}]->(A) 
									set  
									A:AWSPolicyPrincipal,
									D.AccountNo=$AccountNo,
									E.SourceRoleArn=$SourceRoleArn,
									E.DocumentVersion=$DocumentVersion,
									E.DocumentId=$DocumentId,
									E.Effect=$Effect,
									E.ActionKey=$ActionKey,
									E.Action=$Action,
									E.Condition=$Condition,
									E.Sid=$Sid,
									E.ResourceKey=$ResourceKey,
									E.Resource=$Resource,
									E.Principal=$Principal,
									E.PrincipalKey=$PrincipalKey,
									E.Aaia_ExpandedAction=$Aaia_ExpandedAction'''
									
									neo4j_session.run(identify_and_match_principal,PrincipalArn=record['A.Arn'],RoleArn=role_data['Arn'],Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],AccountNo=role_data['Arn'].split(":")[4],SourceRoleArn=role_data['Arn'],DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Condition=policy_statement_details['Condition'],Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Principal=str(json.dumps(statement_principal)),PrincipalKey=policy_statement_details['PrincipalKey'])
								
								#In case the Id does not match with any existing roles/users, it returns an empty record
								if empty_record:
									create_principal_query='''merge 
									(A:AWSPolicyPrincipal {Arn:$PrincipalArn})		
									with A 
									match (B:AWSRole) where B.Arn=$RoleArn 
									with A,B merge 
									(D:AWSPolicy:AWSAssumeRolePolicy {Name: "AssumeRolePolicy",SourceRoleArn: $SourceRoleArn,
									DocumentVersion:$DocumentVersion,
									DocumentId:$DocumentId}) 
									with A,B,D merge (B)-[C:AWSPolicyAttachment]->(D) 
									with A,D merge (D)-[E:AWSPolicyStatement {Action:$Action}]->(A) 
									set 
									D.AccountNo=$AccountNo,
									E.SourceRoleArn=$SourceRoleArn,
									E.DocumentVersion=$DocumentVersion,
									E.DocumentId=$DocumentId,
									E.Effect= $Effect ,
									E.ActionKey=$ActionKey,
									E.Action=$Action,
									E.Condition=$Condition,
									E.Sid=$Sid,
									E.ResourceKey=$ResourceKey,
									E.Resource=$Resource,
									E.Principal=$Principal,
									E.PrincipalKey=$PrincipalKey,
									E.Aaia_ExpandedAction=$Aaia_ExpandedAction'''
									
									neo4j_session.run(create_principal_query,PrincipalArn=principal,RoleArn=role_data['Arn'],Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],AccountNo=role_data['Arn'].split(":")[4],SourceRoleArn=role_data['Arn'],DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Condition=policy_statement_details['Condition'],Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Principal=str(json.dumps(statement_principal)),PrincipalKey=policy_statement_details['PrincipalKey'])
								
							#In case of just account number / root (As both mean same)
							#Ref:https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
							elif principal == arn.ARN(principal).account_number or arn.ARN(principal).root:
							
								ingest_assume_role_principal='''merge (A:AWSAccount {AccountNo:$PrincipalAccountNo}) set A.Arn=$Arn
								set A:AWSPolicyPrincipal 
								with A match (B:AWSRole) where B.Arn=$RoleArn 
								with A,B merge (D:AWSPolicy:AWSAssumeRolePolicy {Name: "AssumeRolePolicy",
								SourceRoleArn: $SourceRoleArn,
								DocumentVersion:$DocumentVersion,
								DocumentId:$DocumentId}) 
								with A,B,D merge
								(B)-[C:AWSPolicyAttachment]->(D) 
								with A,D 
								merge (D)-[E:AWSPolicyStatement {Action:$Action}]->(A) 
								set
								D.AccountNo=$AccountNo,
								E.SourceRoleArn=$SourceRoleArn,
								E.DocumentVersion=$DocumentVersion,
								E.DocumentId=$DocumentId,
								E.Effect=$Effect,
								E.ActionKey=$ActionKey,
								E.Action=$Action,
								E.Condition=$Condition,
								E.Sid=$Sid,
								E.ResourceKey=$ResourceKey,
								E.Resource=$Resource,
								E.Principal=$Principal,
								E.PrincipalKey=$PrincipalKey,
								E.Aaia_ExpandedAction=$Aaia_ExpandedAction
								'''
								neo4j_session.run(ingest_assume_role_principal,Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],PrincipalAccountNo=arn.ARN(principal).account_number,Arn=principal,RoleArn=role_data['Arn'],AccountNo=role_data['Arn'].split(":")[4],SourceRoleArn=role_data['Arn'],DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Condition=policy_statement_details['Condition'],Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Principal=str(json.dumps(statement_principal)),PrincipalKey=policy_statement_details['PrincipalKey'])
							
							#In case of role
							elif arn.ARN(principal).name.startswith("role") and len(arn.ARN(principal).name.split("/"))==2:
								#Length check is to determine if the name is like role/AWSRole which is an actual role so split("/") length will be 2 
								#However this is also possible , where name is like role/AWSRole/SessionName
								#In this case session is also involved , so from node creation standpoint in neo4j
								#This case has to be dealt with separately. Split ("/" lentgh will be 3 in this case
								
								ingest_assume_role_principal='''merge (R:AWSRole {Arn:$PrincipalArn,
								RoleName:$PrincipalName}) set R:AWSPolicyPrincipal, 
								R.AccountNo=$PrincipalAccountNo with R 
								merge (A:AWSAccount {AccountNo:$AccountNo}) 
								with R,A merge (R)-[:Belongs_To_Account]->(A)
								with R match (B:AWSRole) where 
								B.Arn=$RoleArn with R,B 
								merge (D:AWSPolicy:AWSAssumeRolePolicy {Name: "AssumeRolePolicy",
								SourceRoleArn: $SourceRoleArn,
								DocumentVersion:$DocumentVersion,
								DocumentId:$DocumentId}) with R,B,D merge
								(B)-[C:AWSPolicyAttachment]->(D) with R,D merge 
								(D)-[E:AWSPolicyStatement {Action:$Action}]->(R) 
								set 
								D.AccountNo=$AccountNo,
								E.SourceRoleArn=$SourceRoleArn,
								E.DocumentVersion=$DocumentVersion,
								E.DocumentId=$DocumentId,
								E.Effect=$Effect,
								E.ActionKey=$ActionKey,
								E.Action=$Action,
								E.Condition=$Condition,
								E.Sid=$Sid,
								E.ResourceKey=$ResourceKey,
								E.Resource=$Resource,
								E.Principal=$Principal,
								E.PrincipalKey=$PrincipalKey,
								E.Aaia_ExpandedAction=$Aaia_ExpandedAction
								'''
								neo4j_session.run(ingest_assume_role_principal,Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],PrincipalAccountNo=arn.ARN(principal).account_number,PrincipalArn=principal,PrincipalName=arn.ARN(principal).name.split("/")[1],RoleArn=role_data['Arn'],AccountNo=role_data['Arn'].split(":")[4],SourceRoleArn=role_data['Arn'],DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Condition=policy_statement_details['Condition'],Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Principal=str(json.dumps(statement_principal)),PrincipalKey=policy_statement_details['PrincipalKey'])
								
							#In case of role with session
							#RoleSessionName property is added to check if only specific session of the role is allowed to assume the role as part of AWS Statement
							elif arn.ARN(principal).name.startswith("role") and len(arn.ARN(principal).name.split("/"))==3:
								ingest_assume_role_principal='''merge (R:AWSRole {Arn:$PrincipalArn,RoleName:$PrincipalName}) 
								set R:AWSPolicyPrincipal, 
								R.AccountNo=$PrincipalAccountNo with R 
								merge (A:AWSAccount {AccountNo:$AccountNo}) 
								with R,A merge (R)-[:Belongs_To_Account]->(A) 
								with R match (B:AWSRole) where 
								B.Arn=$RoleArn with R,B 
								merge (D:AWSPolicy:AWSAssumeRolePolicy:AWSSessionPolicy 
								{Name: "AssumeRolePolicy",SourceRoleArn: $SourceRoleArn,
								DocumentVersion:$DocumentVersion,
								DocumentId:$DocumentId}) 
								set D.Aaia_SessionName=$SessionName with R,B,D merge
								(B)-[C:AWSPolicyAttachment]->(D) with R,D merge 
								(D)-[E:AWSPolicyStatement {Action:$Action}]->(R) 
								set 
								D.AccountNo=$AccountNo,
								E.SourceRoleArn=$SourceRoleArn,
								E.DocumentVersion=$DocumentVersion,
								E.DocumentId=$DocumentId,
								E.Effect=$Effect,
								E.ActionKey=$ActionKey,
								E.Action=$Action,
								E.Condition=$Condition,
								E.Sid=$Sid,
								E.ResourceKey=$ResourceKey,
								E.Resource=$Resource,
								E.Principal=$Principal,
								E.PrincipalKey=$PrincipalKey,
								E.Aaia_ExpandedAction=$Aaia_ExpandedAction
								'''
								
								neo4j_session.run(ingest_assume_role_principal,PrincipalAccountNo=arn.ARN(principal).account_number,SessionName=arn.ARN(principal).name.split("/")[2],PrincipalArn=principal,PrincipalName=arn.ARN(principal).name.split("/")[1],RoleArn=role_data['Arn'],AccountNo=role_data['Arn'].split(":")[4],SourceRoleArn=role_data['Arn'],DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Condition=policy_statement_details['Condition'],Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Principal=str(json.dumps(statement_principal)),Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],PrincipalKey=policy_statement_details['PrincipalKey'])
							#In case of user
							elif arn.ARN(principal).name.startswith("user"):
								ingest_assume_role_principal='''merge (U:AWSUser {Arn:$PrincipalArn}) set U:AWSPolicyPrincipal, 
								U.AccountNo=$PrincipalAccountNo, U.Name=$PrincipalName with U 
								merge (A:AWSAccount {AccountNo:$AccountNo}) 
								with U,A merge (U)-[:Belongs_To_Account]->(A)
								with U match (B:AWSRole) where 
								B.Arn=$RoleArn with U,B 
								merge 
								(D:AWSPolicy:AWSAssumeRolePolicy 
								{Name: "AssumeRolePolicy",SourceRoleArn: $SourceRoleArn,
								DocumentVersion:$DocumentVersion,DocumentId:$DocumentId}) 
								with U,B,D merge
								(B)-[C:AWSPolicyAttachment]->(D) with U,D merge 
								(D)-[E:AWSPolicyStatement {Action:$Action}]->(U) 
								set 
								D.AccountNo=$AccountNo,
								E.SourceRoleArn=$SourceRoleArn,
								E.DocumentVersion=$DocumentVersion,
								E.DocumentId=$DocumentId,
								E.Effect=$Effect,
								E.ActionKey=$ActionKey,
								E.Action=$Action,
								E.Condition=$Condition,
								E.Sid=$Sid,
								E.ResourceKey=$ResourceKey,
								E.Resource=$Resource,
								E.Principal=$Principal,
								E.PrincipalKey=$PrincipalKey,
								E.Aaia_ExpandedAction=$Aaia_ExpandedAction
								'''
								neo4j_session.run(ingest_assume_role_principal,Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],PrincipalAccountNo=arn.ARN(principal).account_number,PrincipalArn=principal,PrincipalName=arn.ARN(principal).name.split("/")[1],RoleArn=role_data['Arn'],AccountNo=role_data['Arn'].split(":")[4],SourceRoleArn=role_data['Arn'],DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Condition=policy_statement_details['Condition'],Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Principal=str(json.dumps(statement_principal)),PrincipalKey=policy_statement_details['PrincipalKey'])
							#Else raise exception returning type of principal unknown with principal details
							else:
								raise ValueError('Unknown AWSPrincipal : "AWS":'+principal)
					
					elif key =="Service":
						ingest_assume_role_principal='''merge (A:AWSPolicyPrincipal:AWSService {ServiceName:$ServiceName,Arn:$PrincipalArn}) with A match (B:AWSRole) 
						where 
								B.Arn=$RoleArn with A,B 
								merge 
								(D:AWSPolicy:AWSAssumeRolePolicy {Name: "AssumeRolePolicy",SourceRoleArn: $SourceRoleArn,
								DocumentVersion:$DocumentVersion,DocumentId:$DocumentId}) 
								with A,B,D merge
								(B)-[C:AWSPolicyAttachment]->(D) with A,D merge 
								(D)-[E:AWSPolicyStatement {Action:$Action}]->(A) 
								set 
								D.AccountNo=$AccountNo,
								E.SourceRoleArn=$SourceRoleArn,
								E.DocumentVersion=$DocumentVersion,
								E.DocumentId=$DocumentId,
								E.Effect=$Effect,
								E.ActionKey=$ActionKey,
								E.Action=$Action,
								E.Condition=$Condition,
								E.Sid=$Sid,
								E.ResourceKey=$ResourceKey,
								E.Resource=$Resource,
								E.Principal=$Principal,
								E.PrincipalKey=$PrincipalKey,
								E.Aaia_ExpandedAction=$Aaia_ExpandedAction
						'''
						for principal in policy_statement_details['Principal'][key]:
						
							neo4j_session.run(ingest_assume_role_principal,Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],ServiceName=arn.ARN(principal).tech,PrincipalArn=principal,RoleArn=role_data['Arn'],AccountNo=role_data['Arn'].split(":")[4],SourceRoleArn=role_data['Arn'],DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Condition=policy_statement_details['Condition'],Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Principal=str(json.dumps(statement_principal)),PrincipalKey=policy_statement_details['PrincipalKey'])
							
					elif key=="Federated":
						for principal in policy_statement_details['Principal'][key]:
						
							#External IDP (The AWS supported IDPs can be added to the below comparison list as and when encountered)
							if principal in ["cognito-identity.amazonaws.com","accounts.google.com"]:
								#Since cognito is an AWS Service
								set_aws_service_label=""
								if principal == "cognito-identity.amazonaws.com":
									set_aws_service_label=":AWSService"
								
								ingest_assume_role_principal='''merge (A:AWSPolicyPrincipal {Name:$FederationName,Arn:$PrincipalArn) set A:AWSFederated'''+set_aws_service_label+''' with A match (B:AWSRole) 
								where 
								B.Arn=$RoleArn with A,B 
								merge 
								(D:AWSPolicy:AWSAssumeRolePolicy {Name: "AssumeRolePolicy",SourceRoleArn: $SourceRoleArn,
								DocumentVersion:$DocumentVersion,
								DocumentId:$DocumentId}) 
								with A,B,D merge
								(B)-[C:AWSPolicyAttachment]->(D) with A,D merge 
								(D)-[E:AWSPolicyStatement {Action:$Action}]->(A) 
								set 
								D.AccountNo=$AccountNo,
								E.SourceRoleArn=$SourceRoleArn,
								E.DocumentVersion=$DocumentVersion,
								E.DocumentId=$DocumentId,
								E.Effect=$Effect,
								E.ActionKey=$ActionKey,
								E.Action=$Action,
								E.Condition=$Condition,
								E.Sid=$Sid,
								E.ResourceKey=$ResourceKey,
								E.Resource= $Resource,
								E.Principal=$Principal,
								E.PrincipalKey= $PrincipalKey,
								E.Aaia_ExpandedAction= $Aaia_ExpandedAction'''
								
								neo4j_session.run(ingest_assume_role_principal,Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],FederationName=principal,PrincipalArn=principal,RoleArn=role_data['Arn'],AccountNo=role_data['Arn'].split(":")[4],SourceRoleArn=role_data['Arn'],DocumentVersion=policy_document_details['Version'],DocumentId=policy_document_details['Id'],Effect=policy_statement_details['Effect'],ActionKey=policy_statement_details['ActionKey'],Action=str(statement_action).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Condition=policy_statement_details['Condition'],Sid=policy_statement_details['Sid'],ResourceKey=policy_statement_details['ResourceKey'],Resource=str(statement_resource).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),Principal=str(json.dumps(statement_principal)),PrincipalKey=policy_statement_details['PrincipalKey'])
								
							#In case of AWS SAML Provider
							elif arn.ARN(principal).account_number !=None:
								ingest_assume_role_principal='''
								merge (S:AWSSAMLProvider {Arn:$PrincipalArn, 
								PrincipalAccountNo:$AccountNo}) set S.Name=$PrincipalName, S:AWSPolicyPrincipal:AWSFederated
								with S merge (A:AWSAccount {AccountNo:$AccountNo})
								with S,A merge (S)-[:Belongs_To_Account]->(A) with S
								match (B:AWSRole) 
								where 
								B.Arn=$RoleArn with S,B 
								merge 
								(D:AWSPolicy:AWSAssumeRolePolicy {Name: "AssumeRolePolicy",SourceRoleArn: $SourceRoleArn,DocumentVersion:$DocumentVersion,
								DocumentId:$DocumentId})
								with S,B,D merge
								(B)-[C:AWSPolicyAttachment]->(D) with S,D merge 
								(D)-[E:AWSPolicyStatement {Action:$Action}]->(S) 
								set 
								D.AccountNo=$AccountNo,
								E.SourceRoleArn=$SourceRoleArn,
								E.DocumentVersion=$DocumentVersion,
								E.DocumentId=$DocumentId,
								E.Effect=$Effect,
								E.ActionKey=$ActionKey,
								E.Action=$Action,
								E.Condition=$Condition,
								E.Sid=$Sid,
								E.ResourceKey=$ResourceKey,
								E.Resource=$Resource,
								E.Principal=$Principal,
								E.PrincipalKey=$PrincipalKey,
								E.Aaia_ExpandedAction=$Aaia_ExpandedAction
								'''
								neo4j_session.run(ingest_assume_role_principal,
									Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],
									PrincipalArn=principal,
									PrincipalName=arn.ARN(principal).name.split("/")[0],
									AccountNo=role_data['Arn'].split(":")[4],
									PrincipalAccountNo=arn.ARN(principal).account_number,
									RoleArn=role_data['Arn'],
									SourceRoleArn=role_data['Arn'],
									DocumentVersion=policy_document_details['Version'],
									DocumentId=policy_document_details['Id'],
									Effect=policy_statement_details['Effect'],
									ActionKey=policy_statement_details['ActionKey'],
									Action=str(statement_action).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),
									Condition=policy_statement_details['Condition'],
									Sid=policy_statement_details['Sid'],
									ResourceKey=policy_statement_details['ResourceKey'],
									Resource=str(statement_resource).replace("'","").replace("{","").replace("}","").replace("[","").replace("]",""),
									Principal=str(json.dumps(statement_principal)),
									PrincipalKey=policy_statement_details['PrincipalKey'])
										
							else:
								raise ValueError('Unknown AWSPrincipal : "Federated":'+principal)
					else:
						raise KeyError('Unknown AWSPrincipalType :'+key+" \nComplete Policy Statement Record:"+str(policy_statement_details))
	logger.info("[*] Completed loading AWS Role Principal relation into neo4j instance for AWS account '%s'",account_name)

def getAWSInstanceProfiles(data_path,account_name):
	
	jqQuery='.RoleDetailList[] | .InstanceProfileList[] | {InstanceProfileName : .InstanceProfileName,InstanceProfileId: .InstanceProfileId,SourceRoleArn : .Roles[].Arn, CreateDate: .CreateDate, Arn: .Arn, Path : .Path}'
	
	instance_profiles=getAWSIamAccountAuthorizationDetailsInfo(data_path,account_name,jqQuery)
	
	return instance_profiles
	
def loadAWSInstanceProfiles(neo4j_session,data_path,account_name):
	logger.info("[*] Loading AWS Role Instance Profiles into neo4j instance for AWS account '%s'",account_name)
	ingest_role_instance_profiles='''merge (instanceprofile:AWSInstanceProfile {Arn:$Arn}) 
									on match set 
									instanceprofile.AccountNo=$AccountNo,
									instanceprofile.InstanceProfileName=$InstanceProfileName,
									instanceprofile.InstanceProfileId=$InstanceProfileId, 
									instanceprofile.SourceRoleArn=$SourceRoleArn,
									instanceprofile.CreateDate=$CreateDate,
									instanceprofile.Path=$Path
									on create set
									instanceprofile.AccountNo=$AccountNo,
									instanceprofile.InstanceProfileName=$InstanceProfileName,
									instanceprofile.InstanceProfileId=$InstanceProfileId, 
									instanceprofile.SourceRoleArn=$SourceRoleArn,
									instanceprofile.CreateDate=$CreateDate,
									instanceprofile.Path=$Path
									'''
	instance_profiles=getAWSInstanceProfiles(data_path,account_name)
	
	for instance_profile in instance_profiles:
		neo4j_session.run(ingest_role_instance_profiles,Arn=instance_profile['Arn'],AccountNo=instance_profile['Arn'].split(":")[4],InstanceProfileName=instance_profile['InstanceProfileName'],InstanceProfileId=instance_profile['InstanceProfileId'],SourceRoleArn=instance_profile['SourceRoleArn'],CreateDate=instance_profile['CreateDate'],Path=instance_profile['Path'])
	
	logger.info("[*] Completed loading AWS Role Instance Profiles into neo4j instance for AWS account '%s'",account_name)


def loadAWSInstanceProfileRelations(neo4j_session,data_path,account_name):
	logger.info("[*] Loading AWS Role Instance Profile relations into neo4j instance for AWS account '%s'",account_name)
	ingest_role_instance_profile_relation='''match (role:AWSRole),(instanceprofile:AWSInstanceProfile) 
									where role.Arn=instanceprofile.SourceRoleArn
									with role,instanceprofile
									merge (instanceprofile)-[:InstanceProfile_Of]->(role)
									'''
	neo4j_session.run(ingest_role_instance_profile_relation)
	
	logger.info("[*] Completed loading AWS Role Instance Profile relations into neo4j instance for AWS account '%s'",account_name)


#Gets the Account Password Policy for current Account
def getAWSAccountPasswordPolicy(data_path,account_name):
	
	with open(os.path.join(data_path,account_name,'iam','iam-get-account-password-policy.json'),'r') as filein:
		data=json.loads(filein.read())
	jqQuery='.PasswordPolicy'
	account_password_policy=pyjq.all(jqQuery,data)[0]
	
	#Standard Set of keys present in a typical account password policy output
	account_password_policy_standard_keys=['MinimumPasswordLength','RequireSymbols','RequireNumbers','RequireUppercaseCharacters','RequireLowercaseCharacters','AllowUsersToChangePassword','ExpirePasswords','MaxPasswordAge','PasswordReusePrevention','HardExpiry']
	
	#To Check if any value has not been set and set such keys as blank in returning value
	for key in account_password_policy_standard_keys:
		if key in account_password_policy.keys():
			pass
		else:
			account_password_policy.__setitem__(key,'')
	return(account_password_policy)

#Gets the Account Summary of current Account
def getAWSAccountSummary(data_path,account_name):
	
	with open(os.path.join(data_path,account_name,'iam','iam-get-account-summary.json'),'r') as filein:
		data=json.loads(filein.read())
	
	jqQuery='.SummaryMap'
	account_summary=pyjq.all(jqQuery,data)[0]
	return (account_summary)

#Gets the Account Alias for current Account
def getAWSAccountAliases(data_path,account_name):
	
	with open(os.path.join(data_path,account_name,'iam','iam-list-account-aliases.json'),'r') as filein:
		data=json.loads(filein.read())
	
	jqQuery='.AccountAliases[]'
	
	account_alias=pyjq.all(jqQuery,data)
	account_alias=','.join(account_alias)
	return (account_alias)
		
#Gets the AWS AccountNo of current processing Account
def getAWSAccountNo(data_path,account_name):
	jqQuery=".Account"
	logger.debug("[*] Getting AWS AccountNo from '%s' for AWS Account '%s' for jq Query '%s'",
				 data_path + account_name + '/sts/sts-get-caller-identity.json', account_name, jqQuery)
	with open(os.path.join(data_path, account_name, 'sts','sts-get-caller-identity.json'),'r') as filein:
		file_content = json.loads(filein.read())
	logger.debug("[*] Completed getting AWS AccountNo from '%s' for AWS Account '%s' for jq Query '%s'",
				 data_path + account_name + '/sts/sts-get-caller-identity.json', account_name, jqQuery)

	return pyjq.all(jqQuery, file_content)[0]


def loadAWSAccountRelations(neo4j_session,data_path,account_name):
	logger.info("[*] Loading AWS Account Relation into neo4j instance for AWS account '%s'",account_name)

	aws_account_relation='''
						merge (A:AWSAccount {AccountNo:$AccountNo})
						set A.AccountName=$AccountName, 
						A.Arn=$Arn,
						A.PasswordPolicy_MinimumPasswordLength=$MinimumPasswordLength,
						A.PasswordPolicy_RequireNumbers=$RequireNumbers,
						A.PasswordPolicy_RequireSymbols=$RequireSymbols,
						A.PasswordPolicy_RequireUppercaseCharacters=$RequireUppercaseCharacters,
						A.PasswordPolicy_RequireLowercaseCharacters=$RequireLowercaseCharacters,
						A.PasswordPolicy_AllowUsersToChangePassword=$AllowUsersToChangePassword,
						A.PasswordPolicy_ExpirePasswords=$ExpirePasswords,
						A.PasswordPolicy_MaxPasswordAge=$MaxPasswordAge,
						A.PasswordPolicy_PasswordReusePrevention=$PasswordReusePrevention,
						A.PasswordPolicy_HardExpiry=$HardExpiry,
						A.AccountSummary_UsersQuota=$UsersQuota,
						A.AccountSummary_GroupsQuota=$GroupsQuota,
						A.AccountSummary_InstanceProfiles=$InstanceProfiles,
						A.AccountSummary_SigningCertificatesPerUserQuota=$SigningCertificatesPerUserQuota,
						A.AccountSummary_AccountAccessKeysPresent=$AccountAccessKeysPresent,
						A.AccountSummary_RolesQuota=$RolesQuota,
						A.AccountSummary_RolePolicySizeQuota=$RolePolicySizeQuota,
						A.AccountSummary_AccountSigningCertificatesPresent=$AccountSigningCertificatesPresent,
						A.AccountSummary_Users=$Users,
						A.AccountSummary_ServerCertificatesQuota=$ServerCertificatesQuota,
						A.AccountSummary_ServerCertificates=$ServerCertificates,
						A.AccountSummary_AssumeRolePolicySizeQuota=$AssumeRolePolicySizeQuota,
						A.AccountSummary_Groups=$Groups,
						A.AccountSummary_MFADevicesInUse=$MFADevicesInUse,
						A.AccountSummary_Roles=$Roles,
						A.AccountSummary_AccountMFAEnabled=$AccountMFAEnabled,
						A.AccountSummary_MFADevices=$MFADevices,
						A.AccountSummary_GroupsPerUserQuota=$GroupsPerUserQuota,
						A.AccountSummary_GroupPolicySizeQuota=$GroupPolicySizeQuota,
						A.AccountSummary_InstanceProfilesQuota=$InstanceProfilesQuota,
						A.AccountSummary_AccessKeysPerUserQuota=$AccessKeysPerUserQuota,
						A.AccountSummary_Providers=$Providers,
						A.AccountSummary_UserPolicySizeQuota=$UserPolicySizeQuota,
						A.AccountAlias=$AccountAlias
						with A 
						match (B) where B.AccountNo=$AccountNo and 
						not ("AWSAccount" in labels(B)) with A,B
						merge (B)-[:Belongs_To_Account]->(A)'''
	
	account_number=getAWSAccountNo(data_path,account_name)
	arn="arn:aws:iam::"+str(account_number)+":root"
	
	#Getting Account Password Policy
	account_password_policy=getAWSAccountPasswordPolicy(data_path,account_name)
	
	#Getting Account Summary
	account_summary=getAWSAccountSummary(data_path,account_name)
	
	#Getting Account Aliases
	account_alias=getAWSAccountAliases(data_path,account_name)
	
	neo4j_session.run(aws_account_relation,AccountNo=account_number,AccountName=account_name,Arn=arn,MinimumPasswordLength=account_password_policy['MinimumPasswordLength'],RequireNumbers=account_password_policy['RequireNumbers'],RequireSymbols=account_password_policy['RequireSymbols'],RequireUppercaseCharacters=account_password_policy['RequireUppercaseCharacters'],RequireLowercaseCharacters=account_password_policy['RequireLowercaseCharacters'],AllowUsersToChangePassword=account_password_policy['AllowUsersToChangePassword'],ExpirePasswords=account_password_policy['ExpirePasswords'],MaxPasswordAge=account_password_policy['MaxPasswordAge'],PasswordReusePrevention=account_password_policy['PasswordReusePrevention'],HardExpiry=account_password_policy['HardExpiry'],UsersQuota=account_summary['UsersQuota'],GroupsQuota=account_summary['GroupsQuota'],InstanceProfiles=account_summary['InstanceProfiles'],SigningCertificatesPerUserQuota=account_summary['SigningCertificatesPerUserQuota'],AccountAccessKeysPresent=account_summary['AccountAccessKeysPresent'],RolesQuota=account_summary['RolesQuota'],RolePolicySizeQuota=account_summary['RolePolicySizeQuota'],AccountSigningCertificatesPresent=account_summary['AccountSigningCertificatesPresent'],Users=account_summary['Users'],ServerCertificatesQuota=account_summary['ServerCertificatesQuota'],ServerCertificates=account_summary['ServerCertificates'],AssumeRolePolicySizeQuota=account_summary['AssumeRolePolicySizeQuota'],Groups=account_summary['Groups'],MFADevicesInUse=account_summary['MFADevicesInUse'],Roles=account_summary['Roles'],AccountMFAEnabled=account_summary['AccountMFAEnabled'],MFADevices=account_summary['MFADevices'],GroupsPerUserQuota=account_summary['GroupsPerUserQuota'],GroupPolicySizeQuota=account_summary['GroupPolicySizeQuota'],InstanceProfilesQuota=account_summary['InstanceProfilesQuota'],AccessKeysPerUserQuota=account_summary['AccessKeysPerUserQuota'],Providers=account_summary['Providers'],UserPolicySizeQuota=account_summary['UserPolicySizeQuota'],AccountAlias=account_alias)
	
	logger.info("[*] Completed loading AWS Account Relation into neo4j instance for AWS account '%s'",account_name)


	
	
def loadAWSIAM(neo4j_uri,neo4j_user,neo4j_password,data_path,account_name):
	neo4j_auth = (neo4j_user, neo4j_password)
	neo4j_driver = GraphDatabase.driver( neo4j_uri, auth=neo4j_auth, encrypted=False)
	with neo4j_driver.session() as neo4j_session:
		#Load AWS Managed Policies
		loadAWSManagedPolicies(neo4j_session,data_path,account_name)
		
		#Load AWS Users
		loadAWSUserNodes(neo4j_session,data_path,account_name)
		
		#Load AWS Managed Policy Relationship for Users
		loadAWSManagedPolicyRelations(neo4j_session,data_path,account_name,"User")
		
		#Load AWS Inline Policies for Users
		loadAWSInlinePolicies(neo4j_session,data_path,account_name,"User")
		
		#Load AWS Groups 
		loadAWSGroupNodes(neo4j_session,data_path,account_name)
		
		#Load AWS Group User Relationship
		loadAWSUserGroupRelations(neo4j_session,data_path,account_name)
		
		#Load AWS Managed Policy Relationship for Groups
		loadAWSManagedPolicyRelations(neo4j_session,data_path,account_name,"Group")
		
		#Load AWS Inline Policies for Groups
		loadAWSInlinePolicies(neo4j_session,data_path,account_name,"Group")
		
		#Load AWS Roles
		loadAWSRoleNodes(neo4j_session,data_path,account_name)
		
		#Load AWSRole-Principal Relationship from Assume Role Policy
		loadAWSRolePrincipalRelations(neo4j_session,data_path,account_name)
		
		#Load AWS Managed Policy Relations for Roles
		loadAWSManagedPolicyRelations(neo4j_session,data_path,account_name,"Role")
		
		#Load Inline Policies for Roles
		loadAWSInlinePolicies(neo4j_session,data_path,account_name,"Role")
		
		#Load Instance Profile of Roles
		loadAWSInstanceProfiles(neo4j_session,data_path,account_name)
		
		#Load Instance Profile Relation with corresponding Roles
		loadAWSInstanceProfileRelations(neo4j_session,data_path,account_name)
		
		#Load AWS Account Relations
		loadAWSAccountRelations(neo4j_session,data_path,account_name)
		

def help():
	#Kept here just for maintaing a template
	pass


def main(config,args):
	
	neo4j_uri=config['neo4j_conf']['neo4j_uri']
	neo4j_user=config['neo4j_conf']['neo4j_user']
	neo4j_password=config['neo4j_conf']['neo4j_password']
	data_path=os.path.join(config['offline_datapath']['data_path'],"aws")
	if args.name:
		account_name=args.name
		loadAWSIAM(neo4j_uri,neo4j_user,neo4j_password,data_path,account_name)
	else:
		print("-n argument missing. Please provide the name of the account.",file=sys.stderr)
