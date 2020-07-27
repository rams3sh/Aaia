from neo4j import GraphDatabase
from collections import OrderedDict
import pyjq
import json
import logging
import os
import time
import sys
from lib.aws_common import getPolicyDocumentDetails,getPolicyStatementDetails

__description__="loads the aws organization details into neo4j instance"

logging.basicConfig()
logger=logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def getAWSServiceControlPolicy(data_path,account_name):
    with open(os.path.join(data_path,account_name,"organizations",'organizations-list-policies.json'),'r') as filein:
        file_content = json.loads(filein.read())
    jqQuery='.Policies[].Id'
    service_control_policies=pyjq.all(jqQuery,file_content)

    scp_list=[]
    for service_control_policy in service_control_policies:
        with open(os.path.join(data_path,account_name,"organizations","organizations-describe-policy",service_control_policy),'r') as filein:
            file_content=json.loads(filein.read())


        policy_details=OrderedDict()
        policy_details.__setitem__('Id',file_content['Policy']['PolicySummary']['Id'])
        policy_details.__setitem__('Arn', file_content['Policy']['PolicySummary']['Arn'])
        policy_details.__setitem__('Name', file_content['Policy']['PolicySummary']['Name'])
        policy_details.__setitem__('Description', file_content['Policy']['PolicySummary']['Description'])
        policy_details.__setitem__('AwsManaged', file_content['Policy']['PolicySummary']['AwsManaged'])
        policy_details.__setitem__('Content', json.loads(file_content['Policy']['Content']))

        scp_list.append(policy_details)
    return scp_list

def loadAWSServiceControlPolicy(neo4j_session,data_path,account_name):

    #This function loads all the Service Control Policies
    logger.info("[*] Loading AWS Service Control Policy into neo4j instance for AWS account '%s'", account_name)
    ingest_aws_service_control_policy='''merge(scp:AWSPolicy:AWSServiceControlPolicy {Arn:$Arn}) 
                                    set scp.Id=$Id,
                                    scp.Arn=$Arn,
                                    scp.Name=$Name,
                                    scp.Description=$Description,
                                    scp.AwsManaged=$AwsManaged,
                                    scp.DocumentVersion=$DocumentVersion,
                                    scp.DocumentId=$DocumentId 
                                    with scp
                                    merge (resource {Arn: $ResourceArn}) set resource:AWSPolicyResource 
								    with scp,resource 
                                    merge (scp)-[statement:AWSPolicyStatement 
                                    { DocumentVersion:$DocumentVersion,
								    DocumentId:$DocumentId,
                                    Effect:$Effect ,
                                    ActionKey:$ActionKey,
                                    Action:$Action,
                                    Condition:$Condition,
                                    Sid:$Sid,
                                    ResourceKey:$ResourceKey,
                                    Resource:$Resource,
                                    Principal:$Principal,
                                    PrincipalKey:$PrincipalKey,
                                    Aaia_ExpandedAction: $Aaia_ExpandedAction}]->(resource)
								'''

    policies=getAWSServiceControlPolicy(data_path,account_name)

    for policy in policies:
        policy_document_details = getPolicyDocumentDetails(policy['Content'])

        for statement in policy_document_details['Statement']:

            policy_statement_details = getPolicyStatementDetails(statement)
            statement_principal = policy_statement_details['Principal']
            statement_action = policy_statement_details['Action']
            statement_resource = policy_statement_details['Resource']

            # Since empty Principal / Action / Resource is returned as set
            # Stringifying it in query run below will result in value as 'set()'.
            # The following is to avoid it

            if statement_principal == set():
                statement_principal = ""
            if statement_action == set():
                statement_action = ""
            if statement_resource == set():
                statement_resource = ""

            for resource in policy_statement_details['Resource']:
                neo4j_session.run(ingest_aws_service_control_policy,
                                  Aaia_ExpandedAction=policy_statement_details['Aaia_ExpandedAction'],
                                  Name=policy['Name'],
                                  Id=policy['Id'],
                                  Arn=policy['Arn'],
                                  Description=policy['Description'],
                                  AwsManaged=policy['AwsManaged'],
                                  DocumentVersion=policy_document_details['Version'],
                                  DocumentId=policy_document_details['Id'],
                                  Effect=policy_statement_details['Effect'],
                                  ActionKey=policy_statement_details['ActionKey'],
                                  Action=str(statement_action).replace("[", "").replace("]", "").replace("{","").replace("}", "").replace("'", ""),
                                  Condition=str(policy_statement_details['Condition']),
                                  Sid=policy_statement_details['Sid'],
                                  ResourceKey=policy_statement_details['ResourceKey'],
                                  Resource=str(statement_resource).replace("[", "").replace("]", "").replace("{","").replace("}", "").replace("'", ""),
                                  Principal=str(statement_principal).replace("[", "").replace("]", "").replace("{","").replace("}", "").replace("'", ""),
                                  PrincipalKey=policy_statement_details['PrincipalKey'],
                                  ResourceArn=resource)
    logger.info("[*] Completed loading AWS Service Control Policy into neo4j instance for AWS account '%s'", account_name)

def getAWSOrganizationRootNode(data_path,account_name):

    with open(os.path.join(data_path,account_name,"organizations","organizations-list-roots.json"),'r') as filein:
        file_content = json.loads(filein.read())

    jqQuery='.Roots[] | {Id: .Id,Name: .Name,Arn: .Arn,PolicyType: .PolicyTypes[].Type,PolicyStatus: .PolicyTypes[].Status}'

    #The resultant is a Odereddict wrapped in a list. Hence returning an unlisted Ordereddict
    organization_root_node=pyjq.all(jqQuery,file_content)[0]
    return organization_root_node

def loadAWSOrganizationRootNode(neo4j_session,data_path,account_name):
    #This function loads the Organization Node (i.e. the Root Node . Do not confuse with Root Account of Organization)
    #This node is just a root node signifying the structure of the Organization

    logger.info("[*] Loading AWS Organization into neo4j instance for AWS account '%s'", account_name)

    ingest_aws_organization_root_node='''merge (org:AWSOrganization:AWSOrganizationOU {Id:$Id,Arn:$Arn,Name:$Name,
    PolicyType:$PolicyType,PolicyStatus:$PolicyStatus})'''
    organization_root_node_details=getAWSOrganizationRootNode(data_path,account_name)
    neo4j_session.run(ingest_aws_organization_root_node,Id=organization_root_node_details['Id'],Name=organization_root_node_details['Name'],Arn=organization_root_node_details['Arn'],PolicyType=organization_root_node_details['PolicyType'],PolicyStatus=organization_root_node_details['PolicyStatus'])

    logger.info("[*] Completed loading AWS Organization into neo4j instance for AWS account '%s'", account_name)

def getAWSOrganizationMasterAccount(data_path,account_name):

    with open(os.path.join(data_path,account_name,"organizations","organizations-describe-organization.json"),'r') as filein:
        file_content = json.loads(filein.read())
    jqQuery='.Organization | {Id : .Id, Arn:.Arn,FeatureSet:.FeatureSet,MasterAccountArn:.MasterAccountArn,MasterAccountId:.MasterAccountId,MasterAccountEmail:.MasterAccountEmail,AvailablePolicyType:.AvailablePolicyTypes[].Type,AvailablePolicyStatus:.AvailablePolicyTypes[].Status}'

    # The resultant is a Odereddict wrapped in a list. Hence returning an unlisted Ordereddict
    organization_master_account_details=pyjq.all(jqQuery,file_content)[0]
    return organization_master_account_details

def loadAWSOrganizationMasterAccount(neo4j_session,data_path,account_name):

    #This function adds the master account details to the AWSAccount Node
    logger.info("[*] Loading AWS Organization Master Account into neo4j instance for AWS account '%s'", account_name)

    master_account_details=getAWSOrganizationMasterAccount(data_path,account_name)
    ingest_master_account='''merge (account:AWSAccount {AccountNo:$AccountNo})
                            set account:AWSOrganizationMasterAccount, 
                            account.OrganizationAccountArn=$OrganizationAccountArn,
                            account.OrganizationId=$OrganizationId,
                            account.OrganizationArn=$OrganizationArn,
                            account.FeatureSet=$FeatureSet,
                            account.AccountEmail=$AccountEmail,
                            account.AvailablePolicyType=$AvailablePolicyType,
                            account.AvailablePolicyStatus=$AvailablePolicyStatus
                            '''
    neo4j_session.run(ingest_master_account,AccountNo=master_account_details['MasterAccountId'],
                      OrganizationAccountArn=master_account_details['MasterAccountArn'],
                      OrganizationId=master_account_details['Id'],
                      OrganizationArn=master_account_details['Arn'],
                      FeatureSet=master_account_details['FeatureSet'],
                      AccountEmail=master_account_details['MasterAccountEmail'],
                      AvailablePolicyType=master_account_details['AvailablePolicyType'],
                      AvailablePolicyStatus=master_account_details['AvailablePolicyStatus'])

    logger.info("[*] Completed loading AWS Organization Master Account into neo4j instance for AWS account '%s'", account_name)

def getAWSOrganizationOU(data_path,account_name):
    ou_details=[]
    for items in os.walk(os.path.join(data_path,account_name,"organizations","ou_tree")):
        for dir in items:
            if type(dir)!=list and not (dir.endswith("ou_tree")):
                with open(os.path.join(dir,"organizations-list-organizational-units-for-parent.json"),"r") as filein:
                    file_content=json.loads(filein.read())
                for ou in file_content['OrganizationalUnits']:
                    ou.__setitem__('Aaia_ParentOU', os.path.basename(dir))
                    ou_details.append(ou)
    return ou_details

def loadAWSOrganizationOU(neo4j_session,data_path,account_name):
    logger.info("[*] Loading AWS Organization OUs into neo4j instance for AWS account '%s'", account_name)
    ingest_aws_organization_ou='''merge (ou:AWSOrganizationOU {Arn:$Arn})
                                set ou.Id=$Id,
                                ou.Aaia_ParentOU=$Aaia_ParentOU,
                                ou.Name=$Name
                                '''

    ou_list=getAWSOrganizationOU(data_path,account_name)

    for ou in ou_list:
        neo4j_session.run(ingest_aws_organization_ou,Arn=ou['Arn'],
                          Id=ou['Id'],
                          Aaia_ParentOU=ou['Aaia_ParentOU'],
                          Name=ou['Name'])
    logger.info("[*] Completed loading AWS Organization OUs into neo4j instance for AWS account '%s'", account_name)

def getAWSOrganizationAccounts(data_path,account_name):
    organization_accounts_details=[]
    for items in os.walk(os.path.join(data_path,account_name,"organizations","ou_tree")):
        for dir in items:
            if type(dir)!=list and not (dir.endswith("ou_tree")):
                with open(os.path.join(dir,"organizations-list-accounts-for-parent.json"),"r") as filein:
                    file_content=json.loads(filein.read())
                for ou in file_content['Accounts']:
                    ou.__setitem__('Aaia_ParentOU',os.path.basename(dir))

                    #AWS provides JoinedTimestamp in organizations-list-accounts-for-parent api call
                    #in Epoch format. Converting to ISO 8601 Standard as it is the standard followed across
                    #all datetime in Aaia Nodes and Relations
                    ou.__setitem__('JoinedTimestamp',time.strftime('%Y-%m-%dT%H:%M:%SZ', time.localtime(ou['JoinedTimestamp'])))
                    organization_accounts_details.append(ou)
    return organization_accounts_details

def loadAWSOrganizationAccounts(neo4j_session,data_path,account_name):
    logger.info("[*] Loading AWS Organization Accounts into neo4j instance for AWS account '%s'", account_name)
    ingest_aws_organization_accounts=''' merge (account:AWSAccount {AccountNo:$AccountNo})
                            set account.OrganizationAccountArn=$OrganizationAccountArn,
                            account.AccountEmail=$AccountEmail,
                            account.AccountName=$AccountName,
                            account.Status=$Status,
                            account.JoinedMethod=$JoinedMethod,
                            account.JoinedTimestamp=datetime($JoinedTimestamp),
                            account.Aaia_ParentOU=$Aaia_ParentOU
                                    '''
    organization_accounts_details=getAWSOrganizationAccounts(data_path,account_name)

    for account in organization_accounts_details:
        neo4j_session.run(ingest_aws_organization_accounts,
                          AccountNo=account['Id'],
                          OrganizationAccountArn=account['Arn'],
                          AccountEmail=account['Email'],
                          AccountName=account['Name'],
                          Status=account['Status'],
                          JoinedMethod=account['JoinedMethod'],
                          JoinedTimestamp=account['JoinedTimestamp'],
                          Aaia_ParentOU=account['Aaia_ParentOU'])
    logger.info("[*] Completed loading AWS Organization Accounts into neo4j instance for AWS account '%s'", account_name)


def loadAWSOrganizationOURelations(neo4j_session,data_path,account_name):
    logger.info("[*] Loading AWS Organization OU Relations into neo4j instance for AWS account '%s'", account_name)
    ingest_aws_organizations_ou_relations='''match (parentou:AWSOrganizationOU)
                                            with parentou 
                                            match (childou:AWSOrganizationOU) where 
                                            childou.Aaia_ParentOU=parentou.Id with parentou,childou
                                            merge (childou)-[rel:Belongs_To_OU]->(parentou)
                                            '''
    neo4j_session.run(ingest_aws_organizations_ou_relations)
    logger.info("[*] Completed loading AWS Organization OU Relations into neo4j instance for AWS account '%s'", account_name)

def loadAWSOrganizationAccountRelations(neo4j_session,data_path,account_name):
    logger.info("[*] Loading AWS Organization Account OU Relations into neo4j instance for AWS account '%s'",account_name)

    ingest_aws_organization_account_relations='''
                                            match (account:AWSAccount) with account
                                            match (ou:AWSOrganizationOU) where account.Aaia_ParentOU=ou.Id 
                                            with ou,account
                                            merge (account)-[rel:Belongs_To_OU]->(ou)
                                            '''
    neo4j_session.run(ingest_aws_organization_account_relations)
    logger.info("[*] Completed loading AWS Organization Account OU Relations into neo4j instance for AWS account '%s'",account_name)

def getAWSOUAccountPolicyRelations(data_path,account_name):
    jqQuery='.Targets[] | {TargetArn: .Arn,Type: .Type}'
    policy_target_details=[]
    for file in os.listdir(os.path.join(data_path,account_name,"organizations","organizations-list-targets-for-policy")):
        with open(os.path.join(data_path,account_name,"organizations","organizations-list-targets-for-policy",file),"r") as filein:
            file_content=json.loads(filein.read())
        policy_targets=pyjq.all(jqQuery,file_content)

        #Getting the Policy Arn through PolicyID.
        #This avoids the different Policies from different Organizations with same policy ID(if multiple orgs loaded)
        #from being considered as same and establishing wrong relationships

        with open(os.path.join(data_path,account_name,"organizations","organizations-list-policies.json")) as filein:
            file_content_policy_arn=json.loads(filein.read())

        jqQuery_policy_arn='.Policies[] | select (.Id=="#policy_id#") | .Arn'
        policy_arn=pyjq.all(jqQuery_policy_arn.replace('#policy_id#',file),file_content_policy_arn)[0]

        for target in policy_targets:

            target.__setitem__('PolicyArn',policy_arn)
            policy_target_details.append(target)

    return policy_target_details

def loadAWSOUAccountPolicyRelations(neo4j_session,data_path,account_name):
    logger.info("[*] Loading AWS Organization OU Account Policy Relations into neo4j instance for AWS account '%s'",account_name)
    ingest_aws_policy_account_relations='''
                                        match (account:AWSAccount) where account.OrganizationAccountArn=$Arn
                                        with account 
                                        match (policy:AWSServiceControlPolicy) where policy.Arn=$PolicyArn
                                        with account,policy
                                        merge (account)-[:AWSPolicyAttachment]->(policy)
                                        '''

    ingest_aws_policy_ou_relations = '''
                                        match (ou:AWSOrganizationOU) where ou.Arn=$Arn
                                        with ou
                                        match (policy:AWSServiceControlPolicy) where policy.Arn=$PolicyArn
                                        with ou,policy
                                        merge (ou)-[:AWSPolicyAttachment]->(policy)
                                    '''
                                        

    policy_targets=getAWSOUAccountPolicyRelations(data_path, account_name)

    for target in policy_targets:
        if target['Type']=='ACCOUNT':
            neo4j_session.run(ingest_aws_policy_account_relations,Arn=target['TargetArn'],
                              PolicyArn=target['PolicyArn'],
                              )
        elif target['Type'] in ['ROOT','ORGANIZATIONAL_UNIT']:
            neo4j_session.run(ingest_aws_policy_ou_relations,Arn=target['TargetArn'],
                              PolicyArn=target['PolicyArn'])

    logger.info("[*] Completed loading AWS Organization OU Account Policy Relations into neo4j instance for AWS account '%s'",account_name)

def loadAWSOrganizations(neo4j_uri,neo4j_user,neo4j_password,data_path,account_name):
    neo4j_auth = (neo4j_user, neo4j_password)
    neo4j_driver = GraphDatabase.driver( neo4j_uri, auth=neo4j_auth, encrypted=False)
    with neo4j_driver.session() as neo4j_session:

        #Loads all the Service Control Policy in the Organization
        loadAWSServiceControlPolicy(neo4j_session,data_path,account_name)

        #Load AWS Organization Root Node
        loadAWSOrganizationRootNode(neo4j_session, data_path, account_name)

        #Load AWS Organization Master Account
        loadAWSOrganizationMasterAccount(neo4j_session, data_path, account_name)

        #Load AWS Organization OU
        loadAWSOrganizationOU(neo4j_session, data_path, account_name)

        #Loads the AWS Organization Accounts
        loadAWSOrganizationAccounts(neo4j_session, data_path, account_name)

        #Loads AWS Organization OU Relations
        loadAWSOrganizationOURelations(neo4j_session, data_path, account_name)

        #Loads AWS Organization Account OU Relations
        loadAWSOrganizationAccountRelations(neo4j_session, data_path, account_name)

        #Loads AWS Organization Policy Relations
        loadAWSOUAccountPolicyRelations(neo4j_session, data_path, account_name)


def help():
    pass

def main(config,args):
        neo4j_uri = config['neo4j_conf']['neo4j_uri']
        neo4j_user = config['neo4j_conf']['neo4j_user']
        neo4j_password = config['neo4j_conf']['neo4j_password']
        data_path = os.path.join(config['offline_datapath']['data_path'], "aws")
        account_name = args.name
        try:
                loadAWSOrganizations(neo4j_uri,neo4j_user,neo4j_password,data_path,account_name)
        except json.decoder.JSONDecodeError:
                # Json decode error occurs in Aaia mostly Organizations artifacts is not present with expected json.
                # Hence the assumption mentioned here.
                print("Possible that the current account is not Organization root. \nHence appropriate data for organizations may not be collected. \nSkipping organizations module from getting loaded.",file=sys.stderr)
