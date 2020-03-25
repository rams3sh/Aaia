import logging
from neo4j.v1 import GraphDatabase

logging.basicConfig()
logger=logging.getLogger(__name__)
logger.setLevel(logging.INFO)

__description__="cleans all data from neo4j instance"


def clean(neo4j_uri,neo4j_user,neo4j_password,account_name):
	#This function will clean all the data in the neo4j instance. 
	#Query needs to be designed such that it cleans only specific cloud , spcific account's
	#data.
	neo4j_auth = (neo4j_user, neo4j_password)
	neo4j_driver = GraphDatabase.driver( neo4j_uri, auth=neo4j_auth, encrypted=False)
	with neo4j_driver.session() as neo4j_session:
		if account_name=="all":
			logger.info("[*] Cleaning all data from neo4j instance")
			delete_aws_account_data="match (all) detach delete (all)"
			neo4j_session.run(delete_aws_account_data)
			logger.info("[*] Completed cleaning all data from neo4j instance")
		else:
			logger.error("error: invalid argument.\ntype -n 'all' for cleaning all data") 



def help():
	#Kept here just for maintaing a template
	pass

def main(config,args):
	neo4j_uri=config['neo4j_conf']['neo4j_uri']
	neo4j_user=config['neo4j_conf']['neo4j_user']
	neo4j_password=config['neo4j_conf']['neo4j_password']
	account_name=args.name
	clean(neo4j_uri,neo4j_user,neo4j_password,account_name)
