import sys
import importlib
import os
import logging

logging.basicConfig()
logger=logging.getLogger(__name__)
logger.setLevel(logging.INFO)

__description__="manages the aws actions"

def main(config,args):
	if args.action  and args.action !="main":
		if args.action=="help":
			help()
			return
		try:
			library=importlib.import_module(__package__+"."+args.action+".main")
			#clean_db is considered as action as in the current state, the action can 
			#delete only all data. 
			#Hence looping is not necessary for the action.
			#Further , the name 'all' is explicitly checked in clean_db action for proceeding with cleanup
			if args.name == "all" and not args.action== "clean_db":
				for account_name in os.listdir(os.path.join(config['offline_datapath']['data_path'],"aws")):
					args.name=account_name
					library.main(config,args)
			else:
				library.main(config,args)
			del (sys.modules[__package__+"."+args.action+".main"])
		except ModuleNotFoundError:
			logger.error("\nerror: invalid action")
			help()
	else:
		logger.error("\nerror: invalid action")
		help()

def help():
	print("\nAaia\n\navailable actions:")
	for module in os.listdir(os.path.dirname(__file__)):
		absolute_path=os.path.join(os.path.dirname(__file__),module)
		if os.path.isdir(absolute_path) and not module.startswith("_"):
			library=importlib.import_module(__package__+"."+module+".main")
			library.help()
			del (sys.modules[__package__+"."+module+".main"])
