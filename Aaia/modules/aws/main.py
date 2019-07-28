import sys
import os
import importlib
import pkgutil
import logging

logging.basicConfig()
logger=logging.getLogger(__name__)
logger.setLevel(logging.INFO)

__description__="manages the aws modules for Aaia"

def main(config,args):
	if args.module  and args.module !="main":
		if args.module == "help":
			help()
			return
		try:
			library=importlib.import_module(__package__+"."+args.module)
			if args.name:
				if args.name=="all":
					library.main(config,args)
					del (sys.modules[__package__+"."+args.module])
				else:
					print("-n missing argument. Currently supported value for name for this module by default is 'all'.",file=sys.stderr)
			else:
				print("-n missing argument. Currently supported value for name for this module by default is 'all'.",file=sys.stderr)
		except ModuleNotFoundError:
			logger.error("\nerror: invalid module")
			help()
	else:
		logger.error("\nerror: invalid module")
		help()
		
def help():
	print("\nAaia\n\navailable modules:")
	for importer, module_name, _ in pkgutil.iter_modules([os.path.dirname(__file__)]):
		if module_name !="main" :
			library=importlib.import_module(__package__+"."+module_name)
			print(module_name+ " : "+library.__description__)
			library.help()
			del (sys.modules[__package__+"."+module_name])

