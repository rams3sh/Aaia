import sys
import os
import importlib
import pkgutil

__description__="loads the aws data into Aaia"

order_of_module_execution=["iam","organizations"]

def main(config,args):
	parent_dir_of_this_file=os.path.dirname(__file__)
	for module in order_of_module_execution:
		library = importlib.import_module(__package__ + "." + module)
		library.main(config, args)
		del (sys.modules[__package__ + "." + module])

def help():
	parent_dir_of_this_file=os.path.dirname(__file__)
	print(os.path.basename(parent_dir_of_this_file)+ " : "+__description__)
	for module in order_of_module_execution:
		library = importlib.import_module(__package__ + "." + module)
		library.help()
		del (sys.modules[__package__ + "." + module])

