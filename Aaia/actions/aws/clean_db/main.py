import sys
import os
import importlib
import pkgutil

__description__="cleans the aws data from Aaia (Warning : This deletes all data from Aaia)"

def main(config,args):
	parent_dir_of_this_file=os.path.dirname(__file__)
	for importer, module_name, _ in pkgutil.iter_modules([parent_dir_of_this_file]):
		if module_name !="main" :
			library=importlib.import_module(__package__+"."+module_name)
			library.main(config,args)
			del (sys.modules[__package__+"."+module_name])

def help():
	parent_dir_of_this_file=os.path.dirname(__file__)
	print(os.path.basename(parent_dir_of_this_file)+ " : "+__description__)
	for importer, module_name, _ in pkgutil.iter_modules([parent_dir_of_this_file]):
		if module_name !="main" :
			library=importlib.import_module(__package__+"."+module_name)
			print("\t-> "+library.__description__)
			library.help()
			del (sys.modules[__package__+"."+module_name])

