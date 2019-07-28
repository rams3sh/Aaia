import argparse
import configparser

config=configparser.ConfigParser()
config.read('Aaia.conf')

parser=argparse.ArgumentParser(description="Aaia")
parser.add_argument('-n','--name',metavar="",type=str,help='name/alias of the AWS account')


group=parser.add_mutually_exclusive_group(required=True)
group.add_argument('-a','--action',metavar="",type=str,help='action to be taken by Aaia. type -a \'help\' for more details')
group.add_argument('-m','--module',metavar="",type=str,help='module to be invoked by Aaia. type -m \'help\' for more details')

args=parser.parse_args()

if args.action:
	import actions.aws.main as action
	action.main(config,args)

elif args.module:
	import modules.aws.main as module
	module.main(config,args)
