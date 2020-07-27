# Aaia
(A)n(a)lysis  of (I)dentity and (A)ccess

Note: Expansion created post the name was decided :P



## **What does Aaia do ?**

Aaia (pronounced as shown [here](https://translate.google.co.in/#view=home&op=translate&sl=ta&tl=en&text=Aaya) ) helps in visualizing AWS IAM and Organizations in a graph format with help of Neo4j. This helps in identifying the outliers easily. Since it is based on neo4j , one can query the graph using cypher queries to find the anomalies.

Aaia also supports modules to programatically fetch data from neo4j database and process it in a custom fashion. This is mostly useful if any complex comparision or logic has to be applied which otherwise would not be easy through cypher queries.

Aaia was initially intended to be a tool to enumerate privelege esclation possibilities and find loop holes in AWS IAM. It was inspired from the quote by [@JohnLaTwC](https://twitter.com/JohnLaTwC)

"Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win."




## **Why the name "Aaia" ?**

Aaia in [Tamil](https://en.wikipedia.org/wiki/Tamil_language) means grandma. In general, Aaia knows everything about the family. She can easily connect who is related to whom; and how ;and give you the connection within a split second. 
She is a living graph database. :P 

Since "Aaia" (this tool) also does more or less the same, hence the name.


## **Installation**

### Install the neo4j Database

#### 1. Installation using Docker (Recommended)

i. Install Docker Runtime

Check the official documentation regarding installation [here](https://docs.docker.com/engine/install/).

ii. Run the following docker command 
```
docker run -p 7687:7687 -p 7474:7474 -v `pwd`/neo4j/data:/data -v `pwd`/neo4j/logs:/logs -e NEO4J_AUTH=neo4j/test neo4j:3.5.17
```
Note : Above command persists neo4j data in your disk. However, feel free to modify for your needs and change the auth according to your preference. The credentials provided here should be configured in `Aaia.conf` file as well.

#### 2. Installation using binary

Instructions [here](https://neo4j.com/docs/operations-manual/current/installation/)

Setup the username , password and bolt connection uri in Aaia.conf file. 
An example format is given in Aaia.conf file already.

**Note:** 
Aaia has been tested with neo4j v 3.5.17. It may work with older versions. 
Neo4j has introduced some new changes post v 4.0 which has been found not compatible with Aaia's current codebase. 


### Install OS dependency ###

#### Debian :- ####

apt-get install awscli jq

#### Redhat / Fedora / Centos / Amazon Linux :- ####

yum install awscli  jq

#### Note: ####
These packages are needed for Aaia_aws_collector.sh script. Ensure these packages are present in the base system from where the collector script is being run.

### Clone this repository
git clone https://github.com/rams3sh/Aaia

cd Aaia/

### Create a virtual environment
python3 -m venv env


### Activate the virtual environment
source env/bin/activate  

**Note:** 
Aaia depends on pyjq library which is not stable in windows currently. 
Hence Aaia is not supported for Windows OS. 

### Install the dependencies

python -m pip install -r requirements.txt

## **Using Aaia**

### Setting up Permissions in AWS ###

Aaia would require following AWS permissions for collector script to collect relevant data from AWS

```
iam:GenerateCredentialReport
iam:GetCredentialReport
iam:GetAccountAuthorizationDetails
iam:ListUsers
iam:GetUser
iam:ListGroups
iam:ListRoles
iam:GetRole
iam:GetPolicy
iam:GetAccountPasswordPolicy
iam:GetAccountSummary
iam:ListAccountAliases
organizations:ListAccountsForParent
organizations:ListOrganizationalUnitsForParent
organizations:DescribeOrganization
organizations:ListRoots
organizations:ListAccounts
organizations:ListTagsForResource
organizations:ListPolicies
organizations:ListTargetsForPolicy
organizations:DescribePolicy
organizations:ListAWSServiceAccessForOrganization
```

"Organizations" related permissions can be ommitted. However , all the above mentioned "IAM" related permissions are necessary.

Ensure the permissions are available to the user / role / any aws principal which will be used for collection of data for the collector script.



### Collecting data from AWS

Ensure you have aws credentials configured.
Refer [this](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) for help.

Once the crendential is setup. 

Run:- 
```
./Aaia_aws_collector.sh <profile_name>
```
Ensure the output format of the aws profile being used for data collection is set to json as Aaia expects the data collected to be in json format. 


#### Note:- ####
In case of a requirement where data has to be collected from another instance; copy "Aaia_aws_collector.sh" file to the remote instance , run it and copy the generated "offline_data" folder to the Aaia path in the instance where Aaia is setup and carry on with following steps.
This will be helpful in cases of consulting or client audit.


### Loading the collected data to Neo4j DB 

```
python Aaia.py -n <profile_name> -a load_data
```

-n supports "all" as value which means load all data collected and present within offline_data folder.

#### Note: ####
Please ensure you do not have profile as "all" in the credentials file as it may conflict with the argument. :P 

Now we are ready to use Aaia.


### Audit IAM through a custom module

As of now , a sample module is given as a skeleton example. One can consider this as a reference for building custom modules.

```
python Aaia.py -n all -m iam_sample_audit
```


## Thanks to 

Aaia is influenced and inspired from various amazing open source projects. Huge Shoutout to :-

* [Cloudmapper](https://github.com/duo-labs/cloudmapper)
* [Cartography](https://github.com/lyft/cartography)
* [BloodHound](https://github.com/BloodHoundAD/BloodHound)


## Aaia in Action

[![asciicast](https://asciinema.org/a/259578.png)](https://asciinema.org/a/259578)


## Screenshots

A sample visual of a dummy AWS Account's IAM 

![Image of AWS IAM Neo4j Visual](https://github.com/rams3sh/Aaia/blob/master/screenshots/AWS_IAM_Graph.PNG)



A sample visual of a result of a cypher query to find all relations of a user in AWS IAM

![Image of AWS IAM query result Visual](https://github.com/rams3sh/Aaia/blob/master/screenshots/AWS_IAM_example_cypher_query.PNG)



## TO DO

* Write a detailed documentation for understanding Aaia's Neo4j DB Schema
* Write a detailed documentation for developing custom modules for Aaia
* Write custom modules to evaluate [28 AWS privelege escalation methods](https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation) identified by RhinoSecurity.
* Provide a cheatsheet of queries for identifying simple issues in AWS IAM
* Extend Aaia to other cloud providers.


