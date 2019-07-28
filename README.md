# Aaia



## **What does Aaia do ?**

Aaia helps in visualizing the AWS IAM in a graphical fashion with help of Neo4j. This helps in identifying the outliers easily.Since it is based on neo4j , one can query the graph using cypher queries to find the anomalies.

Aaia also supports modules to programatically fetch data from neo4j database and process it in a custom fashion. This is mostly useful if any complex comparision or logic has to be applied to a given data which would otherwise be not easy through cypher queries.

Aaia was initially intended to be a tool to enumerate privelege esclation possibilities and find loop holes in AWS IAM. It was inspired from the quote by [@JohnLaTwC](https://twitter.com/JohnLaTwC)

"Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win."




## **Why the name "Aaia" ?**

Aaia in [Tamil](https://en.wikipedia.org/wiki/Tamil_language) means grandmother. Aaia knows everything about the family. She can easily connect who is related to whom; and how ;and give you the connection within a split second. She is a living graph database. :P 
Since "Aaia" (this tool) also does more or less the same, hence the name.


## **Installation**

### Install the neo4j Database

Instructions [here](https://neo4j.com/docs/operations-manual/current/installation/)

Setup the username , password and bolt connection uri in Aaia.conf file. 
An example is already present in Aaia.conf.


### Clone this repository
git clone https://github.com/rams3sh/Aaia

cd Aaia/

### Create a virtual environment
python3 -m venv env

### Activate the virtual environment
source env/bin/activate  # (In case of Linux / MAC)

env\Scripts\activate.bat # (In case of Windows)

### Install the dependencies

python -m pip install -r requirements.txt

## **Using Aaia**

### Collecting the data from AWS

First, Ensure you have aws credentials configured.
Refer [this](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) for help.

Once the crendential is setup. 

Run:- 
```
./Aaia_aws_collector.sh <profile_name>
```

### Loading the collected data to Neo4j DB 

```
python Aaia.py -n <profile_name> -a load_Data
```

-n supports "all" as value which means load all data collected and present within offline_data folder.


Now we are ready to use Aaia.


### Audit IAM through a custom module

As of now , a sample custom module is given as a skeleton example. One can use this build to various other custom modules.

```
python Aaia.py -n all -m iam_sample_audit
```


## Thanks to 

Aaia is influenced and inspired from various amazing open source tools. Huge Shoutout to :-

* [Cloudmapper](https://github.com/duo-labs/cloudmapper)
* [Cartography](https://github.com/lyft/cartography/tree/master/cartography)
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


