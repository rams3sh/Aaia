from collections import OrderedDict
from policyuniverse import expander_minimizer,all_permissions
import json

def getPolicyStatementDetails(statement):
    '''
    These are the different element of a Policy Statement

    i. Action / NotAction
    ii. Effect
    iii. Resource / NotResource
    iv. Sid
    v. Condition
    vi. Principal / NotPrincipal
    Link : https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html

    This function parses the policy statement and gives values for all possible elements of a policy in a standard key value format
    '''

    # Determining Actions
    try:
        statement_action = statement['Action']
        statement_action_key = "Action"
    except KeyError:
        statement_action = statement['NotAction']
        statement_action_key = "NotAction"

    # Stringifying and Replacing list and set characters helps in linearising the lists / sets
    # PolicyStatement Relationships contain actions as one of the properties
    # Hence sorting is important , as every time the order keeps changing when the string is split.
    # Sorting helps from creating duplicate relationships when the data is synced again
    statement_action = sorted(set(
        str(statement_action).replace("'", "").replace("{", "").replace("}", "").replace("[", "").replace("]","").replace(" ", "").split(",")))

    # Determining Resource
    try:
        statement_resource = statement['Resource']
        statement_resource_key = "Resource"

    except KeyError:
        try:
            statement_resource = statement['NotResource']
            statement_resource_key = "NotResource"
        # In case there is no Resource (AssumeRole Policies do not have Resource mentioned)
        except KeyError:
            statement_resource = set()
            statement_resource_key = ""
    # Stringifying and Replacing list and set characters helps in linearising the lists / sets
    # PolicyStatement Relationships contain resources as one of the properties
    # Hence sorting is important , as every time the order keeps changing when the string is split.
    # Sorting helps from creating duplicate relationships when the data is synced again

    if statement_resource != set():
        statement_resource = sorted(set(
            str(statement_resource).replace("'", "").replace("{", "").replace("}", "").replace("[", "").replace("]","").replace(" ", "").split(",")))

    # Determining Effect
    statement_effect = statement['Effect']
    # Determining Principal

    # Principals are not part of every type of AWS Policy (Hence need for try and except)
    try:
        statement_principal = statement['Principal']
        statement_principal_key = "Principal"
    except KeyError:
        # In case of NotPrincipal
        try:
            statement_principal = statement['NotPrincipal']
            statement_principal_key = "NotPrincipal"

        # In case there is no principal (General AWS Policies do not have explicit mention of principals)
        except KeyError:
            statement_principal = set()
            statement_principal_key = ""

    if statement_principal:
        # In case of * as value for Principal
        if statement_principal == '*' or statement_principal == ['*']:
            # Sub Key should be AWS (Ref :https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html -> (Everyone (anonymous users))
            principal = OrderedDict()
            principal.__setitem__("AWS", ["*"])
            statement_principal = principal

        for key in statement_principal.keys():
            statement_principal[key] = sorted(set(
                str(statement_principal[key]).replace("'", "").replace("{", "").replace("}", "").replace("[","").replace("]", "").replace(" ", "").split(",")))

    try:
        if statement['Condition'] == {}:
            statement_condition = ""
        else:
            # To change it to return to non-string (In case of evaluation)
            # As of now , its been stringified as it is just used t display as
            # a property of the statement relation and not actually planned to
            # evaluate
            statement_condition = str(json.dumps(statement['Condition']))

    except KeyError:
        statement_condition = ""
    try:
        statement_sid = statement['Sid']
    except KeyError:
        statement_sid = ""

    # Policy Universe's get_actions_from_statement works only in Action and not
    # NotAction scenario. Hence temporarily converting the Action key to NotAction
    # and expanding the Action's Wild cards

    temp = OrderedDict()
    not_action_flag = 0
    for key in statement.keys():
        if key == "Action":
            temp.__setitem__(key, statement_action)
        elif key == "NotAction":
            temp.__setitem__("Action", statement_action)
            not_action_flag = 1
        else:
            temp.__setitem__(key, statement[key])

    # statement_aaia_expanded_action variable stores the expanded actions (including inverted NotAction cases).

    statement_aaia_expanded_action = ""
    if not_action_flag == 0:
        statement_aaia_expanded_action = set(expander_minimizer.get_actions_from_statement(temp))
    elif not_action_flag == 1:
        # In case of NotAction all the mentioned actions will be inverted and added to statement_aaia_expanded_action
        statement_aaia_expanded_action = set(
            all_permissions.difference(expander_minimizer.get_actions_from_statement(temp)))

    statement_aaia_expanded_action = sorted(
        str(statement_aaia_expanded_action).replace("'", "").replace("{", "").replace("}", "").replace("[", "").replace(
            "]", "").replace(" ", "").split(","))

    statement_aaia_expanded_action = str(statement_aaia_expanded_action).replace("'", "").replace("{", "").replace("}",
                                                                                                                   "").replace(
        "[", "").replace("]", "").replace(" ", "")

    # ActionKey,ResourceKey,PrincipalKey determines whether it is Action/NotAction , Resource/NotResource and Principal/NotPrincipal respectively in the policy
    # wheras the Action,Resource,Policy in the below OrderedDict() returns actions,resources,principal respectively  as values
    # Example {"NotAction": "iam:*"} will be returned as
    # { "ActionKey" : "NotAction, "Action" : "iam:*"}

    # Hence one has to consider both ActionKey/ResourceKey/PrincipalKey along with Action/Resource/Principal
    # to evaluate the policy

    policy_statement_details = OrderedDict()
    policy_statement_details.__setitem__('Action', statement_action)
    policy_statement_details.__setitem__('ActionKey', statement_action_key)
    policy_statement_details.__setitem__('Aaia_ExpandedAction', statement_aaia_expanded_action)
    policy_statement_details.__setitem__('Effect', statement_effect)
    policy_statement_details.__setitem__('Resource', statement_resource)
    policy_statement_details.__setitem__('ResourceKey', statement_resource_key)
    policy_statement_details.__setitem__('Condition', statement_condition)
    policy_statement_details.__setitem__('Principal', statement_principal)
    policy_statement_details.__setitem__('PrincipalKey', statement_principal_key)
    policy_statement_details.__setitem__('Sid', statement_sid)

    return policy_statement_details


def getPolicyDocumentDetails(policy):
    '''
    These are the different element of a Policy Document

    i. Id
    ii. Version
    iii. Statement
    '''

    try:
        document_id = policy['Id']
    except KeyError:
        document_id = ""

    try:
        document_version = policy['Version']
    except KeyError:
        document_version = ""

    try:
        document_statement = policy['Statement']
        if type(document_statement) == list:
            pass
        else:
            document_statement = [policy['Statement']]

    except KeyError:
        document_statement = ""

    policy_document_details = OrderedDict()
    policy_document_details.__setitem__('Id', document_id)
    policy_document_details.__setitem__('Version', document_version)
    policy_document_details.__setitem__('Statement', document_statement)

    return policy_document_details
