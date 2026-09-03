from nhi.risk.helpers import (
    GLOBAL_NON_RESOURCE_ACTIONS,RESOURCE_SCOPED_ACTIONS, is_non_resource_action)


def analyze_resource(resource) -> bool:
    if isinstance(resource, str):
        resource_list = [resource]
    elif isinstance(resource, list):
        resource_list = resource
    else:
        return False

    for res in resource_list:
        if isinstance(res, str) and res.strip() == "*":
            return True
    return False


def partition_actions(actions):
    discovery_actions = []
    scoped_actions = []

    if isinstance(actions, str):
        actions_list = [actions]
    elif isinstance(actions, list):
        actions_list = actions
    else:
        return [], []

    for action in actions_list:
        if is_non_resource_action(action):
            discovery_actions.append(action)
        else:
            scoped_actions.append(action)

    return discovery_actions, scoped_actions

def scope_resource(resource, placeholder: str):
    if isinstance(resource, str):
        if resource.strip() == "*":
            return placeholder
        return resource

    if isinstance(resource, list):
        scoped_list = []
        for r in resource:
            if isinstance(r, str) and r.strip() == "*":
                scoped_list.append(placeholder)
            else:
                scoped_list.append(r)
        return scoped_list

    return resource


def split_policy_statement(
    policy_doc: dict,
    target_arn_placeholder: str = "arn:aws:*:*:*:placeholder/*",
) -> dict:
    if not isinstance(policy_doc, dict):
        return {}

    new_policy = {}
    for key, val in policy_doc.items():
        if key != "Statement":
            new_policy[key] = val

    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list):
        new_policy["Statement"] = []
        return new_policy

    new_statements = []

    for idx, statement in enumerate(statements,start=1):
        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != "Allow" or not analyze_resource(statement.get("Resource")) or ("NotAction" in statement or "NotResource" in statement):
            new_statements.append(statement)
        else:
            discovery, scoped = partition_actions(statement.get("Action"))
            base_sid = statement.get("Sid", f"Statement{idx}")

            if len(discovery) > 0 and len(scoped) > 0:
                discovery_statment = {
                    "Sid": base_sid + "Discovery",
                    "Effect": "Allow",
                    "Action": discovery,
                    "Resource": "*",
                }
                scoped_statment = {
                    "Sid": base_sid + "Scoped",
                    "Effect": "Allow",
                    "Action": scoped,
                    "Resource": scope_resource(statement.get("Resource"), target_arn_placeholder),
                }

                if "Condition" in statement:
                    discovery_statment["Condition"] = statement["Condition"]
                    scoped_statment["Condition"] = statement["Condition"]

                new_statements.append(discovery_statment)
                new_statements.append(scoped_statment)

            elif len(scoped) > 0 and len(discovery) == 0:
                scoped_statment = {
                    "Sid": base_sid,
                    "Effect": "Allow",
                    "Action": scoped,
                    "Resource": scope_resource(statement.get("Resource"), target_arn_placeholder),
                }
                if "Condition" in statement:
                    scoped_statment["Condition"] = statement["Condition"]

                new_statements.append(scoped_statment)

            else:
                new_statements.append(statement)

    new_policy["Statement"] = new_statements
    return new_policy