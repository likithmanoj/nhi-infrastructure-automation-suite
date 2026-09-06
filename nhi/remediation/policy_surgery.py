from nhi.risk.helpers import is_non_resource_action


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


def scope_resource(resource, replacement_arns):
    """
    Replaces wildcard '*' with replacement_arns (string or list of ARNs)
    while preserving existing sibling ARNs.
    """
    if isinstance(replacement_arns, str):
        replacement_arns = [replacement_arns]

    if isinstance(resource, str):
        if resource.strip() == "*":
            return replacement_arns if len(replacement_arns) > 1 else replacement_arns[0]
        return resource

    if isinstance(resource, list):
        scoped_list = []
        for r in resource:
            if isinstance(r, str) and r.strip() == "*":
                scoped_list.extend(replacement_arns)
            else:
                scoped_list.append(r)
        return scoped_list

    return resource


def split_policy_statement(
    policy_doc: dict,
    target_arns: list[str] | str = "arn:aws:*:*:*:placeholder/*",
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

    for idx, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            continue

        if (
            statement.get("Effect") != "Allow"
            or not analyze_resource(statement.get("Resource"))
            or ("NotAction" in statement or "NotResource" in statement)
        ):
            new_statements.append(statement)
            continue

        discovery, scoped = partition_actions(statement.get("Action"))
        base_sid = statement.get("Sid", f"Statement{idx}")

        if len(discovery) > 0 and len(scoped) > 0:
            discovery_statement = {
                "Sid": f"{base_sid}Discovery",
                "Effect": "Allow",
                "Action": discovery,
                "Resource": "*",
            }
            scoped_statement = {
                "Sid": f"{base_sid}Scoped",
                "Effect": "Allow",
                "Action": scoped,
                "Resource": scope_resource(statement.get("Resource"), target_arns),
            }

            if "Condition" in statement:
                discovery_statement["Condition"] = statement["Condition"]
                scoped_statement["Condition"] = statement["Condition"]

            new_statements.append(discovery_statement)
            new_statements.append(scoped_statement)

        elif len(scoped) > 0 and len(discovery) == 0:
            scoped_statement = {
                "Sid": f"{base_sid}Scoped" if statement.get("Sid") else base_sid,
                "Effect": "Allow",
                "Action": scoped,
                "Resource": scope_resource(statement.get("Resource"), target_arns),
            }
            if "Condition" in statement:
                scoped_statement["Condition"] = statement["Condition"]

            new_statements.append(scoped_statement)

        elif len(discovery) > 0 and len(scoped) == 0:
            discovery_statement = {
                "Sid": f"{base_sid}Discovery" if statement.get("Sid") else base_sid,
                "Effect": "Allow",
                "Action": discovery,
                "Resource": "*",
            }
            if "Condition" in statement:
                discovery_statement["Condition"] = statement["Condition"]

            new_statements.append(discovery_statement)        
        else:
            new_statements.append(statement)

    new_policy["Statement"] = new_statements
    return new_policy