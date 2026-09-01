"""
attributes.py — Access-control policy helpers.

This module handles Attribute-Based Access Control (ABAC) using attributes
stored in Django's database. Attributes are assigned by an administrator,
rather than being supplied by the user requesting access.
"""


# ---- USER ATTRIBUTE LOOKUP ----
# Builds a dictionary of the trusted attributes assigned to a user.
def get_user_attribute_dict(profile):
    """Returns {key: value} for a Profile, sourced from admin-assigned UserAttribute rows."""
    if profile is None:
        return {}
    return {a.key: a.value for a in profile.attributes.all()}


# ---- ACCESS POLICY VALIDATION ----
# Checks whether a user's verified attributes satisfy a file's access policy.
def check_access_policy(access_policy, user_attributes):
    """
    access_policy: "key:value, key:value" string defined by the file owner.
    user_attributes: {key: value} dictionary from the trusted attribute store.

    Returns True only when every valid key:value condition in the policy
    exactly matches an attribute assigned to the user.
    """
    if not access_policy:
        return False
    policy_pairs = [p.strip() for p in access_policy.split(",") if p.strip()]
    if not policy_pairs:
        return False
    for pair in policy_pairs:
        if ":" not in pair:
            continue
        key, value = pair.split(":", 1)
        key, value = key.strip(), value.strip()
        if user_attributes.get(key) != value:
            return False
    return True