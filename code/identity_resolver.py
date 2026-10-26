"""
GhostTrace Identity Resolver
HackerRank Orchestrate October 2026 | Ghost Data Still Exists

Resolves current and historical identity profiles by merging user_identities.csv
and user_audit_log.csv into unified identity graphs.
"""

import csv
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class UserIdentityProfile:
    user_id: str
    current_name: str
    current_email: str
    current_phone: str
    email_hash: str
    updated_at: str
    all_emails: Set[str] = field(default_factory=set)
    all_phones: Set[str] = field(default_factory=set)
    all_names: Set[str] = field(default_factory=set)
    all_email_hashes: Set[str] = field(default_factory=set)
    audit_history: List[Dict[str, str]] = field(default_factory=list)


class IdentityResolver:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.profiles_by_user_id: Dict[str, UserIdentityProfile] = {}
        self.email_to_user_id: Dict[str, str] = {}
        self.phone_to_user_id: Dict[str, str] = {}
        self.email_hash_to_user_id: Dict[str, str] = {}
        self.load()

    def load(self):
        identities_file = os.path.join(self.dataset_dir, "user_identities.csv")
        audit_file = os.path.join(self.dataset_dir, "user_audit_log.csv")

        # 1. Load current identities
        if os.path.isfile(identities_file):
            with open(identities_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row["user_id"].strip()
                    name = row["name"].strip()
                    email = row["email"].strip().lower()
                    phone = row["phone"].strip()
                    email_hash = row["email_hash"].strip()
                    updated_at = row["updated_at"].strip()

                    profile = UserIdentityProfile(
                        user_id=uid,
                        current_name=name,
                        current_email=email,
                        current_phone=phone,
                        email_hash=email_hash,
                        updated_at=updated_at,
                    )
                    profile.all_emails.add(email)
                    profile.all_phones.add(phone)
                    profile.all_names.add(name)
                    if email_hash:
                        profile.all_email_hashes.add(email_hash)
                        self.email_hash_to_user_id[email_hash] = uid

                    self.profiles_by_user_id[uid] = profile
                    self.email_to_user_id[email] = uid
                    if phone:
                        self.phone_to_user_id[phone] = uid

        # 2. Ingest historical audit logs
        if os.path.isfile(audit_file):
            with open(audit_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row["user_id"].strip()
                    field_name = row["field_name"].strip()
                    old_val = row["old_value"].strip()
                    new_val = row["new_value"].strip()
                    event_time = row["event_time"].strip()

                    profile = self.profiles_by_user_id.get(uid)
                    if not profile:
                        # Fallback for user seen only in audit log
                        profile = UserIdentityProfile(
                            user_id=uid,
                            current_name="",
                            current_email="",
                            current_phone="",
                            email_hash="",
                            updated_at=event_time,
                        )
                        self.profiles_by_user_id[uid] = profile

                    profile.audit_history.append(row)

                    if field_name == "email":
                        old_email = old_val.lower()
                        new_email = new_val.lower()
                        profile.all_emails.add(old_email)
                        profile.all_emails.add(new_email)
                        self.email_to_user_id[old_email] = uid
                        self.email_to_user_id[new_email] = uid
                    elif field_name == "phone":
                        profile.all_phones.add(old_val)
                        profile.all_phones.add(new_val)
                        self.phone_to_user_id[old_val] = uid
                        self.phone_to_user_id[new_val] = uid
                    elif field_name == "name":
                        profile.all_names.add(old_val)
                        profile.all_names.add(new_val)
                    elif field_name == "email_hash":
                        profile.all_email_hashes.add(old_val)
                        profile.all_email_hashes.add(new_val)
                        self.email_hash_to_user_id[old_val] = uid
                        self.email_hash_to_user_id[new_val] = uid

    def resolve_by_email(self, email: str) -> Optional[UserIdentityProfile]:
        clean_email = email.strip().lower()
        uid = self.email_to_user_id.get(clean_email)
        if uid:
            return self.profiles_by_user_id.get(uid)
        return None

    def resolve_by_user_id(self, user_id: str) -> Optional[UserIdentityProfile]:
        return self.profiles_by_user_id.get(user_id.strip())

    def get_all_identifiers(self, profile: UserIdentityProfile) -> Set[str]:
        """Returns all searchable tokens for a user (emails, user_id, phones, names, hashes)."""
        tokens = {profile.user_id}
        tokens.update(profile.all_emails)
        tokens.update(profile.all_phones)
        tokens.update(profile.all_names)
        tokens.update(profile.all_email_hashes)
        return tokens
