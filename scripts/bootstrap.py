"""First-run bootstrap: organisation and the initial administrator.

Deliberately refuses to create a default password (ТЗ 44: "no default credentials"). The
password is either supplied on stdin or generated and printed once, and the account must change
it at first login.
"""

from __future__ import annotations

import argparse
import getpass
import secrets
import string
import sys

from msp_api.config import get_settings
from msp_api.db.models import MailboxIdentity, Organization, User
from msp_api.db.session import session_scope
from msp_api.security.audit import AuditAction, record
from msp_api.security.auth import MIN_PASSWORD_LENGTH, hash_password
from msp_contracts import Role
from sqlalchemy import func, select

_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*-_=+"


def generate_password(length: int = 20) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialise the platform and the first admin")
    parser.add_argument("--email", help="administrator email (defaults to MSP_BOOTSTRAP_ADMIN_EMAIL)")
    parser.add_argument("--organization", help="organisation name")
    parser.add_argument(
        "--generate-password",
        action="store_true",
        help="generate a password and print it once instead of prompting",
    )
    parser.add_argument(
        "--role",
        default=Role.SECURITY_ADMIN.value,
        choices=[r.value for r in Role],
        help="role for the bootstrap account",
    )
    args = parser.parse_args()

    settings = get_settings()
    email = (args.email or settings.bootstrap_admin_email or "").strip().lower()
    if not email or "@" not in email:
        print(
            "error: an administrator email is required (--email or MSP_BOOTSTRAP_ADMIN_EMAIL)",
            file=sys.stderr,
        )
        return 2

    if args.generate_password:
        password = generate_password()
        generated = True
    else:
        generated = False
        password = getpass.getpass("Password for the administrator: ")
        if password != getpass.getpass("Repeat the password: "):
            print("error: passwords do not match", file=sys.stderr)
            return 2
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"error: the password must be at least {MIN_PASSWORD_LENGTH} characters", file=sys.stderr)
            return 2

    with session_scope() as session:
        org = session.execute(select(Organization)).scalars().first()
        if org is None:
            org = Organization(
                name=args.organization or settings.organization_name,
                corporate_domains=list(settings.corporate_domain_list),
                trusted_infrastructure_domains=list(settings.trusted_infrastructure_list),
            )
            session.add(org)
            session.flush()
            print(f"created organisation '{org.name}' ({org.id})")
        else:
            print(f"using existing organisation '{org.name}' ({org.id})")

        existing = session.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()
        if existing is not None:
            print(f"error: user {email} already exists", file=sys.stderr)
            return 1

        user = User(
            organization_id=org.id,
            email=email,
            display_name=email.split("@")[0],
            role=Role(args.role),
            password_hash=hash_password(password),
            auth_source="local",
            must_change_password=True,
        )
        session.add(user)
        session.flush()

        if (
            session.execute(
                select(MailboxIdentity).where(
                    MailboxIdentity.organization_id == org.id,
                    func.lower(MailboxIdentity.address) == email,
                )
            ).scalar_one_or_none()
            is None
        ):
            session.add(
                MailboxIdentity(
                    organization_id=org.id,
                    user_id=user.id,
                    address=email,
                    display_name=user.display_name,
                    manual_override=True,
                )
            )

        record(
            session,
            action=AuditAction.USER_CHANGED,
            actor_email="bootstrap",
            actor_role="system",
            organization_id=org.id,
            object_type="user",
            object_id=user.id,
            detail={"operation": "bootstrap", "role": user.role.value},
        )

    print(f"created administrator {email} with role {args.role}")
    if generated:
        print("\n  Generated password (shown once, store it in your password manager):\n")
        print(f"    {password}\n")
    print("The account must change its password at first login.")
    if settings.require_mfa_for_privileged:
        print("MFA is required for privileged roles: configure it in the IdP before the pilot.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
