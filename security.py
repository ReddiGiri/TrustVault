
from extensions import db

from models.document import Document
from models.permission import Permission


def can_access_document(user, document_id, action="READ"):
    """
    Central authorization function.

    READ:
        Allows viewing and downloading.

    EDIT:
        Allows modifying the original document
        through authorized application routes.

    Returns:
        True  = Access allowed
        False = Access denied
    """

    # 1. Validate user
    if user is None or not getattr(user, "is_authenticated", False):
        return False

    # 2. Validate requested action
    if action not in ("READ", "EDIT"):
        return False

    # 3. Find requested document
    document = db.session.get(Document, document_id)

    if document is None:
        return False

    # 4. Admin policy
    if user.role == "ADMIN":
        return True

    # 5. Document owner has full access
    if document.owner_id == user.id:
        return True

    # 6. Find explicit user permission
    permission = Permission.query.filter_by(
        document_id=document_id,
        user_id=user.id
    ).first()

    # 7. No permission means deny
    if permission is None:
        return False

    # 8. READ permission
    if action == "READ":
        return permission.permission_type in ("READ", "EDIT")

    # 9. EDIT permission
    if action == "EDIT":
        return permission.permission_type == "EDIT"

    # 10. Default deny
    return False


def can_view_document(user, document_id):
    """Check whether user can view a document."""

    return can_access_document(
        user,
        document_id,
        action="READ"
    )


def can_download_document(user, document_id):
    """Check whether user can download a document."""

    return can_access_document(
        user,
        document_id,
        action="READ"
    )


def can_edit_document(user, document_id):
    """Check whether user can edit a document."""

    return can_access_document(
        user,
        document_id,
        action="EDIT"
    )


def can_share_document(user, document_id):
    """
    Only the document owner can share
    or revoke document permissions.
    """

    if user is None or not getattr(user, "is_authenticated", False):
        return False

    document = db.session.get(Document, document_id)

    if document is None:
        return False

    return document.owner_id == user.id
