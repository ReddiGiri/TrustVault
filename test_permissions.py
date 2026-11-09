
import uuid
import pytest

from app import app
from extensions import db
from models.user import User
from models.document import Document
from models.permission import Permission
from security import can_access_document


@pytest.fixture
def app_context():
    with app.app_context():
        yield
        db.session.rollback()


@pytest.fixture
def isolated_records(app_context):
    """Create temporary test records and roll them back."""

    owner = db.session.get(User, 1)

    assert owner is not None

    suffix = uuid.uuid4().hex

    viewer = User(
        name="Test Viewer",
        email=f"test_{suffix}@example.com",
        password_hash="test-only-hash",
        role="VIEWER"
    )

    db.session.add(viewer)
    db.session.flush()

    document = Document(
        owner_id=owner.id,
        title="Temporary Security Test",
        category="Testing",
        filename="test.pdf",
        storage_path="private_uploads/test.pdf"
    )

    db.session.add(document)
    db.session.flush()

    yield owner, viewer, document

    db.session.rollback()


def test_owner_can_read_document(app_context):
    giri = db.session.get(User, 1)

    assert giri is not None
    assert can_access_document(giri, 1, "READ") is True


def test_owner_can_edit_document(app_context):
    giri = db.session.get(User, 1)

    assert giri is not None
    assert can_access_document(giri, 1, "EDIT") is True


def test_viewer_can_read_shared_document(app_context):
    ravi = db.session.get(User, 2)

    assert ravi is not None
    assert can_access_document(ravi, 1, "READ") is True


def test_viewer_cannot_edit_read_only_document(app_context):
    ravi = db.session.get(User, 2)

    assert ravi is not None
    assert can_access_document(ravi, 1, "EDIT") is False


def test_user_cannot_access_nonexistent_document(app_context):
    ravi = db.session.get(User, 2)

    assert ravi is not None
    assert can_access_document(ravi, 999999, "READ") is False


def test_invalid_permission_action_is_denied(app_context):
    ravi = db.session.get(User, 2)

    assert ravi is not None
    assert can_access_document(ravi, 1, "DELETE") is False


def test_idor_unshared_document_access_is_denied(isolated_records):
    owner, viewer, document = isolated_records

    assert document.owner_id == owner.id

    # Viewer knows the document ID but has no permission.
    assert can_access_document(
        viewer, document.id, "READ"
    ) is False

    assert can_access_document(
        viewer, document.id, "EDIT"
    ) is False


def test_revoked_permission_blocks_read_and_edit(isolated_records):
    owner, viewer, document = isolated_records

    permission = Permission(
        document_id=document.id,
        user_id=viewer.id,
        permission_type="EDIT"
    )

    db.session.add(permission)
    db.session.flush()

    # Permission is initially granted.
    assert can_access_document(
        viewer, document.id, "READ"
    ) is True

    assert can_access_document(
        viewer, document.id, "EDIT"
    ) is True

    # Revoke permission.
    db.session.delete(permission)
    db.session.flush()

    # Access must be denied immediately.
    assert can_access_document(
        viewer, document.id, "READ"
    ) is False

    assert can_access_document(
        viewer, document.id, "EDIT"
    ) is False
