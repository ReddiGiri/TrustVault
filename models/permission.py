
from extensions import db


class Permission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("documents.id"),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    permission_type = db.Column(
        db.Enum("READ", "EDIT"),
        nullable=False
    )

    granted_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )

    document = db.relationship("Document", backref="permissions")
    user = db.relationship("User", backref="received_permissions")
