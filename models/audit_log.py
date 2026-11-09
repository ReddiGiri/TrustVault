
from extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.BigInteger, primary_key=True)

    actor_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("documents.id"),
        nullable=True
    )

    action = db.Column(db.String(100), nullable=False)

    outcome = db.Column(
        db.Enum("SUCCESS", "DENIED"),
        nullable=False
    )

    details = db.Column(db.JSON)

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )
