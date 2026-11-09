
from extensions import db


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100))

    filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(500), nullable=False)

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )

    updated_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp()
    )

    owner = db.relationship("User", backref="documents")
