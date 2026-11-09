
from flask import Blueprint, render_template, request, abort
from flask_login import login_required, current_user

from models.audit_log import AuditLog
from models.user import User
from models.document import Document


admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin/activity")
@login_required
def activity():

    # Only ADMIN can view audit activity.
    if current_user.role != "ADMIN":
        abort(403)

    page = request.args.get("page", 1, type=int)
    action = request.args.get("action", "").strip()
    outcome = request.args.get("outcome", "").strip().upper()

    query = AuditLog.query

    # Filter by action.
    if action:
        query = query.filter(AuditLog.action == action)

    # Filter by outcome.
    if outcome in ("SUCCESS", "DENIED"):
        query = query.filter(AuditLog.outcome == outcome)

    # Newest activity first.
    pagination = query.order_by(
        AuditLog.created_at.desc()
    ).paginate(
        page=page,
        per_page=20,
        error_out=False
    )

    logs = pagination.items

    # Retrieve associated users and documents.
    user_ids = {log.actor_id for log in logs if log.actor_id}
    document_ids = {
        log.document_id for log in logs if log.document_id
    }

    users = {
        user.id: user
        for user in User.query.filter(User.id.in_(user_ids)).all()
    } if user_ids else {}

    documents = {
        doc.id: doc
        for doc in Document.query.filter(
            Document.id.in_(document_ids)
        ).all()
    } if document_ids else {}

    return render_template(
        "admin_activity.html",
        logs=logs,
        users=users,
        documents=documents,
        pagination=pagination,
        selected_action=action,
        selected_outcome=outcome
    )
