
import os
import uuid
import shutil
import zipfile
from datetime import date

from flask import (
    Blueprint,
    request,
    redirect,
    url_for,
    flash,
    render_template,
    send_file,
    abort
)

from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from extensions import db
from models.user import User
from models.document import Document
from models.permission import Permission
from models.audit_log import AuditLog
from security import can_access_document


documents_bp = Blueprint("documents", __name__)

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

UPLOAD_FOLDER = os.path.join(BASE_DIR, "private_uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "docx", "png", "jpg", "jpeg"}
MAX_FILE_SIZE = 10 * 1024 * 1024


# --------------------------------------------------
# FILE VALIDATION
# --------------------------------------------------

def validate_uploaded_file(file, filename):

    if not filename or "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        return False

    try:
        file.stream.seek(0, os.SEEK_END)
        file_size = file.stream.tell()
        file.stream.seek(0)

        if file_size == 0 or file_size > MAX_FILE_SIZE:
            return False

        header = file.stream.read(1024)
        file.stream.seek(0)

        if extension == "pdf":
            return header.startswith(b"%PDF-")

        if extension == "png":
            return header.startswith(b"\x89PNG\r\n\x1a\n")

        if extension in ("jpg", "jpeg"):
            return header.startswith(b"\xff\xd8\xff")

        if extension == "docx":
            try:
                with zipfile.ZipFile(file.stream) as archive:
                    names = set(archive.namelist())

                    valid_docx = (
                        "[Content_Types].xml" in names
                        and "word/document.xml" in names
                    )

                file.stream.seek(0)
                return valid_docx

            except (zipfile.BadZipFile, OSError):
                file.stream.seek(0)
                return False

        return False

    except (OSError, ValueError):
        file.stream.seek(0)
        return False


# --------------------------------------------------
# DOCUMENTS, SEARCH AND FILTERS
# --------------------------------------------------

@documents_bp.route("/documents")
@login_required
def my_documents():

    if current_user.role == "ADMIN":

        documents = Document.query.all()

    else:

        owned_documents = Document.query.filter_by(
            owner_id=current_user.id
        ).all()

        shared_permissions = Permission.query.filter_by(
            user_id=current_user.id
        ).all()

        shared_documents = [
            permission.document
            for permission in shared_permissions
            if permission.document is not None
        ]

        all_documents = {
            doc.id: doc
            for doc in owned_documents + shared_documents
        }

        documents = list(all_documents.values())

    # Search and filter values
    search = request.args.get("search", "").strip().lower()
    owner_filter = request.args.get("owner", "").strip().lower()
    category_filter = request.args.get("category", "").strip().lower()
    from_date = request.args.get("from_date", "").strip()
    to_date = request.args.get("to_date", "").strip()

    # Search by document title or filename
    if search:

        documents = [
            doc for doc in documents
            if search in (doc.title or "").lower()
            or search in (doc.filename or "").lower()
        ]

    # Filter by owner
    if owner_filter:

        documents = [
            doc for doc in documents
            if doc.owner and (
                owner_filter in (doc.owner.name or "").lower()
                or owner_filter in (doc.owner.email or "").lower()
            )
        ]

    # Filter by category
    if category_filter:

        documents = [
            doc for doc in documents
            if category_filter in (doc.category or "").lower()
        ]

    # Filter by starting date
    if from_date:

        try:
            start_date = date.fromisoformat(from_date)

            documents = [
                doc for doc in documents
                if doc.created_at
                and doc.created_at.date() >= start_date
            ]

        except ValueError:
            flash("Invalid starting date.")

    # Filter by ending date
    if to_date:

        try:
            end_date = date.fromisoformat(to_date)

            documents = [
                doc for doc in documents
                if doc.created_at
                and doc.created_at.date() <= end_date
            ]

        except ValueError:
            flash("Invalid ending date.")

    # Newest documents first
    documents.sort(
        key=lambda doc: doc.created_at,
        reverse=True
    )

    # Documents current user can edit
    editable_document_ids = {
        doc.id
        for doc in documents
        if can_access_document(
            current_user,
            doc.id,
            action="EDIT"
        )
    }

    # Separate READ and EDIT permissions for Viewer
    shared_read_documents = []
    shared_edit_documents = []

    if current_user.role == "VIEWER":

        viewer_permissions = Permission.query.filter_by(
            user_id=current_user.id
        ).all()

        for permission in viewer_permissions:

            doc = permission.document

            if doc is None:
                continue

            if permission.permission_type == "READ":
                shared_read_documents.append(doc)

            elif permission.permission_type == "EDIT":
                shared_edit_documents.append(doc)

    # Owner: get users who have access to owned documents
    owner_permissions = {}

    if current_user.role == "OWNER":

        owned_ids = [
            doc.id
            for doc in documents
            if doc.owner_id == current_user.id
        ]

        if owned_ids:

            permissions = Permission.query.filter(
                Permission.document_id.in_(owned_ids)
            ).all()

            for permission in permissions:

                owner_permissions.setdefault(
                    permission.document_id,
                    []
                ).append(permission)

    return render_template(
        "documents.html",
        documents=documents,
        editable_document_ids=editable_document_ids,
        shared_read_documents=shared_read_documents,
        shared_edit_documents=shared_edit_documents,
        owner_permissions=owner_permissions,
        search=search,
        owner_filter=owner_filter,
        category_filter=category_filter,
        from_date=from_date,
        to_date=to_date
    )


# --------------------------------------------------
# UPLOAD DOCUMENT
# --------------------------------------------------

@documents_bp.route("/upload", methods=["POST"])
@login_required
def upload_document():

    if current_user.role != "OWNER":
        abort(403)

    file = request.files.get("document")

    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()

    if not file or not file.filename:
        flash("Please select a document.")
        return redirect(url_for("documents.my_documents"))

    if not title:
        flash("Document title is required.")
        return redirect(url_for("documents.my_documents"))

    original_filename = secure_filename(file.filename)

    if not original_filename or "." not in original_filename:
        flash("Invalid filename.")
        return redirect(url_for("documents.my_documents"))

    if not validate_uploaded_file(file, original_filename):
        flash("Invalid file content, unsupported format, or file exceeds 10 MB.")
        return redirect(url_for("documents.my_documents"))

    file.stream.seek(0)

    extension = original_filename.rsplit(".", 1)[1].lower()

    stored_filename = f"{uuid.uuid4().hex}.{extension}"

    file_path = os.path.join(
        UPLOAD_FOLDER,
        stored_filename
    )

    try:

        file.save(file_path)

        document = Document(
            owner_id=current_user.id,
            title=title,
            category=category or None,
            filename=original_filename,
            storage_path=file_path
        )

        db.session.add(document)
        db.session.flush()

        log = AuditLog(
            actor_id=current_user.id,
            document_id=document.id,
            action="DOCUMENT_UPLOAD",
            outcome="SUCCESS",
            details={
                "filename": original_filename
            }
        )

        db.session.add(log)
        db.session.commit()

        flash("Document uploaded successfully!")

    except Exception:

        db.session.rollback()

        if os.path.exists(file_path):
            os.remove(file_path)

        raise

    return redirect(url_for("documents.my_documents"))


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# --------------------------------------------------

@documents_bp.route("/download/<int:document_id>", methods=["GET"])
@login_required
def download_document(document_id):

    document = db.session.get(Document, document_id)

    if document is None or not can_access_document(
        current_user,
        document_id,
        action="READ"
    ):

        log = AuditLog(
            actor_id=current_user.id,
            document_id=document.id if document else None,
            action="DOCUMENT_DOWNLOAD",
            outcome="DENIED",
            details={
                "reason": "READ permission required"
            }
        )

        db.session.add(log)
        db.session.commit()

        abort(403)

    if not os.path.isfile(document.storage_path):
        abort(404)

    log = AuditLog(
        actor_id=current_user.id,
        document_id=document.id,
        action="DOCUMENT_DOWNLOAD",
        outcome="SUCCESS",
        details={
            "filename": document.filename
        }
    )

    db.session.add(log)
    db.session.commit()

    response = send_file(
        document.storage_path,
        as_attachment=True,
        download_name=document.filename
    )

    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"

    return response


# --------------------------------------------------
# SHARE DOCUMENT
# --------------------------------------------------

@documents_bp.route("/share/<int:document_id>", methods=["POST"])
@login_required
def share_document(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if document.owner_id != current_user.id:
        abort(403)

    email = request.form.get(
        "email", ""
    ).strip().lower()

    permission_type = request.form.get(
        "permission_type", ""
    ).upper()

    if permission_type not in ("READ", "EDIT"):

        flash("Invalid permission selected.")
        return redirect(url_for("documents.my_documents"))

    recipient = User.query.filter_by(email=email).first()

    if recipient is None:

        flash("User not found.")
        return redirect(url_for("documents.my_documents"))

    if recipient.id == current_user.id:

        flash("You cannot share a document with yourself.")
        return redirect(url_for("documents.my_documents"))

    if recipient.role != "VIEWER":

        flash("You can share documents with Viewer accounts only.")
        return redirect(url_for("documents.my_documents"))

    try:

        permission = Permission.query.filter_by(
            document_id=document.id,
            user_id=recipient.id
        ).first()

        if permission:

            permission.permission_type = permission_type
            action = "PERMISSION_UPDATED"

        else:

            permission = Permission(
                document_id=document.id,
                user_id=recipient.id,
                permission_type=permission_type
            )

            db.session.add(permission)
            action = "PERMISSION_GRANTED"

        log = AuditLog(
            actor_id=current_user.id,
            document_id=document.id,
            action=action,
            outcome="SUCCESS",
            details={
                "recipient_email": recipient.email,
                "permission": permission_type
            }
        )

        db.session.add(log)
        db.session.commit()

        flash("Document permission saved successfully!")

    except Exception:

        db.session.rollback()
        raise

    return redirect(url_for("documents.my_documents"))


# --------------------------------------------------
# REVOKE PERMISSION
# --------------------------------------------------

@documents_bp.route(
    "/revoke/<int:document_id>/<int:user_id>",
    methods=["POST"]
)
@login_required
def revoke_permission(document_id, user_id):

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if document.owner_id != current_user.id:
        abort(403)

    permission = Permission.query.filter_by(
        document_id=document.id,
        user_id=user_id
    ).first()

    if permission is None:

        flash("Permission not found.")
        return redirect(url_for("documents.my_documents"))

    recipient = db.session.get(User, user_id)

    try:

        log = AuditLog(
            actor_id=current_user.id,
            document_id=document.id,
            action="PERMISSION_REVOKED",
            outcome="SUCCESS",
            details={
                "recipient_email": (
                    recipient.email if recipient else None
                ),
                "previous_permission": permission.permission_type
            }
        )

        db.session.add(log)
        db.session.delete(permission)
        db.session.commit()

        flash("Document access revoked successfully!")

    except Exception:

        db.session.rollback()
        raise

    return redirect(url_for("documents.my_documents"))


# --------------------------------------------------
# EDIT DOCUMENT METADATA
# --------------------------------------------------

@documents_bp.route("/edit/<int:document_id>", methods=["POST"])
@login_required
def edit_document(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if not can_access_document(
        current_user,
        document_id,
        action="EDIT"
    ):

        log = AuditLog(
            actor_id=current_user.id,
            document_id=document_id,
            action="DOCUMENT_EDIT",
            outcome="DENIED",
            details={
                "reason": "EDIT permission required"
            }
        )

        db.session.add(log)
        db.session.commit()

        abort(403)

    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()

    if not title:

        flash("Document title is required.")
        return redirect(url_for("documents.my_documents"))

    try:

        old_title = document.title
        old_category = document.category

        document.title = title
        document.category = category or None

        log = AuditLog(
            actor_id=current_user.id,
            document_id=document.id,
            action="DOCUMENT_EDIT",
            outcome="SUCCESS",
            details={
                "old_title": old_title,
                "new_title": title,
                "old_category": old_category,
                "new_category": category or None
            }
        )

        db.session.add(log)
        db.session.commit()

        flash("Document updated successfully!")

    except Exception:

        db.session.rollback()
        raise

    return redirect(url_for("documents.my_documents"))


# --------------------------------------------------
# PDF EDITOR
# --------------------------------------------------

@documents_bp.route("/editor/<int:document_id>")
@login_required
def pdf_editor(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if not can_access_document(
        current_user,
        document_id,
        action="EDIT"
    ):
        abort(403)

    if not document.filename.lower().endswith(".pdf"):
        abort(400, description="Only PDF files can be edited.")

    return render_template(
        "pdf_editor.html",
        document=document,
        pdf_url=url_for(
            "documents.pdf_preview",
            document_id=document_id
        )
    )


# --------------------------------------------------
# SECURE PDF PREVIEW
# --------------------------------------------------

@documents_bp.route("/pdf-preview/<int:document_id>")
@login_required
def pdf_preview(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if not can_access_document(
        current_user,
        document_id,
        action="EDIT"
    ):
        abort(403)

    if not document.filename.lower().endswith(".pdf"):
        abort(400)

    if not os.path.isfile(document.storage_path):
        abort(404)

    response = send_file(
        document.storage_path,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=document.filename,
        conditional=True
    )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"

    return response


# --------------------------------------------------
# SAVE EDITED PDF
# --------------------------------------------------

@documents_bp.route(
    "/editor/<int:document_id>/save",
    methods=["POST"]
)
@login_required
def save_edited_pdf(document_id):

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if not can_access_document(
        current_user,
        document_id,
        action="EDIT"
    ):

        log = AuditLog(
            actor_id=current_user.id,
            document_id=document_id,
            action="PDF_EDIT",
            outcome="DENIED",
            details={
                "reason": "EDIT permission required"
            }
        )

        db.session.add(log)
        db.session.commit()

        abort(403)

    if not document.filename.lower().endswith(".pdf"):
        abort(400)

    uploaded_file = request.files.get("edited_pdf")

    if not uploaded_file or not uploaded_file.filename:
        abort(400, description="Edited PDF is missing.")

    uploaded_file.stream.seek(0, os.SEEK_END)
    file_size = uploaded_file.stream.tell()
    uploaded_file.stream.seek(0)

    if file_size == 0 or file_size > MAX_FILE_SIZE:
        abort(400, description="PDF must be between 1 byte and 10 MB.")

    header = uploaded_file.stream.read(1024)
    uploaded_file.stream.seek(0)

    if b"%PDF-" not in header:
        abort(400, description="Invalid PDF file.")

    original_path = os.path.abspath(document.storage_path)
    private_root = os.path.abspath(UPLOAD_FOLDER)

    if os.path.commonpath(
        [original_path, private_root]
    ) != private_root:
        abort(400, description="Invalid document storage path.")

    if not os.path.isfile(original_path):
        abort(404)

    backup_folder = os.path.join(
        UPLOAD_FOLDER,
        "versions"
    )

    os.makedirs(backup_folder, exist_ok=True)

    backup_name = (
        f"document_{document.id}_"
        f"{uuid.uuid4().hex}.pdf"
    )

    backup_path = os.path.join(
        backup_folder,
        backup_name
    )

    temp_path = os.path.join(
        UPLOAD_FOLDER,
        f"{uuid.uuid4().hex}.tmp"
    )

    try:

        shutil.copy2(original_path, backup_path)

        uploaded_file.save(temp_path)

        os.replace(temp_path, original_path)

        log = AuditLog(
            actor_id=current_user.id,
            document_id=document.id,
            action="PDF_EDIT",
            outcome="SUCCESS",
            details={
                "filename": document.filename,
                "previous_version_backup": backup_name,
                "new_file_size": file_size
            }
        )

        db.session.add(log)
        db.session.commit()

        return {
            "message": "PDF saved successfully."
        }, 200

    except Exception:

        db.session.rollback()

        if os.path.exists(backup_path):
            shutil.copy2(backup_path, original_path)

        raise

    finally:

        if os.path.exists(temp_path):
            os.remove(temp_path)
