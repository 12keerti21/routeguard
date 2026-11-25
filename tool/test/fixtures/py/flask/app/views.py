import requests
from flask import Blueprint, jsonify, request, abort
from flask_login import login_required, current_user

from app.models import Note, User, db

api = Blueprint("api", __name__)


@api.route("/login", methods=["POST"])
def login():
    return jsonify({})


# vulnerable: any signed-in user reads any note
@api.route("/notes/<int:note_id>")
@login_required
def get_note(note_id):
    note = Note.query.get_or_404(note_id)
    return jsonify(id=note.id, text=note.text)


# safe: scoped to the caller
@api.route("/safe/notes/<int:note_id>")
@login_required
def get_note_safe(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first_or_404()
    return jsonify(id=note.id, text=note.text)


# safe: compared with the caller
@api.route("/checked/notes/<int:note_id>", methods=["DELETE"])
@login_required
def delete_note_checked(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    db.session.delete(note)
    return "", 204


# vulnerable: the body sets is_admin
@api.route("/users", methods=["POST"])
@login_required
def create_user():
    data = request.get_json()
    user = User(**data)
    db.session.add(user)
    return jsonify(id=user.id)


# vulnerable: the password hash goes back
@api.route("/me")
@login_required
def me():
    return jsonify({"email": current_user.email, "password": current_user.password})


# vulnerable: fetches a URL the client sends
@api.route("/preview")
@login_required
def preview():
    url = request.args.get("url")
    return requests.get(url).text


# operator route with no role check
@api.route("/admin/stats")
@login_required
def stats():
    return jsonify({})
