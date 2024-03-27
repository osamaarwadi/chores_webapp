def is_logged_in(session):
    if ("user_id" in session or "admin_id" in session):
        return True
    else:
        return False