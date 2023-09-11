import csv
import datetime
import html
import os
import pytz
import re
import requests
import subprocess
import urllib
import uuid

from flask import redirect, render_template, request, session
from flask_paginate import Pagination, get_page_parameter, get_page_args
from functools import wraps




def allowed_file(filename):
    """Verify if a filename has an allowed extension"""
    
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'rar'}
    
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def check_password_chars(password):
    haveSpecialSymbol = False
    haveNumber = False
    haveUpper = False

    if len(password) < 8 or len(password) > 16:
        return False

    for c in password:
        if c.isnumeric():
            haveNumber = True
        elif c.isupper():
            haveUpper = True
        elif c in "!#$%&'()*+,-./:;<=>?@[\]^_`{|}~":
            haveSpecialSymbol = True

    if haveNumber and haveUpper and haveSpecialSymbol:
        return True
    else:
        return False


def delete_email(type, email_id, db):
    """Move an email to trash or delete it permanently"""
    
    category = db.execute(f"SELECT category FROM emails_{type} WHERE email_id = ?", email_id)[0]["category"]
    count = db.execute(f"SELECT COUNT(*) FROM emails_{'received' if type == 'sent' else 'sent'} WHERE email_id = ?", email_id)[0]["COUNT(*)"]
    
    # To move the email to the trash
    if category == "INBOX" or category == "SENT":
        db.execute(f"UPDATE emails_{type} SET category = 'TRASH' WHERE email_id = ?", email_id)
        
    # To delete the email permanently
    else:
        # Add file size to user free space if the email has a file
        if db.execute("SELECT SUM(size) FROM files WHERE email_id = ?", email_id)[0]["SUM(size)"]:
            db.execute(f"UPDATE users SET free_space = (free_space + (SELECT SUM(size) FROM files WHERE email_id = ?)) WHERE id = ?", email_id, session["user_id"])
        
        # Delete email view
        db.execute(f"DELETE FROM emails_{type} WHERE email_id = ?", email_id)
        
        if count == 0:
            # Delete files associated with the email
            paths = db.execute("SELECT path FROM files WHERE email_id = ?", email_id)
            for path in paths:
                if os.path.exists(path["path"]):
                    os.remove(path["path"])

            # Delete email from database
            db.execute("DELETE FROM emails WHERE id = ?", email_id)


def expandEmail(email_id, active_page, db):
    """Expand selected email"""
    
    # Get email data
    sender = db.execute("SELECT id, first_name, last_name, email FROM users WHERE id = (SELECT sender_id FROM emails WHERE emails.id = ?)", email_id)[0]
    receiver = db.execute("SELECT id, first_name, last_name, email FROM users WHERE id = (SELECT receiver_id FROM emails WHERE emails.id = ?)", email_id)[0]
    attachments = db.execute("SELECT id, SUBSTR(name, 38) AS name, SUBSTR(path, INSTR(path, 'files')) AS path, type, size FROM files WHERE email_id = ?", email_id)
    
    # Determine the email type
    type = "received" if receiver["id"] == session["user_id"] else "sent"
    
    email = db.execute("SELECT id, subject, content, date, favorite FROM emails, ? WHERE id = ? AND email_id = ?", "emails_" + type, email_id, email_id)[0]
    
    # Get http origin request
    http_referer = request.environ.get('HTTP_REFERER', 'default value')
    
    # Get the previous page number
    if '?page=' in http_referer.split('/')[-1]:
        page = [*http_referer][-1]
    else:
        page = ''
    
    # Get user free space
    user_space = {}
    
    user_space["free"] = db.execute("SELECT free_space FROM users WHERE id = ?", session["user_id"])[0]["free_space"]
    user_space["used"] = (1024**3) - user_space["free"]
    user_space["used_percent"] = user_space["used"] * 100 / (1024**3)
    
    # Redirect user to the expanded email page
    return render_template("expanded_email.html", active_page=active_page, user_space=user_space, email=email, sender=sender, receiver=receiver, type=type, page=page, attachments=attachments)


def get_emails(select, tables, filter='TRUE', tables_filters_clauses=None, tables_filters_values=None, join_table=None, per_page=None, offset=None, db=None):
    """Get emails from database"""
    
    # Define default query clauses and add optional ones
    clauses = [
        f"emails.id IN (SELECT email_id FROM {join_table} WHERE {filter})",
        f"{'sender_id' if join_table == 'emails_sent' else 'receiver_id'} = ?",
        f"users.id = (SELECT {'receiver_id FROM emails WHERE sender_id' if join_table == 'emails_sent' else 'sender_id FROM emails WHERE receiver_id'} = ? AND emails.id = email_id)"
        ]
    clauses = clauses + tables_filters_clauses if tables_filters_clauses else clauses
    
    # Define default query values (? values) and add optional ones
    values = [
        session["user_id"],
        session["user_id"],
        ]
    values = values + tables_filters_values + [per_page, offset] if tables_filters_values else values + [per_page, offset]
    
    # Get received and sent emails if join table is 'ALL'
    if join_table == "ALL":
        received = get_emails(select=select,
                            tables=["users"],
                            join_table="emails_received",
                            filter=filter,
                            tables_filters_clauses=tables_filters_clauses)
        
        sent = get_emails(select=select,
                            tables=["users"],
                            join_table="emails_sent",
                            filter=filter,
                            tables_filters_clauses=tables_filters_clauses)
        
        query = f"{received} UNION {sent} ORDER BY date DESC LIMIT ? OFFSET ?"
        print(query)
        return db.execute(query, *values[0:len(values) - 2] * 2, *values[len(values) - 2:])
    
    # Get emails query
    query = f"""
                SELECT {", ".join(select)}, 
                CASE
                    WHEN emails.id = {join_table}.email_id THEN '{"sent" if join_table == "emails_sent" else "received"}'
                END type
                FROM emails, {", ".join(tables)} 
                LEFT JOIN {join_table} ON emails.id = email_id 
                {" WHERE " + " AND ".join(clauses)} 
            """
    
    # Return query if a database is not set
    if not db:
        return query
    
    # Query into database and return emails
    query += " ORDER BY date DESC LIMIT ? OFFSET ?"
    return db.execute(query, *values)


def get_pagination(total):
    """Get pagination"""
    
    # # Get page number
    # page = request.args.get(get_page_parameter(), type=int, default=1)
    
    # # Set rows per page and offset
    # per_page = 50
    # offset = (page - 1) * per_page
    
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page', per_page=5)
    
    pagination = Pagination(page=page, per_page=per_page, total=total, record_name='emails')
    
    # Set start and end index of pagination
    start = pagination.page * pagination.per_page - pagination.per_page + 1 if pagination.total > 0 else 0
    end = pagination.page * pagination.per_page if pagination.page * pagination.per_page < pagination.total else pagination.total
    
    return pagination, start, end, per_page, offset


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def remove_html(string):
    return html.unescape(re.compile(r'<[^>]+>').sub('', string))
