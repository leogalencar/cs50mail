import logging
import os
import sys

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, session
from flask_ckeditor import CKEditor
from flask_session import Session
from pathlib import Path
from tempfile import mkdtemp
from uuid import uuid4
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, SubmitField

from helpers import allowed_file, apology, check_password_chars, delete_email, expandEmail, get_emails, get_pagination, login_required, remove_html

# Make ANSI escape sequences on terminal output (Windows)
if sys.platform.lower() == 'win32':
    os.system('color')

# Configure Application
app = Flask(__name__, static_url_path='/static')

# Configure max file size for uploads
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

# Configure CKEditor
ckeditor = CKEditor(app)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///mail.db")

# Configure SQLite database to show logs
logging.getLogger("cs50").disabled = False

# Configure app default folder
THIS_FOLDER = Path(__file__).parent.resolve()

# Define app host
app_host = "server" if str(THIS_FOLDER)[0] == '/' else "local"

# Configure app URL
if app_host == "server":
    DEFAULT_URL = "https://mrdelta.pythonanywhere.com"   # Web URL (pythonanywhere)
else:
    DEFAULT_URL = "http://127.0.0.1:5000"                # Local URL


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# TODO : Sync other pages to receive user space info
@app.route("/")
@app.route("/inbox")
@app.route("/inbox/")
@app.route("/<int:email_id>")
@app.route("/inbox/<int:email_id>")
@login_required
def index(email_id=None):
    """Show inbox emails"""
    
    # Get all emails received
    if not email_id:
        
        # Count total emails
        emails_count = db.execute("SELECT COUNT(emails.id) AS emails_count FROM emails WHERE emails.id IN (SELECT email_id FROM emails_received WHERE category = 'INBOX') AND emails.receiver_id = ?", session["user_id"])[0]["emails_count"]
        
        # Get pagination
        pagination, start, end, per_page, offset = get_pagination(emails_count)
        
        # Get emails from database        
        emails = get_emails(select=["emails.id", "subject", "content", "date", "favorite", "first_name", "last_name"],
                            tables=["users"],
                            join_table="emails_received",
                            filter="category = 'INBOX'",
                            per_page=per_page,
                            offset=offset,
                            db=db)
        
        # Format date to -> month day (Example: Aug 14) and remove HTML tags
        for email in emails:
            email["date"] = datetime.strptime(email["date"], "%Y-%m-%d %H:%M:%S").strftime("%b %d")
            email["content"] = remove_html(email["content"])
        
        # Get user free space
        user_space = {}
        
        user_space["free"] = db.execute("SELECT free_space FROM users WHERE id = ?", session["user_id"])[0]["free_space"]
        user_space["used"] = (1024**3) - user_space["free"]
        user_space["used_percent"] = user_space["used"] * 100 / (1024**3)
        
        # Redirect user to index page
        return render_template("index.html", active_page='inbox', emails=emails, user_space=user_space, pagination=pagination, start=start, end=end)
    
    # Expand selected email
    else:
        return expandEmail(email_id=email_id, active_page='inbox', db=db)


@app.route("/delete/<email_id>", methods=["POST"])
@app.route("/delete/list/<items>", methods=["POST"])
@app.route("/delete/<type>/<email_id>", methods=["POST"])
@login_required
def delete(email_id=None, type=None, items=None):
    """Move email to trash, if it's already in trash then delete it"""
    
    # User reached route via POST (as submitting a form via POST)
    if request.method == "POST":
        
        # Get http origin request
        http_referer = request.environ.get('HTTP_REFERER', 'default value')
        
        # Get page
        if '?page=' in http_referer.split('/')[-1]:
            page = [*http_referer][-1]
        else:
            page = None
        
        # Set allowed URLs
        ALLOWED_URLS = {
            "inbox": [
                f"{DEFAULT_URL}/",
                f"{DEFAULT_URL}/?page={page}",
                f"{DEFAULT_URL}/{email_id}",
                f"{DEFAULT_URL}/inbox",
                f"{DEFAULT_URL}/inbox/",
                f"{DEFAULT_URL}/inbox?page={page}",
                f"{DEFAULT_URL}/inbox/{email_id}"
            ],
            "sent": [
                f"{DEFAULT_URL}/sent",
                f"{DEFAULT_URL}/sent/",
                f"{DEFAULT_URL}/sent/?page={page}",
                f"{DEFAULT_URL}/sent/{email_id}"
            ],
            "favorites": [
                f"{DEFAULT_URL}/favorites",
                f"{DEFAULT_URL}/favorites/",
                f"{DEFAULT_URL}/favorites/?page={page}",
                f"{DEFAULT_URL}/favorites/{email_id}"
            ],
            "trash": [
                f"{DEFAULT_URL}/trash",
                f"{DEFAULT_URL}/trash/?page={page}",
                f"{DEFAULT_URL}/trash/{email_id}"
            ],
            "search": [
                f"{DEFAULT_URL}/search/",
                f"{DEFAULT_URL}/search/{type}/",
                f"{DEFAULT_URL}/search/?page={page}",
                f"{DEFAULT_URL}/search/{email_id}"
            ]
        }
        
        # User sent a request from inbox (to move the email to the trash)
        if not type and http_referer in ALLOWED_URLS["inbox"]:
            
            # If multiple emails were selected
            if items:
                checkboxes = request.form.getlist("checkbox-email")
                
                for c_email_id in checkboxes:
                    db.execute("UPDATE emails_received SET category = 'TRASH' WHERE email_id = ?", c_email_id.split("-")[1])
                
                return redirect(f"/?page={page}") if page else redirect("/")
            
            db.execute("UPDATE emails_received SET category = 'TRASH' WHERE email_id = ?", email_id)

            return redirect(f"/?page={page}") if page else redirect("/")
        
        # User sent a request from sent emails (to move the email to the trash)
        if not type and http_referer in ALLOWED_URLS["sent"]:
            
            # If multiple emails were selected
            if items:
                checkboxes = request.form.getlist("checkbox-email")
                
                for c_email_id in checkboxes:
                    db.execute("UPDATE emails_sent SET category = 'TRASH' WHERE email_id = ?", c_email_id.split("-")[1])
                
                return redirect(f"/?page={page}") if page else redirect("/")
            
            db.execute("UPDATE emails_sent SET category = 'TRASH' WHERE email_id = ?", email_id)
            
            return redirect(f"/sent/?page={page}") if page else redirect("/sent")
        
        # User sent a request from search
        if f"{DEFAULT_URL}/search/" in http_referer:
            
            # If multiple emails were selected
            if items:
                checkboxes = request.form.getlist("checkbox-email")
                
                for c_email in checkboxes:
                    c_email = c_email.split("-")
                    delete_email(type=c_email[0], email_id=c_email[1], db=db)
            
            elif type == "received" or type == "sent":
                delete_email(type=type, email_id=email_id, db=db)
            
            # Split request's origin
            http_referer = http_referer.split("/")
            
            # Eliminate the email id number in the URL
            if http_referer[-1].isnumeric():
                http_referer.pop()

            # Join request's origin
            http_referer = "/".join(http_referer)
            
            # Redirect user to origin page
            return redirect(http_referer)
        
        # User sent a request from trash (to delete the email permanently)
        if http_referer in ALLOWED_URLS["trash"]:
            
            # If multiple emails were selected
            if items:
                checkboxes = request.form.getlist("checkbox-email")
                
                for c_email in checkboxes:
                    c_email = c_email.split("-")
                    delete_email(type=c_email[0], email_id=c_email[1], db=db)
            
            elif type == "received" or type == "sent":
                delete_email(type=type, email_id=email_id, db=db)
            
            # Split request's origin
            http_referer = http_referer.split("/")
            
            # Eliminate the email id number in the URL
            if http_referer[-1].isnumeric():
                http_referer.pop()
            
            # Join request's origin
            http_referer = "/".join(http_referer)
            
            # Redirect user to origin page
            return redirect(http_referer)
    
    # User reached route via GET (as clicking by link or via redirect)
    else:
        return render_template("index.html")


@app.route("/download/<path:filename>", methods=["GET"])
def download(filename):
    return send_file(filename, as_attachment=True)


@app.route("/favorites")
@app.route("/favorites/")
@app.route("/favorites/<email_id>")
@login_required
def favorites(email_id=None):
    """Show favorite emails"""
    
    # Get all emails in trash
    if not email_id:       
        
        # Count total emails
        emails_count = db.execute("""
                                    SELECT COUNT(emails.id) AS emails_count 
                                    FROM emails 
                                    WHERE (emails.id IN (SELECT email_id FROM emails_received WHERE favorite = 1) AND emails.receiver_id = ?)
                                    OR (emails.id IN (SELECT email_id FROM emails_sent WHERE favorite = 1) AND emails.sender_id = ?);
                                """, session["user_id"], session["user_id"])[0]["emails_count"]

        # Get pagination
        pagination, start, end, per_page, offset = get_pagination(emails_count)
        
        # Get emails stored in trash
        emails = get_emails(select=["emails.id", "subject", "content", "date", "favorite", "first_name", "last_name", "email"],
                            tables=["users"],
                            filter="favorite = 1",
                            join_table="ALL",
                            per_page=per_page,
                            offset=offset,
                            db=db)
        
        # Format date to -> month day (Example: Aug 14) and remove HTML tags
        for email in emails:
            email["date"] = datetime.strptime(email["date"], "%Y-%m-%d %H:%M:%S").strftime("%b %d")
            email["content"] = remove_html(email["content"])
        
        # Get user free space
        user_space = {}
        
        user_space["free"] = db.execute("SELECT free_space FROM users WHERE id = ?", session["user_id"])[0]["free_space"]
        user_space["used"] = (1024**3) - user_space["free"]
        user_space["used_percent"] = user_space["used"] * 100 / (1024**3)
        
        # Redirect user to trash page
        return render_template("favorites.html", active_page='favorites', emails=emails, user_space=user_space, pagination=pagination, start=start, end=end)
    
    # Expand selected email
    else:
        return expandEmail(email_id=email_id, active_page='favorites', db=db)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    
    # Forget any user_id
    session.clear()
    
    # User reached route via POST (as submitting a form via POST)
    if request.method == "POST":
        email = request.form.get("emailInput")
        password = request.form.get("passwordInput")
        
        # Validate if data was submitted
        if not email:
            return apology("must provide email")
        
        if not password:
            return apology("must provide password")
        
        # Query database for user account
        user = db.execute("SELECT * FROM users WHERE email = ?", email)
        
        # Check if user exists and if password is correct
        if len(user) != 1 or not check_password_hash(user[0]["password"], password):
            return apology("invalid email and/or password")
        
        # Remember which user has logged in
        session["user_id"] = user[0]["id"]
        
        # Set navbar to default behavior (expanded)
        session["navbar"] = True
        
        # Redirect user to home page
        return redirect("/inbox")
    
    # User reached route via GET (as clicking by link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    
    # Forget any user_id
    session.clear()
    
    # Redirect user to login form
    return redirect("/inbox")


@app.route('/navbar', methods=['POST'])
@login_required
def navbar():
    """Get status of navbar and update it"""
    
    # Retrieve the data sent from JavaScript
    data = request.get_json()
    
    # Process the data using Python code
    session["navbar"] = data['value']
    
    # Return the result to JavaScript
    return jsonify(result=session["navbar"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    
    # User reached route via POST (as submitting a form via POST)
    if request.method == "POST":
        first_name = request.form.get("firstNameInput")
        last_name = request.form.get("lastNameInput")
        email = request.form.get("emailInput")
        password = request.form.get("passwordInput")
        password_confirm = request.form.get("confirmPasswordInput")
        
        users_count = db.execute("SELECT COUNT(*) AS users_count FROM users WHERE email = ?", email)
        
        # Validate user data
        if not first_name:
            return apology("must provide first name")
        
        if not last_name:
            return apology("must provide last name")
        
        if not email:
            return apology("must provide email")
        else:
            email += '@cs50mail.com'
        
        if users_count[0]["users_count"] != 0:
            return apology("email already exists")
        
        if not password:
            return apology("must provide password")
        
        if password != password_confirm:
            return apology("passwords do not match")
        
        # Generate password hash
        hash = generate_password_hash(password)
        
        # Insert user into the database
        db.execute("INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)", first_name, last_name, email, hash)
        
        # Redirect user to login page
        return render_template("login.html")
    
    # User reached route via GET (as clicking by link or via redirect)
    else:
        return render_template("register.html")


@app.route("/restore/<type>/<email_id>", methods=["POST"])
def restore(type, email_id):
    """Restore email from trash"""
    
    # Check email type
    if type == "received":
        db.execute("UPDATE emails_received SET category = ? WHERE email_id = ?", "INBOX", email_id)
    elif type == "sent":
        db.execute("UPDATE emails_sent SET category = ? WHERE email_id = ?", "SENT", email_id)
    
    # Get request's origin
    http_origin = request.environ.get("HTTP_REFERER", "default value").split("/")
    
    if http_origin[-1].isnumeric():
        http_origin.pop()
        
    http_origin = "/".join(http_origin)
    
    # Redirect user to the request's origin page
    return redirect(http_origin)


@app.route("/search/", methods=["GET"])
@app.route("/search/<string:email_info>/", methods=["GET"])
@app.route("/search/<string:email_info>/<email_id>", methods=["GET"])
def search(email_info='', email_id=None):
    """Search for emails"""
    
    # Get search input data
    email_info = request.args.get("q") if request.args.get("q") else email_info
    
    # Get all emails searched
    if not email_id: 
        
        # Get search info to search into the database
        search_info = '%' + email_info + '%' if email_info else ''
        
        # Count total emails
        emails_count = db.execute("""
                                    SELECT COUNT(emails.id) AS emails_count 
                                    FROM emails 
                                    WHERE subject LIKE ?
                                    AND (emails.id IN (SELECT email_id FROM emails_received) AND emails.receiver_id = ?)
                                    OR (emails.id IN (SELECT email_id FROM emails_sent) AND emails.sender_id = ?)
                                """, search_info, session["user_id"], session["user_id"])[0]["emails_count"]

        # Get pagination
        pagination, start, end, per_page, offset = get_pagination(emails_count)
        
        # Get emails stored in trash
        emails = get_emails(select=["emails.id", "subject", "content", "date", "favorite", "first_name", "last_name", "email", "category"],
                            tables=["users"],
                            tables_filters_clauses=["subject LIKE ?"],
                            tables_filters_values=[search_info],
                            join_table="ALL",
                            per_page=per_page,
                            offset=offset,
                            db=db)
        
        # Format date to -> month day (Example: Aug 14) and remove HTML tags
        for email in emails:
            email["date"] = datetime.strptime(email["date"], "%Y-%m-%d %H:%M:%S").strftime("%b %d")
            email["content"] = remove_html(email["content"])
        
        # Get user free space
        user_space = {}
        
        user_space["free"] = db.execute("SELECT free_space FROM users WHERE id = ?", session["user_id"])[0]["free_space"]
        user_space["used"] = (1024**3) - user_space["free"]
        user_space["used_percent"] = user_space["used"] * 100 / (1024**3)
        
        # Redirect user to search page with the searched info
        return render_template("search.html", active_page='search/' + email_info, emails=emails, user_space=user_space, keyword=email_info, pagination=pagination, start=start, end=end)
    
    # Expand selected email
    else:
        return expandEmail(email_id=email_id, active_page='search/' + email_info, db=db)


@app.route("/sendEmail", methods=["GET", "POST"])
def sendEmail():
    """Send email"""
    
    # User reached route via POST (as submitting a form via POST)
    if request.method == "POST":
        recipient_email = request.form.get("recipient")
        subject = request.form.get("subject")
        message = request.form.get("ckeditor")
        files = request.files.getlist('file')
        date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get sender id as list
        receiver_id = db.execute("SELECT id FROM users WHERE email = ?", recipient_email)
        
        if recipient_email and len(receiver_id) != 0 and subject and message and files:
            
            # Get sender id as value
            receiver_id = db.execute("SELECT id FROM users WHERE email = ?", recipient_email)[0]["id"]
            
            # Insert new email into emails table
            email_id = db.execute("INSERT INTO emails (subject, content, date, sender_id, receiver_id) VALUES (?, ?, ?, ?, ?)", subject, message, date, session["user_id"], receiver_id)
            
            # Insert new email into sender "sent box"
            db.execute("INSERT INTO emails_sent (email_id, category, favorite) VALUES (?, ?, ?)", email_id, "SENT", 0)
            
            # Insert new email into receiver inbox
            db.execute("INSERT INTO emails_received (email_id, category, favorite) VALUES (?, ?, ?)", email_id, "INBOX", 0)
            
            # Configure upload folder for files
            if not os.path.exists(THIS_FOLDER / f'files/{session["user_id"]}'):
                os.makedirs(THIS_FOLDER / f'files/{session["user_id"]}')
            app.config["UPLOAD_FOLDER"] = THIS_FOLDER / f'files/{session["user_id"]}'
            
            # Handle files
            for file in files:
            
                if file.filename != '' and allowed_file(file.filename):
                    # Make file name secure
                    filename = secure_filename(str(uuid4()) + '_' + file.filename)
                    
                    # Save file
                    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(path)
                    
                    # Define file type and it's size
                    file_type = filename.split(".")[-1]
                    size = os.stat(path).st_size
                    
                    # Check if sender has free space
                    if db.execute("SELECT free_space FROM users WHERE id = ?", session["user_id"])[0]["free_space"] < size:
                        return redirect("/")
                    
                    # Check if receiver has free space
                    if db.execute("SELECT free_space FROM users WHERE id = ?", receiver_id)[0]["free_space"] < size:
                        return redirect("/")
                    
                    # Reduce sender free space
                    db.execute("UPDATE users SET free_space = (free_space - ?) WHERE id = ?", size, session["user_id"])
                    
                    # Reduce receiver free space
                    db.execute("UPDATE users SET free_space = (free_space - ?) WHERE id = ?", size, receiver_id)
                    
                    # Redefine file path for saving in the database
                    path = os.path.join(f'files/{session["user_id"]}', filename)
                    
                    # Save file data on the database
                    db.execute("INSERT INTO files (email_id, name, path, type, size) VALUES (?, ?, ?, ?, ?)", email_id, filename, path, file_type, size)
        else:
            return apology("error")
        
        # Redirect user to home page
        return redirect("/inbox")
    
    # User reached route via GET (as clicking by link or via redirect)
    else:
        return redirect("/inbox")


@app.route("/sent")
@app.route("/sent/")
@app.route("/sent/<email_id>")
@login_required
def sent(email_id=None):
    """Show sent emails"""
    
    # Get all sent emails
    if not email_id:
        
        # Count total emails
        emails_count = db.execute("SELECT COUNT(emails.id) AS emails_count FROM emails, users WHERE emails.id IN (SELECT email_id FROM emails_sent WHERE category = 'SENT') AND emails.sender_id = ? AND users.id = (SELECT receiver_id FROM emails WHERE sender_id = ?) ORDER BY date DESC", session["user_id"], session["user_id"])[0]["emails_count"]
        
        # Get pagination
        pagination, start, end, per_page, offset = get_pagination(emails_count)
        
        # Get emails from database
        emails = get_emails(select=["emails.id", "subject", "content", "date", "favorite", "first_name", "last_name", "email"],
                            tables=["users"],
                            join_table="emails_sent",
                            filter="category = 'SENT'",
                            per_page=per_page,
                            offset=offset,
                            db=db)
        
        # Format date to -> month day (Example: Aug 14) and remove HTML tags
        for email in emails:
            email["date"] = datetime.strptime(email["date"], "%Y-%m-%d %H:%M:%S").strftime("%b %d")
            email["content"] = remove_html(email["content"])

        # Get user free space
        user_space = {}
        
        user_space["free"] = db.execute("SELECT free_space FROM users WHERE id = ?", session["user_id"])[0]["free_space"]
        user_space["used"] = (1024**3) - user_space["free"]
        user_space["used_percent"] = user_space["used"] * 100 / (1024**3)
        
        # Redirect user to sent emails page
        return render_template("sent.html", active_page="sent", emails=emails, user_space=user_space, pagination=pagination, start=start, end=end)
    
    # Expand selected email
    else:
        return expandEmail(email_id=email_id, active_page='sent', db=db)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """User settings"""
    
    # User reached route via POST (as submitting a form via POST)
    if request.method == "POST":
        old_password = request.form.get("oldPasswordInput")
        password = request.form.get("passwordInput")
        password_confirmation = request.form.get("passwordConfirmationInput")
        
        # Validate if data was submitted
        if not old_password:
            return apology("must provide email")
        
        if not password:
            return apology("must provide password")
        
        if not password_confirmation:
            return apology("must provide password confirmation")
        
        # Query database for user account
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        
        # Check if user exists and if password is correct
        if len(user) != 1 or not check_password_hash(user[0]["password"], old_password):
            return apology("invalid old password")
        
        # Change user password
        db.execute("UPDATE users SET password = ? WHERE id = ?", generate_password_hash(password), session["user_id"])
        
        # Redirect user to home page
        return redirect("/inbox")
    
    # User reached route via GET (as clicking by link or via redirect)
    else:
        return render_template("settings.html", active_page='settings')


@app.route("/star/<email_id>", methods=["POST"])
@app.route("/star/<type>/<email_id>", methods=["POST"])
@login_required
def star(email_id, type=None):
    """Star / favorite an email"""
    
    # User reached route via POST (as submitting a form via POST)
    if request.method == "POST":
        
        # Get http origin request
        http_referer = request.environ.get("HTTP_REFERER", "default value")
        
        # Get page
        if '?page=' in http_referer.split('/')[-1]:
            page = [*http_referer][-1]
        else:
            page = None
        
        # Set allowed URLs
        ALLOWED_URLS = {
            "inbox": [
                f"{DEFAULT_URL}/",
                f"{DEFAULT_URL}/?page={page}",
                f"{DEFAULT_URL}/{email_id}",
                f"{DEFAULT_URL}/inbox",
                f"{DEFAULT_URL}/inbox/",
                f"{DEFAULT_URL}/inbox?page={page}",
                f"{DEFAULT_URL}/inbox/{email_id}"
            ],
            "sent": [
                f"{DEFAULT_URL}/sent",
                f"{DEFAULT_URL}/sent/",
                f"{DEFAULT_URL}/sent/?page={page}",
                f"{DEFAULT_URL}/sent/{email_id}"
            ],
            "favorites": [
                f"{DEFAULT_URL}/favorites",
                f"{DEFAULT_URL}/favorites/",
                f"{DEFAULT_URL}/favorites/?page={page}",
                f"{DEFAULT_URL}/favorites/{email_id}"
            ],
            "search": [
                f"{DEFAULT_URL}/search/",
                f"{DEFAULT_URL}/search/{type}/",
                f"{DEFAULT_URL}/search/?page={page}",
                f"{DEFAULT_URL}/search/{email_id}"
            ]
        }
        
        # User sent a request from inbox
        if not type and http_referer in ALLOWED_URLS["inbox"]:
            
            if db.execute("SELECT favorite FROM emails_received WHERE email_id = ?", email_id)[0]["favorite"] == 0:
                db.execute("UPDATE emails_received SET favorite = 1 WHERE email_id = ?", email_id)
            else:
                db.execute("UPDATE emails_received SET favorite = 0 WHERE email_id = ?", email_id)
            
            # Redirect user to origin page
            return redirect(http_referer)
        
        # User sent a request from sent emails
        if not type and http_referer in ALLOWED_URLS["sent"]:
            
            if db.execute("SELECT favorite FROM emails_sent WHERE email_id = ?", email_id)[0]["favorite"] == 0:
                db.execute("UPDATE emails_sent SET favorite = 1 WHERE email_id = ?", email_id)
            else:
                db.execute("UPDATE emails_sent SET favorite = 0 WHERE email_id = ?", email_id)
            
            # Redirect user to origin page
            return redirect(http_referer)
        
        # User sent a request from search
        if type and http_referer in ALLOWED_URLS["search"]:

            # Check the email type and unfavorite it from the appropriate table
            if type == 'received':
                if db.execute("SELECT favorite FROM emails_received WHERE email_id = ?", email_id)[0]["favorite"] == 0:
                    db.execute("UPDATE emails_received SET favorite = 1 WHERE email_id = ?", email_id)
                else:
                    db.execute("UPDATE emails_received SET favorite = 0 WHERE email_id = ?", email_id)
            elif type == 'sent':
                if db.execute("SELECT favorite FROM emails_sent WHERE email_id = ?", email_id)[0]["favorite"] == 0:
                    db.execute("UPDATE emails_sent SET favorite = 1 WHERE email_id = ?", email_id)
                else:
                    db.execute("UPDATE emails_sent SET favorite = 0 WHERE email_id = ?", email_id)
            
            # Redirect user to origin page
            return redirect(http_referer)
        
        # User sent a request from favorites
        if type and http_referer in ALLOWED_URLS["favorites"]:

            # Check the email type and unfavorite it from the appropriate table
            if type == 'received':
                db.execute("UPDATE emails_received SET favorite = 0 WHERE email_id = ?", email_id)
            elif type == 'sent':
                db.execute("UPDATE emails_sent SET favorite = 0 WHERE email_id = ?", email_id)
            
            # Split request's origin
            http_referer = http_referer.split("/")
            
            # Eliminate the email id number in the URL
            if http_referer[-1].isnumeric():
                http_referer.pop()
            
            # Join request's origin
            http_referer = "/".join(http_referer)
            
            # Redirect user to origin page
            return redirect(http_referer)
    
    # User reached route via GET (as clicking by link or via redirect)
    else:
        return render_template("index.html")


@app.route("/trash")
@app.route("/trash/")
@app.route("/trash/<email_id>")
@login_required
def trash(email_id=None):
    """Show emails in trash"""
    
    # Get all emails in trash
    if not email_id:       
        
        # Count total emails
        emails_count = db.execute("""
                                    SELECT COUNT(emails.id) AS emails_count 
                                    FROM emails 
                                    WHERE (emails.id IN (SELECT email_id FROM emails_received WHERE category = 'TRASH') AND emails.receiver_id = ?)
                                    OR (emails.id IN (SELECT email_id FROM emails_sent WHERE category = 'TRASH') AND emails.sender_id = ?);
                                """, session["user_id"], session["user_id"])[0]["emails_count"]

        # Get pagination
        pagination, start, end, per_page, offset = get_pagination(emails_count)
        
        # Get emails stored in trash
        emails = get_emails(select=["emails.id", "subject", "content", "date", "favorite", "first_name", "last_name", "email"],
                            tables=["users"],
                            filter="category = 'TRASH'",
                            join_table="ALL",
                            per_page=per_page,
                            offset=offset,
                            db=db)
        
        # Format date to -> month day (Example: Aug 14) and remove HTML tags
        for email in emails:
            email["date"] = datetime.strptime(email["date"], "%Y-%m-%d %H:%M:%S").strftime("%b %d")
            email["content"] = remove_html(email["content"])
        
        # Get user free space
        user_space = {}
        
        user_space["free"] = db.execute("SELECT free_space FROM users WHERE id = ?", session["user_id"])[0]["free_space"]
        user_space["used"] = (1024**3) - user_space["free"]
        user_space["used_percent"] = user_space["used"] * 100 / (1024**3)
        
        # Redirect user to trash page
        return render_template("trash.html", active_page='trash', emails=emails, user_space=user_space, pagination=pagination, start=start, end=end)
    
    # Expand selected email
    else:
        return expandEmail(email_id=email_id, active_page='trash', db=db)