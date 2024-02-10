import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    ids = session["user_id"]
    trans = db.execute(
        "SELECT symbol, name, price,  SUM(shares) as totshare, SUM(price * shares) as total FROM transctions WHERE user_id = ? GROUP BY symbol", ids)
    cash = db.execute("SELECT cash from users where id = ?", ids)[0]["cash"]
    grand = db.execute(
        "SELECT SUM(price * shares) + cash AS total FROM transctions JOIN users ON transctions.user_id = users.id WHERE user_id = ?", ids)[0]['total']
    tot = cash
    for item in trans:
        tot = tot + item['totshare'] * item['price']
    return render_template("index.html", trans=trans, cash=cash, grands=tot)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        if not request.form.get("shares"):
            return apology("must provide a number", 403)
        if lookup(request.form.get("symbol")) == None:
            return apology("Invalid symbol", 400)
        check = request.form.get("shares")
        try:
            checks = int(check)
        except:
            return apology("number must be an integer", 400)
        if checks < 0:
            return apology("No of shares can't be negative", 400)
        id = session["user_id"]
        cash = {}
        cash = db.execute("SELECT cash FROM users where id = ?", id)[0]["cash"]
        hii = lookup(request.form.get("symbol"))
        total = checks * hii['price']
        if cash < total:
            return apology("Insufficient Funds", 403)

        db.execute("INSERT INTO transctions(user_id, name, shares, price, type, symbol) VALUES(?, ?, ?, ?, ?, ?)",
                   id, hii['name'], checks, hii['price'], "bought", hii['symbol'])
        db.execute("UPDATE users SET cash = ?", cash-total)
        return redirect("/")


@ app.route("/history")
@ login_required
def history():
    """Show history of transactions"""
    if request.method == "GET":
        id = session["user_id"]
        history = db.execute("SELECT symbol, shares, price, time FROM transctions WHERE user_id = ?", id)
        return render_template("history.html",trans = history)


@ app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@ app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@ app.route("/quote", methods=["GET", "POST"])
@ login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:

        if lookup(request.form.get("symbol")) == None:
            return apology("invalid symbol", 400)
        hi = lookup(request.form.get("symbol"))
        return render_template("quote_success.html", name=hi['name'], price=hi['price'], symbol=hi['symbol'])


@ app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        # Ensure both the entered passwords are same
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("both password do not match", 400)
        rows1 = db.execute("SELECT * FROM users WHERE username = ?",
                           request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows1) != 0:
            return apology("Username already exists", 400)
        db.execute("INSERT INTO users(username, hash) VALUES(?,?)", request.form.get(
            "username"), generate_password_hash(request.form.get("password")))
        return redirect("/")


@ app.route("/sell", methods=["GET", "POST"])
@ login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        id = session["user_id"]
        sym = db.execute("SELECT symbol FROM transctions WHERE user_id = ? GROUP BY symbol", id)
        return render_template("sell.html", sym= sym)
    else:
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        if not request.form.get("shares"):
            return apology("must provide a number", 403)
        if lookup(request.form.get("symbol")) == None:
            return apology("Invalid symbol", 400)
        check = request.form.get("shares")
        try:
            checks = int(check)
        except:
            return apology("number must be an integer", 400)
        if checks < 0:
            return apology("No of shares can't be negative", 400)
        id = session["user_id"]
        hi = lookup(request.form.get("symbol"))
        share_no = db.execute("SELECT SUM(shares) AS tot FROM transctions WHERE user_id = ? AND symbol = ? ",
                              id, hi['symbol'])[0]["tot"]
        if share_no < checks:
            return apology("Do not have enough shares", 400)
        cash = db.execute("SELECT cash from users where id = ?", id)[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + hi['price'] * checks, id )
        db.execute("INSERT INTO transctions(user_id, name, shares, price, type, symbol) VALUES(?, ?, ?, ?, ?, ?)", id, hi['name'], -checks, hi['price'], "sold", hi['symbol'])
        return redirect("/")

@ app.route("/changepass", methods=["GET", "POST"])
@ login_required
def changepass():
    if request.method == "POST":
        id = session["user_id"]
        if not request.form.get("pass"):
            return apology("enter old password", 403)
        if not request.form.get("newpass1"):
            return apology("must provide new password", 403)
        if not request.form.get("newpass2"):
            return apology("must provide new password again", 403)
        oldpass = request.form.get("pass")
        dbpass = db.execute("SELECT hash FROM users WHERE id = ?", id)[0]["hash"]
        newpass1 = request.form.get("newpass1")
        newpass2 = request.form.get("newpass2")
        if newpass1 != newpass2:
            return apology("both password not same", 403)
        if check_password_hash(dbpass, oldpass) == True:
         newpass = generate_password_hash(request.form.get("newpass1"))
         db.execute("UPDATE users SET hash = ? WHERE id = ?", newpass, id)
         return redirect("/login")
        else:
             return apology("both new password do not match", 400)


    else:
         return render_template("changepassword.html")




