import configparser
import ssl
from sendgrid.helpers.mail import Mail
from sendgrid import SendGridAPIClient
import secrets
from turtle import title
from unicodedata import category
from flask import Flask, render_template, request, redirect, url_for, session
import ibm_db
import bcrypt
import base64
import os

conn = ibm_db.connect("DATABASE=bludb;HOSTNAME=824dfd4d-99de-440d-9991-629c01b3832d.bs2io90l08kqb1od8lcg.databases.appdomain.cloud;PORT=30119;SECURITY=SSL; SSLServerCertificateDigiCertGlobalRootCA.crt;PROTOCOL=TCPIP;UID=yxn13720;PWD=46gVfLcYJP6WedPZ;", "", "")


app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

ssl._create_default_https_context = ssl._create_unverified_context

config = configparser.ConfigParser()
config.read("config.ini")

try:
    settings = config["SETTINGS"]
except:
    settings = {}

API = settings.get("APIKEY", None)
from_email = settings.get("FROM", None)
to_email = settings.get("TO", None)
subject = "Smart Fashion"
html_content = 'Fashion Prod'
print(API)


def sendMail(API, from_email, to_email, subject, html_content):
    if API != None and from_email != None and len(to_email) > 0:
        message = Mail(from_email, to_email, subject, html_content)
    try:
        sg = SendGridAPIClient(API)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)


sendMail(API=API, from_email=from_email, to_email=to_email,
         subject=subject, html_content=html_content)


@app.route("/", methods=['GET'])
def home():
    if 'email' not in session:
        return redirect(url_for('login'))
    else:
        email = session.get('email')
    return render_template('home.html', email=email)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phoneno = request.form['phoneno']
        password = request.form['password']

        if not username or not email or not phoneno or not password:
            return render_template('register.html', error='Please fill all fields')
        hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        query = "SELECT * FROM user_detail WHERE email=? OR phoneno=?"
        stmt = ibm_db.prepare(conn, query)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.bind_param(stmt, 2, phoneno)
        ibm_db.execute(stmt)
        isUser = ibm_db.fetch_assoc(stmt)
        if not isUser:
            insert_sql = "INSERT INTO user_detail(username, email, phoneno, password) VALUES (?,?,?,?)"
            prep_stmt = ibm_db.prepare(conn, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, username)
            ibm_db.bind_param(prep_stmt, 2, email)
            ibm_db.bind_param(prep_stmt, 3, phoneno)
            ibm_db.bind_param(prep_stmt, 4, hash)
            ibm_db.execute(prep_stmt)
            return render_template('register.html', success="You can login")
        else:
            return render_template('register.html', error='Invalid Credentials')

    return render_template('register.html', name='Home')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            return render_template('login.html', error='Please fill all fields')
        query = "SELECT * FROM user_detail WHERE email=?"
        stmt = ibm_db.prepare(conn, query)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.execute(stmt)
        isUser = ibm_db.fetch_assoc(stmt)
        print(isUser, password)

        if not isUser:
            return render_template('login.html', error='Invalid Credentials')

        isPasswordMatch = bcrypt.checkpw(password.encode(
            'utf-8'), isUser['PASSWORD'].encode('utf-8'))

        if not isPasswordMatch:
            return render_template('login.html', error='Invalid Credentials')

        session['email'] = isUser['EMAIL']
        return redirect(url_for('home'))

    return render_template('login.html', name='Home')


@app.route("/admin", methods=['GET', 'POST'])
def adregister():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phoneno = request.form['phoneno']
        password = request.form['password']

        if not username or not email or not phoneno or not password:
            return render_template('adminregister.html', error='Please fill all fields')
        hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        query = "SELECT * FROM admin_detail WHERE email=? OR phoneno=?"
        stmt = ibm_db.prepare(conn, query)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.bind_param(stmt, 2, phoneno)
        ibm_db.execute(stmt)
        isUser = ibm_db.fetch_assoc(stmt)
        if not isUser:
            insert_sql = "INSERT INTO admin_detail(username, email, phoneno, password) VALUES (?,?,?,?)"
            prep_stmt = ibm_db.prepare(conn, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, username)
            ibm_db.bind_param(prep_stmt, 2, email)
            ibm_db.bind_param(prep_stmt, 3, phoneno)
            ibm_db.bind_param(prep_stmt, 4, hash)
            ibm_db.execute(prep_stmt)
            return render_template('adminregister.html', success="You can login")
        else:
            return render_template('adminregister.html', error='Invalid Credentials')

    return render_template('adminregister.html', name='Home')


@app.route("/adminlogin", methods=['GET', 'POST'])
def adlogin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            return render_template('adminlogin.html', error='Please fill all fields')
        query = "SELECT * FROM admin_detail WHERE email=?"
        stmt = ibm_db.prepare(conn, query)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.execute(stmt)
        isUser = ibm_db.fetch_assoc(stmt)
        print(isUser, password)

        if not isUser:
            return render_template('adminlogin.html', error='Invalid Credentials')

        isPasswordMatch = bcrypt.checkpw(password.encode(
            'utf-8'), isUser['PASSWORD'].encode('utf-8'))

        if not isPasswordMatch:
            return render_template('adminlogin.html', error='Invalid Credentials')

        session['email'] = isUser['EMAIL']
        return redirect(url_for('addproduct'))

    return render_template('adminlogin.html', name='Home')


@app.route("/addproduct", methods=['get', 'post'])
def addproduct():
    if request.method == 'POST':
        name = request.form['name']
        image = request.form['image']
        rate = request.form['rate']
        categorie = request.form['categorie']
        if categorie == 'shirt':
            insert_sql = "INSERT INTO SHIRT (name, image, categorie,rate) VALUES (?,?,?,?)"
            prep_stmt = ibm_db.prepare(conn, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, name)
            ibm_db.bind_param(prep_stmt, 2, image)
            ibm_db.bind_param(prep_stmt, 3, categorie)
            ibm_db.bind_param(prep_stmt, 4, rate)
            ibm_db.execute(prep_stmt)
        if categorie == 'pant':
            insert_sql = "INSERT INTO PANT(name, image, categorie,rate) VALUES (?,?,?,?)"
            prep_stmt = ibm_db.prepare(conn, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, name)
            ibm_db.bind_param(prep_stmt, 2, image)
            ibm_db.bind_param(prep_stmt, 3, categorie)
            ibm_db.bind_param(prep_stmt, 4, rate)
            ibm_db.execute(prep_stmt)
        if categorie == 'watch':
            insert_sql = "INSERT INTO WATCH(name, image, categorie, rate) VALUES (?,?,?)"
            prep_stmt = ibm_db.prepare(conn, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, name)
            ibm_db.bind_param(prep_stmt, 2, image)
            ibm_db.bind_param(prep_stmt, 3, categorie)
            ibm_db.bind_param(prep_stmt, 4, rate)
            ibm_db.execute(prep_stmt)
        if categorie == 'shoe':
            insert_sql = "INSERT INTO SHOE(name, image, categorie, rate) VALUES (?,?,?,?)"
            prep_stmt = ibm_db.prepare(conn, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, name)
            ibm_db.bind_param(prep_stmt, 2, image)
            ibm_db.bind_param(prep_stmt, 3, categorie)
            ibm_db.bind_param(prep_stmt, 4, rate)
            ibm_db.execute(prep_stmt)

    return render_template('addproducts.html', success="You can login")


@app.route("/data")
def display():
    shirt_list = []
    pant_list = []
    watch_list = []
    shoes_list = []

    # selecting_shirt
    sql = "SELECT * FROM SHIRT"
    stmt = ibm_db.exec_immediate(conn, sql)
    shirt = ibm_db.fetch_both(stmt)
    while shirt != False:
        shirt_list.append(shirt)
        shirt = ibm_db.fetch_both(stmt)

   # selecting_pant

    sql1 = "SELECT * FROM PANT"
    stmt1 = ibm_db.exec_immediate(conn, sql1)
    pant = ibm_db.fetch_both(stmt1)
    while pant != False:
        pant_list.append(pant)
        pant = ibm_db.fetch_both(stmt1)

# selecting_watch
    sql2 = "SELECT * FROM WATCH"
    stmt2 = ibm_db.exec_immediate(conn, sql2)
    watch = ibm_db.fetch_both(stmt2)
    while watch != False:
        watch_list.append(watch)
        watch = ibm_db.fetch_both(stmt2)

    # selecting_shoes
    sql3 = "SELECT * FROM SHOE"
    stmt3 = ibm_db.exec_immediate(conn, sql3)
    shoes = ibm_db.fetch_both(stmt3)
    while shoes != False:
        shoes_list.append(shoes)
        shoes = ibm_db.fetch_both(stmt3)

    # returning to HTML
    return render_template('data.html', shirts=shirt_list, pants=pant_list, watchs=watch_list, shoes=shoes_list)


@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(port=port, host='0.0.0.0')
