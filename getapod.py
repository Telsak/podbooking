import os
from flask import Flask, render_template, abort, redirect, request, flash, url_for
from flask_admin import Admin, AdminIndexView, expose, menu
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, HiddenField
from wtforms.validators import DataRequired
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from datemagic import date_start_epoch, sec_to_date, date_to_sec, init_dates, date_to_str, check_book_epoch, epoch_hr, show_calendar, unixtime
from scrapeinfo import pull_ics_data, scrape_user_info, test_ldap_auth
from flask_migrate import Migrate
from time import sleep

GRACE_MINUTES = 60
BOOK_HOURS = [8,10,13,15,17,19,21]
SITE_PREFIX = ''
lock_commit = False

basedir = os.path.abspath(os.path.dirname(__file__))
userdetails = dict()
scheduledetails = dict()
scheduletimestamp = 0


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite') 
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SECRET_KEY'] = 'thisisasecretkeyoncethisgoeslivenoreallyipromise'
app.config['FLASK_ADMIN_SWATCH'] = 'lumen'

login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"

db = SQLAlchemy(app)
bcrypt = Bcrypt()
migrate = Migrate(app, db, render_as_batch=True)

login_manager.init_app(app)
bcrypt.init_app(app)

def get_rooms():
    return Rooms.query.all()

def get_users():
    return User.query.all()

def get_user(user):
    return User.query.filter(User.username==user).first()

def get_db_bookings():
    return Bookings.query.all()

app.jinja_env.globals.update(get_rooms=get_rooms)
app.jinja_env.globals.update(get_users=get_users)
app.jinja_env.globals.update(get_user=get_user)
app.jinja_env.globals.update(get_db_bookings=get_db_bookings)
app.jinja_env.globals.update(show_calendar=show_calendar)

class LoginForm(FlaskForm):
    name = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    next = HiddenField("Hidden")
    submit = SubmitField("Submit")

class BookForm(FlaskForm):
    name = StringField("Användarnamn", validators=[DataRequired()], render_kw={'readonly': True})
    partner = StringField("Labbpartner")
    comment = StringField("Kommentar")
    next = HiddenField("Hidden")
    submit = SubmitField("Submit")

class Rooms(db.Model):
    __tablename__ = 'getapod_rooms'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True)
    pods = db.Column(db.Integer)

    def __init__(self, name, pods):
        self.name = name
        self.pods = pods

class Bookings(db.Model):
    __tablename__ = 'getapod_bookings'
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.Integer)
    time = db.Column(db.Integer)
    pod = db.Column(db.Integer)
    duration = db.Column(db.Integer)
    name1 = db.Column(db.String(64))
    name2 = db.Column(db.String(64), nullable=True)
    comment = db.Column(db.String(64), nullable=True)
    flag = db.Column(db.String(64))
    confirmation = db.Column(db.String(64))

    def __init__(self, room, time, pod, duration, name1, name2, comment, flag, confirmation):
        self.room = room
        self.time = time
        self.pod = pod
        self.duration = duration
        self.name1 = name1
        self.name2 = name2
        self.comment = comment
        self.flag = flag
        self.confirmation = confirmation

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role')

    def __repr__(self):
        return '<Role %r>' % self.name

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password = db.Column(db.String(300), nullable=False, unique=True)
    flag = db.Column(db.String(64), nullable=False)
    # TODO: #9 ta bort last_login!
    last_login = db.Column(db.Integer, nullable=False)
    created = db.Column(db.Integer)
    fullname = db.Column(db.String(128))
    mail = db.Column(db.String(128))
    profile = db.Column(db.String(64))

    def __repr__(self):
        return '<User %r>' % self.username

class UserModelView(ModelView):
    form_columns = ('username', 'password', 'flag', 'last_login', 'role')
    column_exclude_list = ['password']

    # necessary to stop flask-admin from saving passwords in cleartext :(
    def on_model_change(self, form, model, is_created):
        # If creating a new user, hash password
        if is_created:
            model.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            model.created = unixtime()
            model.fullname, model.mail, model.profile = scrape_user_info(model.username, model.role.name)
        else:
            old_password = form.password.object_data
            # If password has been changed, hash password
            if not old_password == model.password:
                model.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
    
    def is_accessible(self):
        if current_user.is_active and current_user.is_authenticated:
            return current_user.role.name == "Admin"
    
    def _handle_view(self, name):
        if not self.is_accessible():
            return redirect(url_for('login'))

class RoomsModelView(ModelView):
    def is_accessible(self):
        if current_user.is_active and current_user.is_authenticated:
            return current_user.role.name == "Admin"
    
    def _handle_view(self, name):
        if not self.is_accessible():
            return redirect(url_for('login'))

class BookingModelView(ModelView):
    def is_accessible(self):
        if current_user.is_active and current_user.is_authenticated:
            return current_user.role.name in ['Admin', 'Teacher'] 
    
    def _handle_view(self, name):
        if not self.is_accessible():
            return redirect(url_for('login'))

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role.name in ["Admin", "Teacher"]

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

    @expose('/')
    def index(self):
        if not current_user.is_authenticated and current_user.role.name in ["Admin", "Teacher"]:
            return redirect(url_for('login'))
        return super(MyAdminIndexView, self).index()

admin = Admin(app, name='Podbokning', template_mode='bootstrap4', index_view=MyAdminIndexView())
admin.add_view(RoomsModelView(Rooms, db.session))
admin.add_view(UserModelView(User, db.session))
admin.add_view(BookingModelView(Bookings, db.session))
#admin.add_link(menu.MenuLink(name='Logout', category='', url='/logout?next=/'))

def check_user_details(cname='EMPTY'):
    global userdetails
    if len(userdetails) == 0:
        user_list = User.query.all()
        for user in user_list:
            userdetails[user.username] = dict()
            userdetails[user.username]['fullname'] = user.fullname
            userdetails[user.username]['mail'] = user.mail
            userdetails[user.username]['profile'] = user.profile
    
    if cname in userdetails.keys():
        return userdetails[cname]['fullname'], userdetails[cname]['mail'], userdetails[cname]['profile']
    elif cname != 'EMPTY':
        user_query = User.query.filter(User.username==cname)
        userdetails[cname] = dict()
        userdetails[cname]['fullname'] = user_query[0].fullname
        userdetails[cname]['mail'] = user_query[0].mail
        userdetails[cname]['profile'] = user_query[0].profile
        return userdetails[cname]['fullname'], userdetails[cname]['mail'], userdetails[cname]['profile']
    else:
        return 'noname', 'nomail', 'noprofile'

def get_bookings(roomdata, epoch):
    booking_data = {}
    tds = f'style="border-radius:10px"'
    tdsb = f'style="border-radius:10px;border-width:3px;border-color:DarkSlateGray;"'
    tdcl = f'class="text-center align-middle'
    bookflag = 'STANDARD'
    admins = [x.username for x in User.query.filter(User.role_id!=2).all()]
    baseurl = url_for("help").replace("help", "")
    for hour in BOOK_HOURS:
        booking_data[hour] = {}
        for pod in range(1, roomdata.pods+1):
            mod_epoch = epoch+(hour*3600)
            data = Bookings.query.filter(Bookings.time==(mod_epoch)).filter(Bookings.room==roomdata.id).filter(Bookings.pod==pod).all()
            bookurl = f'{roomdata.name}/{sec_to_date(mod_epoch)}/{hour}/{chr(pod+64)}'
            book_icon = f'<a href="{baseurl}book/{bookurl}" style=color:black><font size=+1><i class="bi bi-calendar-plus"></i></font></a>'
            expired_icon = f'<font size=+1><i class="bi bi-x-octagon"></i></font>'
            # matching bookings to the query? YES!
            if len(data) >= 1:
                showstring = f'XXX{data[0].name1}</a>'
                if len(data[0].name2) > 0:
                    showstring += f'<br>{data[0].name2}'
                if len(data[0].comment) > 0:
                    showstring += f'<br>{data[0].comment}'
                fullname, mail, profile = check_user_details(data[0].name1)
                user_link = f'<a href="#" data-bs-toggle="modal" data-bs-target="#userInfo" data-bs-fullname="{fullname}" data-bs-mail="{mail}" data-bs-profile="{profile}" data-bs-username="{data[0].name1}" data-bs-bookurl="{bookurl}" data-bs-baseurl="{baseurl}">{showstring.replace("XXX", "")}</a>'
                expire_link = f'<a href="#" data-bs-toggle="modal" data-bs-target="#oldBooking">{showstring.replace("XXX", "")}</a>'
                book_icon = f'<a href="{baseurl}book/{bookurl}" style=color:black><font size=+1><i class="bi bi-calendar-plus"></i></font></a>'
                admin_icon = f'<font size=+1><i class="bi bi-shield-lock"></i></font>'
                #delete_icon = f'<font color="red"><i class="bi bi-calendar-x-fill"></i></font>'
                #delete_div = f'<span style="float:right">{delete_icon}</span>'
                #admin_del = f'<a href="{SITE_PREFIX}/delete/{bookurl}">{showstring.replace("XXX", delete_div)}</a>'
                # if the pod isn't marked as available
                if data[0].comment == 'DAYBOOKING' and data[0].name1 in admins:
                    bookflag = 'DAYBOOKING'
                if data[0].flag != 'AVAILABLE':
                    if current_user.is_authenticated:
                        if current_user.role.name in ['Admin', 'Teacher']:
                            booking_data[hour][pod] = f'<td {tds} {tdcl} table-warning">{user_link}</td>'
                        else:
                            booking_data[hour][pod] = f'<td {tds} {tdcl} table-warning">{user_link}</td>'
                    else:
                        booking_data[hour][pod] = f'<td {tds} {tdcl} table-danger">{admin_icon}</td>'
                else:
                    if current_user.is_authenticated:
                        if check_book_epoch(mod_epoch, 45) and current_user.username == data[0].name1:
                            #booking_data[hour][pod] = f'<td {tdsb} {tdcl} table-warning"><a href="/delete/{bookurl}">{showstring.replace("XXX", "")}</td>'
                            booking_data[hour][pod] = f'<td {tdsb} {tdcl} table-warning">{user_link}</td>'
                        elif current_user.role.name in ['Admin', 'Teacher']:
                            booking_data[hour][pod] = f'<td {tds} {tdcl} table-warning">{user_link}</td>'
                        elif current_user.username == data[0].name1:
                            booking_data[hour][pod] = f'<td {tds} {tdcl} table-secondary">{expire_link}</td>'
                        else:
                            booking_data[hour][pod] = f'<td {tds} {tdcl} table-success">{user_link}</td>'
                    else:
                        booking_data[hour][pod] = f'<td {tds} {tdcl} table-warning">{user_link}</td>'
            # matching bookings to the query? NO!
            else:
                if current_user.is_authenticated and current_user.role.name in ['Admin', 'Teacher']:
                        booking_data[hour][pod] = f'<td {tds} {tdcl} table-success">{book_icon}</td>'
                else:
                    if check_book_epoch(mod_epoch, GRACE_MINUTES):
                        booking_data[hour][pod] = f'<td {tds} {tdcl} table-success">{book_icon}</td>'
                    else:
                        booking_data[hour][pod] = f'<td {tds} {tdcl} table-secondary">{expired_icon}</td>'
    return booking_data, bookflag

def set_booking(roomdata, epoch, pod, form):
    availability = {
        'Admin': 'UNAVAILABLE',
        'Teacher': 'UNAVAILABLE',
        'Student': 'AVAILABLE'
    }
    roomflag = availability[current_user.role.name]
    if current_user.role.name == "Student":
        # disallow booking if booking in the past (but give a grace period)
        if not check_book_epoch(epoch, GRACE_MINUTES):
            flash(f'Not permitted to book pod at this time! You cant book expired timeslots!', 'warning')
            baseurl = url_for("help").replace("help", "")
            return False, f'{baseurl}show/{roomdata.name.upper()}/{sec_to_date(epoch)}'
        else:
            # check how many bookings currently exist on the user, beginning on any current booking timeslot
            now_hr = epoch_hr('HR')
            user_time_start = epoch_hr('NOW')
            for hour in BOOK_HOURS:
                if now_hr in range(hour, hour+3):     
                    user_time_start = date_start_epoch(epoch) + (3600*hour)
            duration_data = [x.duration for x in Bookings.query.filter(Bookings.time>=user_time_start).filter(Bookings.name1==current_user.username).all()]
            if sum(duration_data) > 2:
                flash(f'Not permitted to book pod at this time! You have too many booked slots!', 'warning')
                return False, f'{baseurl}show/{roomdata.name.upper()}/{sec_to_date(epoch)}'
    if len(Bookings.query.filter(Bookings.time==epoch).filter(Bookings.room==roomdata.id).filter(Bookings.pod==ord(pod.upper())-64).all()) >= 1:
        flash('This timeslot is no longer available. Please pick another time or pod.', 'warning')
        return False, f'{baseurl}show/{roomdata.name.upper()}/{sec_to_date(epoch)}'
    else:
        booking = Bookings(
            room=roomdata.id,
            time=epoch,
            pod=ord(pod.upper())-64,
            duration=2,
            name1=current_user.username,
            name2=form['partner'],
            comment=form['comment'],
            flag=roomflag,
            confirmation='PENDING'
        )
        return True, booking

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/show/<room>')
@app.route('/show/<room>/<caldate>')
def show(room, caldate='Null'):
    global scheduledetails
    global scheduletimestamp
    if len(scheduledetails) == 0 or abs(unixtime()-scheduletimestamp) > 21600:
        scheduledetails = {}
        scheduledetails, scheduletimestamp = pull_ics_data()
    if room.upper() not in [x.name for x in Rooms.query.all()]:
        flash("No such resource, check room name!", "danger")
        abort(404, description="Resource not found")
    if caldate == 'Null':
        return redirect(url_for("show", room=room.upper(), caldate=date_to_str()))
    else:
        today_d = caldate
    dates = init_dates(today_d)
    show = {}
    roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
    show['room'] = {'name': roomdata.name.upper(), 'pods': [chr(x+65) for x in range(roomdata.pods)]}
    show['dates'] = dates
    show['clocks'] = BOOK_HOURS
    show['query'], show['flag'] = get_bookings(roomdata, dates['today']['string'])
    return render_template('show.html', show=show, cal=scheduledetails, SITE_PREFIX=url_for("help").replace("help", ""))

@app.route('/book')
@app.route('/book/<room>')
@app.route('/book/<room>/<caldate>')
@app.route('/book/<room>/<caldate>/<hr>/<pod>', methods=('GET', 'POST'))
@login_required
def book(room='Null', caldate='Null', hr='Null', pod='Null'):
    if request.method == 'POST' and int(hr) in BOOK_HOURS:
        roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
        book_time = date_to_sec(caldate) + (3600 * int(hr))
        state, booking = set_booking(roomdata, book_time, pod, request.form)
        if state:
            global lock_commit
            while lock_commit == True:
                sleep(0.025)
            lock_commit = True

            db.session.add(booking)
            try:
                db.session.commit()
                flash(f'Pod successfully booked!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(e, "danger")

            lock_commit = False
            
            return redirect(url_for("show", room=roomdata.name.upper(), caldate=date_to_str()), code=302)
        else:
            return render_template('debug.html', debugdata=booking)
    else:
        if 'Null' in locals().values():
            return redirect(url_for("show", room="B112", caldate=date_to_str()), code=302)
        else:
            roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
            # if this is a valid book url...
            if int(hr) in BOOK_HOURS:
                roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
                book_time = date_to_sec(caldate) + (3600 * int(hr))
                return render_template('book.html', data=locals())
            else:
                return redirect(url_for("show", room=roomdata.name.upper()), code=302)

@app.route('/delete/<room>')
@app.route('/delete/<room>/<caldate>')
@app.route('/delete/<room>/<caldate>/<hr>')
@app.route('/delete/<room>/<caldate>/<hr>/<pod>')
@login_required
def delete(room='Null', caldate='Null', hr='Null', pod='Null'):
    # verify delete url args
    if 'Null' in locals().values():
        return redirect(url_for("show", room="B112", caldate=date_to_str()), code=302)
    else:
        try:
            _ = ord(pod)-64
            _ = int(hr)
            _ = caldate[:]
        except:
            flash("Invalid deletion data!", "danger")
            return redirect(url_for("show", room="B112", code=302))
        epoch = date_to_sec(caldate)
        roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
        delete_request = Bookings.query.filter(Bookings.time==(epoch+(int(hr)*3600))).filter(Bookings.room==roomdata.id).filter(Bookings.pod==ord(pod)-64)
        if current_user.username == delete_request[0].name1 or current_user.role.name in ['Teacher', 'Admin']:
            global lock_commit
            while lock_commit == True:
                sleep(0.025)
            lock_commit = True
            
            delete_request.delete()
            db.session.commit()
            
            lock_commit = False            
            flash("Reservation slot deleted", "success")
        else:
            flash("Unauthorized deletion request!", "warning")
        return redirect(url_for("show", room=roomdata.name.upper(), caldate=caldate), code=302)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # validating form
    if form.validate_on_submit():
        name = form.name.data.split('@')[0]
        password = form.password.data
        form.name.data = ''
        form.password.data = ''
        next = form.next.data
        try:
            user = User.query.filter_by(username=name).first()
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                if 'next' in locals() and len(locals()['next']) > 0:
                    return redirect(next)
                else:
                    return redirect(url_for('index'))
            else:
                flash("Invalid Username or password!", "danger")
        except Exception as e:
            if 'has no attribute' in str(e):
                flash("No such user!", "danger")
            else:
                flash(e, "danger")

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = LoginForm()
    # validating form
    if form.validate_on_submit():
        name = form.name.data.split('@')[0]
        password = form.password.data
        form.name.data = ''
        form.password.data = ''
        
        user = User.query.filter_by(username=name).first()
        # if user doesnt exist
        if user is None:
            if test_ldap_auth(name.lower(), password):
                created = unixtime()
                fullname, mail, profile = scrape_user_info(name, 'Student')

                user = User(
                    username=name.lower(),
                    role_id=2,
                    password=bcrypt.generate_password_hash(password).decode('utf-8'),
                    flag='CAN_BOOK',
                    last_login=0,
                    created=created,
                    fullname=fullname,
                    mail=mail,
                    profile=profile
                )
                
                global lock_commit
                while lock_commit == True:
                    sleep(0.025)
                lock_commit = True
                
                db.session.add(user)
                db.session.commit()

                lock_commit = False

                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Invalid user or password!', 'danger')
        else:
            flash('User already exists! Try logging in instead.', 'danger')
        return render_template('signup.html', form=form)

    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/')
@app.route('/<data>')
def index(data='Null'):
    # TODO: Set up a landing page for the booking system. Don't overdo it though.
    return redirect(url_for("show", room='B112'), code=302)

@app.route('/debug')
#@login_required
def debug():
    return render_template('debug.html', debugdata=abs(unixtime()-scheduletimestamp))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

# TODO: #3 Split application into smaller modules - easy peasy