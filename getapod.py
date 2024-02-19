import os, gunicorn, json
from base64 import b64decode
from requests import post
from flask import (
    Flask, render_template, abort, redirect, request, 
    flash, url_for, session, Response, current_app
)
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import (
    StringField, SubmitField, PasswordField, HiddenField, SelectField,
    IntegerField, TextAreaField
)
from wtforms.validators import DataRequired, NumberRange
from flask_login import (
    UserMixin, login_user, LoginManager, current_user, 
    logout_user, login_required
)
from datemagic import (
    date_start_epoch, sec_to_date, date_to_sec, init_dates, 
    date_to_str, check_book_epoch, epoch_hr, show_calendar, 
    unixtime, endtimes, sec_to_weekday, datetime, year_start_unixtime
)
from scrapeinfo import get_profile, pull_ics_data, scrape_user_info, test_ldap_auth
from flask_migrate import Migrate
from time import sleep
from collections import defaultdict
from icalmagic import generate_ical

from bs4 import BeautifulSoup as bs
from sqlalchemy import func

import re

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
app.config['LOGSEVERITY'] = 4
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"

db = SQLAlchemy(app)
bcrypt = Bcrypt()
migrate = Migrate(app, db, render_as_batch=True)

login_manager.init_app(app)
bcrypt.init_app(app)

def log_webhook(facility='', severity=4, msg='Null'):
    if app.config['SETTINGS']['base']['logging']['ENABLE'] and 'discord.com/api/webhooks' in app.config['SETTINGS']['base']['logging']['WEBHOOK']:
        url = app.config['SETTINGS']['base']['logging']['WEBHOOK']
        levels = app.config['SETTINGS']['base']['logging']['LEVELS']
        app_severity = app.config['SETTINGS']['base']['logging']['SEVERITY']
        
        if severity <= app_severity or 'SIGNUP' in facility:
            post(url, json={"username": f'getapod: {facility}-{levels[severity]}', 
                        "content": msg})

def read_config():
    try:
        with open('config.json', 'r') as file:
            return json.load(file)
    except:
        return {
            'base': {
                'logging': {
                    'SEVERITY': 4,
                    'ENABLE': False,
                    'WEBHOOK': 'No webhook specified',
                    'LEVELS': [
                        'EMERGENCY',
                        'ALERT', 
                        'CRITICAL', 
                        'ERROR', 
                        'WARNING', 
                        'NOTICE', 
                        'INFORMATIONAL', 
                        'DEBUG'
                    ]
                },
                'disabled': []
            }
        }

def write_config(config_data):
    try:
        with open('config.json', 'w') as file:
            json.dump(config_data, file, indent=2)
            return True
    except:
        flash("Error. Unable to save configuration!", "warning")
        return False

#app.config['WEBHOOK'] = log_webhook('GETURL')
app.config['SETTINGS'] = read_config()

def get_rooms():
    return Rooms.query.all()

def get_users():
    return User.query.all()

def get_user(user):
    return User.query.filter(User.username==user).first()

def get_db_bookings():
    return Bookings.query.all()

def get_user_num_bookings(user):
    return len(Bookings.query.filter(Bookings.name1==user).all())

def get_user_hours(user):
    bh = len(Bookings.query.filter(Bookings.name1==user).all()) * 2
    ph = len(Bookings.query.filter(func.lower(Bookings.name2)==user).all()) * 2
    return bh + ph

app.jinja_env.globals.update(get_rooms=get_rooms)
app.jinja_env.globals.update(get_users=get_users)
app.jinja_env.globals.update(get_user=get_user)
app.jinja_env.globals.update(get_db_bookings=get_db_bookings)
app.jinja_env.globals.update(show_calendar=show_calendar)
app.jinja_env.globals.update(get_user_num_bookings=get_user_num_bookings)
app.jinja_env.globals.update(get_user_hours=get_user_hours)
app.jinja_env.globals.update(unixtime=unixtime)
app.jinja_env.globals.update(sec_to_date=sec_to_date)
app.jinja_env.globals.update(endtimes=endtimes)
app.jinja_env.globals.update(sec_to_weekday=sec_to_weekday)
app.jinja_env.globals.update(date_to_sec=date_to_sec)

class LoginForm(FlaskForm):
    name = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    next = HiddenField('Hidden')
    submit = SubmitField('Submit')

class BookForm(FlaskForm):
    name = StringField('Användarnamn', validators=[DataRequired()], render_kw={'readonly': True})
    partner = StringField('Labbpartner')
    comment = StringField('Kommentar')
    next = HiddenField('Hidden')
    submit = SubmitField('Submit')

class CreateSkillsInstanceForm(FlaskForm):
    name = StringField('Provnamn', validators=[DataRequired()])
    course = StringField('Kurskod', validators=[DataRequired()])
    period = SelectField('Läsperiod', choices=['LP1', 'LP2', 'LP3', 'LP4'], validators=[DataRequired()])
    type = SelectField(u'Skilltyp', choices=['Skill', 'Omskill'], validators=[DataRequired()])
    year = StringField('Läsår', validators=[DataRequired()])
    comment = TextAreaField('Kommentar')
    next = HiddenField('Hidden')
    submit = SubmitField("Submit")

class CreateSkillsLocAndDatesForm(FlaskForm):
    skill_id = HiddenField(validators=[DataRequired()], render_kw={'readonly': True})
    skill_name = StringField('Skill', validators=[DataRequired()])
    standard_dates = StringField('Datum', validators=[DataRequired()])
    standard_times = StringField('Tider', validators=[DataRequired()])
    standard_rooms = StringField('Salar', validators=[DataRequired()])
    standard_duration = IntegerField('Längd', validators=[DataRequired(), NumberRange(60,300, 'Välj mellan 60 - 300 min')])
    extra_dates = StringField('Extra datum')
    extra_times = StringField('Extra tider')
    extra_rooms = StringField('Extra salar')
    extra_duration = IntegerField('Längd', validators=[NumberRange(60,300, 'Välj mellan 60 - 300 min')])
    comment = TextAreaField('Kommentar')
    next = HiddenField('Hidden')
    submit = SubmitField("Submit")
    
class SkillInstance(db.Model):
    __tablename__ = 'skillinstance'
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.Integer)
    owner = db.Column(db.String(128))
    name = db.Column(db.String(128))
    course = db.Column(db.String(128))
    schoolyear = db.Column(db.Integer)
    period = db.Column(db.String(4))
    standard_dates = db.Column(db.String(512))
    standard_rooms = db.Column(db.String(128))
    standard_times = db.Column(db.String(256))
    standard_duration = db.Column(db.Integer)
    extra_dates = db.Column(db.String(512))
    extra_rooms = db.Column(db.String(128))
    extra_times = db.Column(db.String(256))
    extra_duration = db.Column(db.Integer)
    bookings = db.relationship('SkillBooking', backref='skillinstance')
    type = db.Column(db.String(32))
    status = db.Column(db.String(32))
    comment = db.Column(db.String(1024))

class SkillBooking(db.Model):
    __tablename__ = 'skillbookings'
    id = db.Column(db.Integer, primary_key=True)
    skill_id = db.Column(db.Integer, db.ForeignKey('skillinstance.id'))
    date = db.Column(db.String(16))
    time = db.Column(db.Integer)
    room = db.Column(db.String(16))
    timeslot = db.Column(db.Integer)
    student = db.Column(db.String(16))
    result = db.Column(db.String(32))
    teacher = db.Column(db.String(32))
    comment = db.Column(db.String(256))
    flag = db.Column(db.String(64))

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
    last_login = db.Column(db.Integer, nullable=False)
    created = db.Column(db.Integer)
    fullname = db.Column(db.String(128))
    mail = db.Column(db.String(128))
    profile = db.Column(db.String(64))

    def __repr__(self):
        return '<User %r>' % self.username

class UserModelView(ModelView):
    # fix for ldap errors breaking user signup - manual entries required
    form_columns = ('username', 'fullname', 'password', 'flag', 'mail', 'last_login', 'role')
    column_exclude_list = ['password']

    # necessary to stop flask-admin from saving passwords in cleartext :(
    def on_model_change(self, form, model, is_created):
        # If creating a new user, hash password
        if is_created:
            model.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            model.created = unixtime()
            # grab the profile automatically from the admin form when creating new user
            model.profile = get_profile(form.username.data)
            # line below is for when ldap is working properly
            # model.fullname, model.mail, model.profile = scrape_user_info(model.username, model.role.name)
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

class SkillInstanceModelView(ModelView):
    form_columns = ('name', 'course', 'schoolyear', 'period')
    
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
admin.add_view(SkillInstanceModelView(SkillInstance, db.session))

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

def get_skillbookings(roomdata, caldate, skill, sdict):    
    booking_data = {}
    tds = f'style="border-radius:10px;width: {100//roomdata.pods}%"'
    tdsb = f'style="border-radius:10px;border-width:3px;border-color:DarkSlateGray;width: {100//roomdata.pods}%"'
    tdcl = f'class="text-center align-middle'
    bookflag = 'STANDARD'
    baseurl = url_for("index")
    BOOK_HOURS = sdict['dates'][caldate][roomdata.name]['times']
    epoch = date_to_sec(caldate[2:])
    for hour in BOOK_HOURS:
        booking_data[hour] = {}
        for pod in range(1, roomdata.pods+1):
            mod_epoch = epoch+((int(hour.split(':')[0])*3600) + (int(hour.split(':')[1])*60))
            data = SkillBooking.query.filter(
                SkillBooking.time==mod_epoch).filter(
                SkillBooking.room==roomdata.name.upper()).filter(
                SkillBooking.timeslot==pod).filter(
                SkillBooking.skill_id==skill.id).all()
            bookurl = f'{skill.id}/{sec_to_date(mod_epoch)}/{roomdata.name}/{hour}/{pod}'
            book_icon = f'<a href="{baseurl}bookskill/{bookurl}" style=color:black><font size=+1><i class="bi bi-calendar-plus"></i></font></a>'
            expired_icon = f'<font size=+1><i class="bi bi-x-octagon"></i></font>'
            if data is None:
                if current_user.is_authenticated and current_user.role.name in ['Admin', 'Teacher']:
                    booking_data[hour][pod] = f'<td {tds} {tdcl} table-success">{book_icon}</td>'
                else:
                    if check_book_epoch(mod_epoch, 1):
                        booking_data[hour][pod] = f'<td {tds} {tdcl} table-success">{book_icon}</td>'
                    else:
                        booking_data[hour][pod] = f'<td {tds} {tdcl} table-secondary">{expired_icon}</td>'
            else:
                if len(data) >= 1:
                    data = data[0]
                    showstring = f'XXX{data.student}</a>'
                    fullname, mail, profile = check_user_details(data.student)
                    user_link = f'<a href="#" data-bs-toggle="modal" data-bs-target="#userInfo" data-bs-fullname="{fullname}" data-bs-mail="{mail}" data-bs-profile="{profile}" data-bs-username="{data.student}" data-bs-bookurl="{bookurl}" data-bs-baseurl="{baseurl}">{showstring.replace("XXX", "")}</a>'
                    expire_link = f'<a href="#" data-bs-toggle="modal" data-bs-target="#oldBooking">{showstring.replace("XXX", "")}</a>'
                    book_icon = f'<a href="{baseurl}book/{bookurl}" style=color:black><font size=+1><i class="bi bi-calendar-plus"></i></font></a>'
                    admin_icon = f'<font size=+1><i class="bi bi-shield-lock"></i></font>'
                    # if the pod isn't marked as available
                    if data.flag != 'AVAILABLE':
                        if current_user.is_authenticated:
                            if current_user.role.name in ['Admin', 'Teacher']:
                                booking_data[hour][pod] = f'<td {tds} {tdcl} table-warning">{user_link}</td>'
                            else:
                                booking_data[hour][pod] = f'<td {tds} {tdcl} table-danger">{admin_icon}</td>'
                        else:
                            booking_data[hour][pod] = f'<td {tds} {tdcl} table-danger">{admin_icon}</td>'
                    else:
                        if current_user.is_authenticated:
                            if check_book_epoch(mod_epoch, 1) and current_user.username == data.student:
                                booking_data[hour][pod] = f'<td {tdsb} {tdcl} table-warning">{user_link}</td>'
                            elif current_user.role.name in ['Admin', 'Teacher']:
                                booking_data[hour][pod] = f'<td {tds} {tdcl} table-warning">{user_link}</td>'
                            elif current_user.username == data.student:
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
                        if check_book_epoch(mod_epoch, 1):
                            booking_data[hour][pod] = f'<td {tds} {tdcl} table-success">{book_icon}</td>'
                        else:
                            booking_data[hour][pod] = f'<td {tds} {tdcl} table-secondary">{expired_icon}</td>'

    return booking_data, bookflag

def get_bookings(roomdata, epoch):
    booking_data = {}
    tds = f'style="border-radius:10px"'
    tdsb = f'style="border-radius:10px;border-width:3px;border-color:DarkSlateGray;"'
    tdcl = f'class="text-center align-middle'
    bookflag = 'STANDARD'
    admins = [x.username for x in User.query.filter(User.role_id!=2).all()]
    baseurl = url_for("index")
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
                # if the pod isn't marked as available
                if data[0].name1 in admins:
                    if data[0].comment in ['ALLSLOTS', 'MORNING', 'AFTERNOON', 'SCHOOLDAY']:
                        bookflag = data[0].comment
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
    fac='BOOK'
    if current_user.role.name == "Student":
        # disallow booking if booking in the past (but give a grace period)
        baseurl = url_for("index")
        if not check_book_epoch(epoch, GRACE_MINUTES):
            flash(f'Not permitted to book pod at this time! You cant book expired timeslots!', 'warning')
            return False, f'{baseurl}show/{roomdata.name.upper()}/{sec_to_date(epoch)}'
        else:
            # check how many bookings currently exist on the user, beginning on any current booking timeslot
            now_hr = epoch_hr('HR')
            user_time_start = epoch_hr('NOW')
            for hour in BOOK_HOURS:
                if now_hr in range(hour, hour+3) and now_hr != 12:
                    user_time_start = date_start_epoch(user_time_start) + (3600*hour)
            duration_data = [x.duration for x in Bookings.query.filter(Bookings.time>=user_time_start).filter(Bookings.name1==current_user.username).all()]
            if sum(duration_data) > 2:
                flash(f'Not permitted to book pod at this time! You have too many booked slots!', 'warning')
                log_webhook(facility=fac, severity=4, msg=f'{current_user.username} : Not permitted to book pod at this time! You have too many booked slots!')
                return False, f'{baseurl}show/{roomdata.name.upper()}/{sec_to_date(epoch)}'
    if len(Bookings.query.filter(Bookings.time==epoch).filter(Bookings.room==roomdata.id).filter(Bookings.pod==ord(pod.upper())-64).all()) >= 1:
        flash('This timeslot is no longer available. Please pick another time or pod.', 'warning')
        log_webhook(facility=fac, severity=4, msg=f'{current_user.username} : This timeslot is no longer available. Please pick another time or pod.')
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
    
def view_bookings(user):
    now_hr = epoch_hr('HR')
    user_time_start = epoch_hr('NOW')
    for hour in BOOK_HOURS:
        if now_hr in range(hour, hour+3):
            user_time_start = date_start_epoch(user_time_start) + (3600*hour)
    try:
        bookings_list = [x for x in Bookings.query.filter(Bookings.time>=user_time_start).filter(Bookings.name1==user).all()]
    except:
        bookings_list = []
    bookings_dict = {}
    if len(bookings_list) >= 1:
        rooms = get_rooms()
        for i in range(len(bookings_list)):
            b = bookings_list[i]
            date = sec_to_date(b.time), epoch_hr(b.time)
            room = rooms[b.room-1]
            pod = chr(b.pod+64)
            comment = b.comment
            bookings_dict[i+1] = {'date': date, 'room': room.name, 'pod': pod, 'comment': comment}
            ical_data = generate_ical(b.time, user, room.name, pod)
            session[f'ics{i+1}'] = ical_data

    return bookings_dict

def set_skillbooking(room, skill, epoch, pod, form):
    fac='SKILLBOOKING'
    bookflag = 'UNAVAILABLE'
    if current_user.role.name == "Student":
        # disallow booking if booking in the past
        baseurl = url_for("index")
        bookflag = 'AVAILABLE'
        if not check_book_epoch(epoch, 0):
            flash(f'Not permitted to book pod at this time! The exam has already started!', 'warning')
            return False, f'{baseurl}skills'
        else:
            # check so the user doesn't already have a skill booking..
            num_skillbookings = len(SkillBooking.query.filter(SkillBooking.skill_id==skill.id).filter(SkillBooking.student==form.get('booker')).all())
            if num_skillbookings > 0:
                flash(f'Not permitted to book skill at this time! You already have a booked slot!', 'warning')
                log_webhook(facility=fac, severity=4, msg=f'{current_user.username} : Not permitted to book skill at this time! You already have a booked slot!')
                return False, f'{baseurl}skills'
    if len(SkillBooking.query.filter(
            SkillBooking.skill_id==skill.id).filter(
            SkillBooking.time==epoch).filter(
            SkillBooking.room==room.upper()).filter(
            SkillBooking.timeslot==pod).all()) > 0:
        flash('This timeslot is no longer available. Please pick another time or seat.', 'warning')
        log_webhook(facility=fac, severity=4, msg=f'{current_user.username} : This timeslot is no longer available. Please pick another time or seat.')
        return False, f'{baseurl}showskill/{skill.id}/{room.upper()}/{sec_to_date(epoch)}'
    else:
        # teachers booking students trip this statement, avoids red-marked reservation slot
        if current_user.username != form.get('booker'):
            bookflag = 'AVAILABLE'
        booking = SkillBooking(
            skill_id=skill.id,
            room=room.upper(),
            date=sec_to_date(epoch),
            time=epoch,
            timeslot=pod,
            student=form.get('booker'),
            result='UNGRADED',
            teacher='UNGRADED',
            comment='UNGRADED',
            flag=bookflag
        )
        return True, booking

def get_skill_users(id, caldate, room):
    skill_dict = build_skill_dict(SkillInstance.query.filter(SkillInstance.id==id).first())
    userdata = {}
    userdata['date'] = caldate
    userdata['room'] = room.upper()
    userdata['students'] = {}
    skill_data = skill_dict[0]['dates'][caldate][room.upper()] 
    for time in skill_data['times']:
        skill_time = date_to_sec(caldate[2:]) + (int(time.split(':')[0])*3600) + (int(time.split(':')[1])*60)
        skill_time_end = endtimes(time, skill_data['duration'])
        students = SkillBooking.query.filter(
                   SkillBooking.skill_id==id).filter(
                   SkillBooking.time==skill_time).filter(
                   SkillBooking.room==room.upper()).all()
        userdata['students'][time] = {}
        studentlist = []
        for student in students:
            user = User.query.filter(User.username==student.student).first()
            studentlist.append(user)
        userdata['students'][time]['info'] = studentlist
        userdata['students'][time]['endtime'] = skill_time_end
        
    return userdata

def build_skill_dict(skill):
    std_dates = sorted(skill.standard_dates.split(','))
    ext_dates = sorted(skill.extra_dates.split(','))
    all_dates = sorted(set(std_dates + ext_dates)) if 'UNSET' not in ext_dates else std_dates
    sdata = {"alldates" : all_dates, "skill" : skill, "dates" : {}}
    try:
        for date in std_dates:
            for room in sorted(skill.standard_rooms.upper().split(',')):
                if date not in sdata["dates"]:
                    sdata["dates"][date] = {}
                sdata["dates"][date][room] = {
                    "times": sorted(skill.standard_times.split(',')),
                    "duration": skill.standard_duration
                }
        if 'UNSET' not in ext_dates:
            for date in ext_dates:
                for room in sorted(skill.extra_rooms.upper().split(',')):
                    if date not in sdata["dates"]:
                        sdata["dates"][date] = {}
                    sdata["dates"][date][room] = {
                        "times": sorted(skill.extra_times.split(',')),
                        "duration": skill.extra_duration
                    }
        return sdata, 'True'
    except:
        return sdata, 'False'

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', msg=e), 404

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_login = unixtime()
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/show/<room>')
@app.route('/show/<room>/<caldate>')
def show(room, caldate='Null'):
    global scheduledetails
    global scheduletimestamp
    if len(scheduledetails) == 0 or abs(unixtime()-scheduletimestamp) > 21600:
        tempdetails = {}
        tempdetails, scheduletimestamp = pull_ics_data()
        if len(tempdetails) > 0:
            scheduledetails = tempdetails
    if room.upper() not in [x.name for x in Rooms.query.all()]:
        flash("No such resource, check room name!", "danger")
        abort(404, description="Resource not found")
    if caldate == 'Null':
        return redirect(url_for("show", room=room.upper(), caldate=date_to_str()))
    else:
        # Validation to catch incorrect date entries
        if not re.match(r"\d{2}-\d{1,2}-\d{1,2}$", caldate):
            flash("Invalid date format. Expected YY-MM-DD.", "danger")
            return redirect(url_for('show', room=room.upper()))            
        today_d = caldate
    dates = init_dates(today_d)
    show = {}
    roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
    show['room'] = {'name': roomdata.name.upper(), 'pods': [chr(x+65) for x in range(roomdata.pods)]}
    show['dates'] = dates
    show['clocks'] = BOOK_HOURS
    show['query'], show['flag'] = get_bookings(roomdata, dates['today']['string'])
    disabled_rooms = current_app.config['SETTINGS']['base']['disabled']
    return render_template('show.html', show=show, cal=scheduledetails, SITE_PREFIX=url_for("index"), roomdata=disabled_rooms)

@app.route('/showskill/<id>')
@app.route('/showskill/<id>/<caldate>')
@app.route('/showskill/<id>/<caldate>/<room>')
@login_required
def showskill(id, room='Null', caldate='Null'):
    if 'Null' in caldate:
        try:
            skill = SkillInstance.query.filter(SkillInstance.id==id).first()
            _ = skill.id
        except:
            flash("DATE: No such resource, check skill identifier!", "danger")
            return redirect(url_for('skills'))
        std_dates = sorted(skill.standard_dates.split(','))
        std_rooms = sorted(skill.standard_rooms.upper().split(','))
        return redirect(url_for('showskill', id=skill.id, caldate=std_dates[0], room=std_rooms[0]))
    elif 'Null' in room:
        # catching requests for the default view for a specific skilldate but no room
        try:
            skill = SkillInstance.query.filter(SkillInstance.id==id).first()
            _ = skill.id
        except:
            flash("ROOM: No such resource, check skill identifier!", "danger")
            return redirect(url_for('skills'))
        show = {}
        show['dict'], show['status'] = build_skill_dict(skill)
        all_rooms = sorted([x for x in show['dict']['dates'][caldate].keys()])
        return redirect(url_for('showskill', id=skill.id, caldate=caldate, room=all_rooms[0]))
    else:
        try:
            skill = SkillInstance.query.filter(SkillInstance.id==id).first()
            roomdata = Rooms.query.filter(Rooms.name==room).all()[0]
            x, y = skill.id, roomdata.id
            if skill.status != 'PUBLISH' and current_user.role.name not in ['Admin', 'Teacher']:
                raise ValueError('ID: Skill is not published!')
        except:
            flash("ID: No such resource, check skill identifier!", "danger")
            return redirect(url_for('skills'))
        room = room.upper()
        if ((room in skill.standard_rooms.upper().split(',') and caldate in skill.standard_dates.split(',')) or 
            (room in skill.extra_rooms.upper().split(',') and caldate in skill.extra_dates.split(','))):
            # the room and date exists in the skillinstance object we selected
            show = {}
            show['dict'], show['status'] = build_skill_dict(skill)
            if show['status'] == 'True':
                show['room'] = {'name': room, 'pods': [x for x in range(roomdata.pods)]}
                show['clocks'] = show['dict']['dates'][caldate][roomdata.name]['times']
                show['query'], show['status'] = get_skillbookings(roomdata, caldate, skill, show['dict'])
                all_rooms = sorted([x for x in show['dict']['dates'][caldate].keys()])
                return render_template('showskill.html', show=show, SITE_PREFIX=url_for("index"), room=all_rooms)
            else:
                flash("Unable to process skillinfo!", "danger")
                return redirect(url_for('skills'))
        else:
            flash("No skill instance with that calender & room data!", "danger")
            return redirect(url_for('skills'))

@app.route('/bookskill')
@app.route('/bookskill/<id>')
@app.route('/bookskill/<id>/<caldate>')
@app.route('/bookskill/<id>/<caldate>/<room>')
@app.route('/bookskill/<id>/<caldate>/<room>/<time>/<pod>', methods=('GET', 'POST'))
@login_required
def bookskill(id='Null', room='Null', caldate='Null', time='Null', pod='Null'):
    if request.method == 'POST':
        fac='BOOKSKILL'
        # verify the request is valid
        try:
            _ = int(id)
            skill = SkillInstance.query.filter(SkillInstance.id==id).first()
            _ = skill.id
            if skill.status != 'PUBLISH' and current_user.role.name not in ['Admin', 'Teacher']:
                raise ValueError('ID: Skill is not published!')
            # manual input of invalid id will abort on .username attribute, crashing to exception and abort booking
            booker = request.form.get('booker')
            booker_query = User.query.filter(User.username==booker).first()
            booker == booker_query.username
            sdict = build_skill_dict(skill)
            # check if this is a NAIS booking
            if caldate in skill.extra_dates and room in skill.extra_rooms and time in skill.extra_times:
                if f'NAIS-{request.form.get("booker")}' not in skill.comment:
                    flash(f'You do not have access to book the extended skill session!', "danger")
                    return redirect(url_for("skills"))
            if time in sdict[0]['dates']['20' + caldate][room.upper()]['times']:
                book_time = date_to_sec(caldate) + (int(time.split(':')[0])*3600) + (int(time.split(':')[1])*60)
                state, booking = set_skillbooking(room.upper(), skill, book_time, pod, request.form)
                if state:
                    global lock_commit
                    while lock_commit == True:
                        sleep(0.005)
                    lock_commit = True

                    db.session.add(booking)
                    try:
                        db.session.commit()
                        log_webhook(facility=fac, severity=6, msg=f'{current_user.username} : Skill successfully booked!')
                        flash(f'Skill successfully booked!', 'success')
                    except Exception as e:
                        db.session.rollback()
                        flash(f'Exception at rollback: {e}', "danger")
                        log_webhook(facility=fac, severity=4, msg=f'{current_user.username} : {e}')

                    lock_commit = False
                    
                    return redirect(url_for("showskill", id=skill.id, room=room.upper(), caldate='20' + caldate), code=302)
                else:
                    return redirect(booking)
        except Exception as e:
            flash(f"Invalid booking parameters! {e}", "warning")
            return redirect(url_for("skills"))
    elif request.method == 'GET':
        if 'Null' in locals().values():
            flash("Invalid booking parameters!", "warning")
            return redirect(url_for("skills"))
        else:
            # verify the request is valid
            try:
                _ = int(id)
                skill = SkillInstance.query.filter(SkillInstance.id==id).first()
                _ = skill.id
                if skill.status != 'PUBLISH' and current_user.role.name not in ['Admin', 'Teacher']:
                    raise ValueError('ID: Skill is not published!')
                sdict = build_skill_dict(skill)
                if time in sdict[0]['dates']['20' + caldate][room.upper()]['times']:
                    DAY = 84600
                    students = User.query.filter(User.role_id==2).filter(User.last_login>=unixtime()-(30*DAY)).order_by("username").all()
                    return render_template('bookskill.html', data=locals(), skill=skill, student_data=students)
                else:
                    return redirect(url_for("showskill", id=id), code=302)
            except Exception as e:
                flash(f"Invalid booking parameters! {e}", "warning")
                return redirect(url_for("skills"))

@app.route('/book')
@app.route('/book/<room>')
@app.route('/book/<room>/<caldate>')
@app.route('/book/<room>/<caldate>/<hr>/<pod>', methods=('GET', 'POST'))
@login_required
def book(room='Null', caldate='Null', hr='Null', pod='Null'):
    if request.method == 'POST' and int(hr) in BOOK_HOURS:
        fac='BOOK'
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
                log_webhook(facility=fac, severity=6, msg=f'{current_user.username} : Pod successfully booked!')
            except Exception as e:
                db.session.rollback()
                flash(e, "danger")
                log_webhook(facility=fac, severity=4, msg=f'{current_user.username} : {e}')

            lock_commit = False
            
            ical_data = generate_ical(book_time, current_user.username, room.upper(), pod)
            session['icsflash'] = ical_data
            flash(f'Pod successfully booked! <a href="{url_for("getcal", ics="icsflash")}">Add me to calendar</a>', 'success')
            return redirect(url_for("show", room=roomdata.name.upper(), caldate=caldate), code=302)
        else:
            return redirect(booking)
    else:
        if 'Null' in locals().values():
            return redirect(url_for("show", room="B114", caldate=date_to_str()), code=302)
        else:
            roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
            # if this is a valid book url...
            if int(hr) in BOOK_HOURS:
                roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
                book_time = date_to_sec(caldate) + (3600 * int(hr))
                return render_template('book.html', data=locals())
            else:
                return redirect(url_for("show", room=roomdata.name.upper()), code=302)

@app.route('/getcal/<ics>')
@login_required
def getcal(ics):
    """
    Fetches the iCalendar data associated with a given key from the user's session and 
    returns it as a downloadable file response.

    The function retrieves iCalendar data stored in the session, then sends it back 
    as a MIME type 'text/calendar' attachment, allowing users to download it as an 
    iCalendar (.ics) file.

    Parameters:
    ics (str): The key used to retrieve the iCalendar data from the session.

    Returns:
    Response: A Flask response object with the iCalendar data as a downloadable .ics file.
    """
    ical_data = session[ics]
    response = Response(ical_data, mimetype='text/calendar')
    response.headers.set('Content-Type', 'text/calendar')
    response.headers.set('Content-Disposition', 'attachment', filename='booking.ics')
    return response

@app.route('/delete/<room>')
@app.route('/delete/<room>/<caldate>')
@app.route('/delete/<room>/<caldate>/<hr>')
@app.route('/delete/<room>/<caldate>/<hr>/<pod>')
@login_required
def delete(room='Null', caldate='Null', hr='Null', pod='Null'):
    # verify delete url args
    if 'Null' in locals().values():
        return redirect(url_for("show", room="B114", caldate=date_to_str()), code=302)
    else:
        try:
            _ = ord(pod)-64
            _ = int(hr)
            _ = caldate[:]
        except:
            flash("Invalid deletion data!", "danger")
            return redirect(url_for("show", room="B114", code=302))
        fac='DELETE'
        epoch = date_to_sec(caldate)
        roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
        delete_request = Bookings.query.filter(Bookings.time==(epoch+(int(hr)*3600))).filter(Bookings.room==roomdata.id).filter(Bookings.pod==ord(pod)-64)
        can_delete = False
        if current_user.role.name in ['Teacher', 'Admin']:
            can_delete = True
        elif current_user.username == delete_request[0].name1:
            if unixtime() < delete_request[0].time:
                can_delete = True
            else:
                flash("Ah ah ah, You didn't say the magic word!", "warning")
                return redirect(url_for("show", room=roomdata.name.upper(), caldate=caldate), code=302)        
        if can_delete:
            global lock_commit
            while lock_commit == True:
                sleep(0.025)
            lock_commit = True
            
            delete_request.delete()
            db.session.commit()
            
            lock_commit = False            
            
            log_webhook(facility=fac, severity=6, msg=f'{current_user.username} : Reservation slot deleted!')
            flash("Reservation slot deleted", "success")
        else:
            log_webhook(facility=fac, severity=4, msg=f'{current_user.username} : Unauthorized deletion request!')
            flash("Unauthorized deletion request!", "warning")
        return redirect(url_for("show", room=roomdata.name.upper(), caldate=caldate), code=302)

@app.route('/sbdelete/<id>/<caldate>/<room>/<time>/<pod>')
@login_required
def sbdelete(id='Null', caldate='Null', room='Null', time='Null', pod='Null'):
    # verify delete url args
    if 'Null' in locals().values():
        return redirect(url_for("skills"), code=302)
    else:
        try:
            _ = int(pod)
            _ = time[:]
            _ = caldate[:]
            skill = SkillInstance.query.filter(SkillInstance.id==id).first()
            if skill.status != 'PUBLISH' and current_user.role.name not in ['Admin', 'Teacher']:
                    raise ValueError('ID: Skill is not published!')
        except:
            flash("Invalid deletion data!", "danger")
            return redirect(url_for("skills"), code=302)
        fac='SKILLBOOKING-DELETE'
        epoch = date_to_sec(caldate)
        mod_epoch = epoch + ((int(time.split(':')[0])*3600) + (int(time.split(':')[1])*60))

        delete_request = SkillBooking.query.filter(SkillBooking.skill_id==id).filter(SkillBooking.time==mod_epoch).filter(SkillBooking.room==room.upper()).filter(SkillBooking.timeslot==pod)
        if current_user.username == delete_request[0].student or current_user.role.name in ['Teacher', 'Admin']:
            global lock_commit
            while lock_commit == True:
                sleep(0.025)
            lock_commit = True
            
            delete_request.delete()
            db.session.commit()
            
            lock_commit = False            
            
            log_webhook(facility=fac, severity=6, msg=f'{current_user.username} : Reservation slot deleted!')
            flash("Skill Reservation slot deleted", "success")
        else:
            log_webhook(facility=fac, severity=4, msg=f'{current_user.username} : Unauthorized deletion request!')
            flash("Unauthorized skill deletion request!", "warning")
        return redirect(url_for("showskill", id=id, room=room.upper(), caldate='20' + caldate), code=302)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # validating form
    if form.validate_on_submit():
        name = form.name.data.split('@')[0]
        # help users logging in with uncooperative phones that capitalizes input
        name = name.lower()
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
    """
    Handles user signup by validating input from a login form and creating a 
    new user entry in the database if the user does not already exist. 

    Authentication is checked against an LDAP service using the function 
    test_ldap_auth(). If the user is authenticated and does not exist in the 
    system, their details are scraped using the function scrape_user_info() 
    and a new user entry is created.

    The function also handles thread-safe database commits using a global 
    lock, `lock_commit`, to ensure data integrity.

    Parameters:
    None

    Returns:
    render_template: Flask template for the signup page, with form details.
                     It may also redirect to the login page in certain scenarios.

    Raises:
    None explicitly, but underlying functions (like database commits or 
    LDAP authentication) may raise exceptions.
    """
    fac='SIGNUP'
    form = LoginForm()
    # validating form
    if form.validate_on_submit():
        name = form.name.data.split('@')[0]
        password = form.password.data
        form.name.data = ''
        form.password.data = ''
        
        user = User.query.filter_by(username=name.lower()).first()
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

                log_webhook(facility=fac, severity=6, msg=f'{name.lower()} : User successfully created!')
                flash('User successfully created, go ahead and log in!', 'success')

                lock_commit = False
                return redirect(url_for('login'))
            else:
                log_webhook(facility=fac, severity=4, msg=f'{name} : Invalid user or password!')
                flash('Invalid user or password!', 'danger')
        else:
            log_webhook(facility=fac, severity=3, msg=f'{name} : User already exists!')
            flash('User already exists! Try logging in instead.', 'danger')
            return redirect(url_for('login'))
        return render_template('signup.html', form=form)

    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/skillstatus/<id>/<status>')
@login_required
def skillstatus(id, status):
    if current_user.role.name in ['Admin', 'Teacher']:
        skill = SkillInstance.query.filter(SkillInstance.id==id).first()
        skill.status = status
        db.session.commit()
        flash(f"Skill {id}:{skill.name} status changed to {skill.status}.", "success")
        return redirect(url_for('skills'), code=302)
    else:
        abort(404, description="Resource not found")

@app.route('/skills')
@app.route('/skills/<year>')
@app.route('/skills/users/<id>/<caldate>/<room>/')
@login_required
def skills(year='Null', id='Null', caldate='Null', room='Null'):
    sk_rule = request.url_rule
    if 'users' in str(sk_rule):
        data = get_skill_users(id, caldate, room)
        skill = SkillInstance.query.filter(SkillInstance.id==id).first()
        return render_template('skills_users.html', data=data, skill=skill)
    else:
        if year != 'Null':
            all_skills = SkillInstance.query.filter(SkillInstance.name.contains(year)).all()
        else:
            all_skills = SkillInstance.query.all()
        archived, published = 0, 0
        for skill in all_skills:
            if skill.status == 'PUBLISH':
                published += 1
            elif skill.status == 'ARCHIVED':
                archived += 1
        active = len(all_skills) - archived
        return render_template('skills.html', all=all_skills, numskills=(active, published, archived), year=year)

@app.route('/setskill', methods=['GET', 'POST'])
@login_required
def setskill():
    if current_user.role.name in ['Admin', 'Teacher']:
        form = CreateSkillsInstanceForm()
        if request.method == 'GET':
            return render_template('skills_teacher.html', form=form)
        elif request.method == 'POST':
            if form.validate_on_submit():
                if form.comment.data is None:
                    form.comment.data = ''
                instance = SkillInstance(
                    created=unixtime(),
                    owner=current_user.username,
                    name=form.name.data,
                    course=form.course.data,
                    schoolyear=form.year.data,
                    period=form.period.data,
                    standard_times='UNSET',
                    standard_dates='UNSET',
                    standard_rooms='UNSET',
                    standard_duration=60,
                    comment=form.comment.data,
                    extra_times='UNSET',
                    extra_dates='UNSET',
                    extra_rooms='UNSET',
                    extra_duration=60,
                    type=form.type.data,
                    status='HIDDEN'
                )

                global lock_commit
                while lock_commit == True:
                    sleep(0.025)
                lock_commit = True
                
                db.session.add(instance)
                db.session.commit()

                # log_webhook(facility='SKILLINSTANCE', severity=6, 
                # msg=f'{current_user.username} : Skill added ({form.name}-{form.course}-{form.year}-{form.period})')

                lock_commit = False

                return redirect(url_for("skills"))
    else:
        return redirect(url_for("skills"))

@app.route('/skilldates/<id>', methods=['GET', 'POST'])
@login_required
def skilldates(id):
    if current_user.role.name in ['Admin', 'Teacher']:
        form = CreateSkillsLocAndDatesForm()
        if request.method == 'GET':
            try:
                skillinstance = SkillInstance.query.filter(SkillInstance.id==id).first()
                _ = skillinstance.id
            except:
                flash("No such resource, check skill identifier!", "danger")
                abort(404, description="Resource not found")

            skillinstance = SkillInstance.query.filter(SkillInstance.id==id).first()
            form.comment.data = skillinstance.comment
            return render_template('skills_date_and_loc.html', form=form, skill=skillinstance)
        elif request.method == 'POST':
            if form.validate_on_submit():
                skillinstance = SkillInstance.query.filter(SkillInstance.id==form.skill_id.data).first()
                skillinstance.name = form.skill_name.data
                skillinstance.standard_dates = form.standard_dates.data.lstrip(';').replace(' ', '').replace(';', ',').replace('-0', '-')
                skillinstance.standard_times = form.standard_times.data.lstrip(',').replace(' ', '')
                skillinstance.standard_rooms = form.standard_rooms.data.lstrip(',').replace(' ', '')
                skillinstance.standard_duration = form.standard_duration.data
                skillinstance.comment = form.comment.data
                               
                num_unset = sum([int('UNSET' in i) for i in [form.extra_dates.data, form.extra_times.data, form.extra_rooms.data]])
                if 0 < num_unset < 3:
                    flash("Error, either fill all extra fields or leave them untouched", "warning")
                    return redirect(url_for("skills"))
                else:
                    skillinstance.extra_dates = form.extra_dates.data.lstrip(';').replace(' ', '').replace(';', ',').replace('-0', '-')
                    skillinstance.extra_times = form.extra_times.data.lstrip(',').replace(' ', '')
                    skillinstance.extra_rooms = form.extra_rooms.data.lstrip(',').replace(' ', '')
                    skillinstance.extra_duration = form.extra_duration.data
                
                db.session.commit()
                flash("Skill successfully updated!", "success")
                return redirect(url_for("skills"))
            else:
                flash("form could not be validated!", "danger")
                return redirect(url_for("skills"))
    else:
        flash("Unauthorized request!", "danger")
        return redirect(url_for("skills"))

@app.route('/help')
@app.route('/help/<lang>')
def help(lang='Null'):
    if lang == 'en':
        return render_template('help_en.html')
    else:
        return render_template('help.html')

@app.route('/news')
def news():
    """
    Loads and sorts news data from a 'news.json' file, then renders it on 
    the 'news.html' template. News items are sorted by date in descending order.

    Returns:
    render_template: Flask template with the sorted news data.
    """    
    with open('news.json', 'r', encoding='utf-8') as f:
        news = json.load(f)
        news.sort(key=lambda x: datetime.strptime(x['date'], '%d %B, %Y'), reverse=True)
    return render_template('news.html', news=news)

@app.route('/')
@app.route('/<data>')
def index(data='Null'):
    """
    Handles route for the main page of a web application, providing redirection for legacy 
    PHP lab room links, rendering English version of the homepage, and showing lab room 
    association from user's session.

    Parameters:
    data (str, optional): Route data which can be 'php', 'en', or other. Defaults to 'Null'.

    Returns:
    render_template: Flask template response. Depending on the provided data, this could be 
    a redirection, 'index_en.html', or 'index.html' with or without lab room information.
    """
    if 'php' in data:
        labrooms = ['','B112', 'B114', 'B118', '', '', '', 'B125', 'B123']
        labroom_id = int(request.args.get('room'))
        session['labroom'] = labrooms[labroom_id]
        return redirect(url_for("index"))
    elif 'en' == data:
        return render_template('index_en.html')
    else:
        try:
            labroom = session.pop('labroom')
            if labroom == 'B112':
                labroom = 'B114'
            return render_template('index.html', rr=labroom)
        except:
            return render_template('index.html', rr='Null')

@app.route('/highscore')
def highscore():
    def year_top_ten(year_users, sept1):
        year_bookings = Bookings.query.with_entities(Bookings.name1, Bookings.name2, Bookings.time, Bookings.flag).filter(Bookings.time >= sept1).all()

        for name1, name2, _, flag in year_bookings:
            if flag == 'AVAILABLE':
                year_users[name1.lower()] += 1
                if name2 and name2.lower() != name1.lower():
                    year_users[name2.lower()] += 1

        year_sorted_users = sorted(year_users.items(), key=lambda x: x[1], reverse=True)
        year_top_users = [(user, count) for user, count in year_sorted_users][:10]
        highscore = {i: {} for i in range(1,11)}
        
        for i in range(10):
            username, hours = year_top_users[i]
            details = User.query.filter_by(username=username).first()
            highscore[i+1] = (username, details.fullname, details.profile, int(hours)*2)

        return highscore
    
    year1_stats = {i: ('aaaa0000', 'unclaimed', '', 0) for i in range(1,11)}
    year2_stats = {i: ('aaaa0000', 'unclaimed', '', 0) for i in range(1,11)}
    
    year1_sept1 = year_start_unixtime()
    year2_sept1 = year1_sept1 - 31536000

    year1_stats = year_top_ten(defaultdict(int), year1_sept1)
    year2_stats = year_top_ten(defaultdict(int), year2_sept1)
    
    return render_template('highscore.html', year1=year1_stats, year2=year2_stats)

@app.route('/confirm', methods=['POST'])
def confirm():
    response = request.json
    token = response["token"]

    if token == "12345":
        user_id = response["data"]["user_id"]
        

@app.route('/debug')
@login_required
def debug():
    stuff='trololol'
    return render_template('debug.html', debugdata=stuff)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'GET':
        if current_user.role.name in ['Admin', 'Teacher']:
            app.config['SETTINGS'] = read_config()
            return render_template('settings.html', config=app.config['SETTINGS'])
        else:
            flash("Invalid or unknown resource!", "error")
            return redirect(url_for("index"))
    elif request.method == 'POST':
        if current_user.role.name in ['Admin', 'Teacher']:
            current_app.config['SETTINGS']['base']['disabled'] = request.form.getlist('room_disabled')
            current_app.config['SETTINGS']['base']['logging']['SEVERITY'] = int(request.form['severity_select'])
            current_app.config['SETTINGS']['base']['logging']['ENABLE'] = request.form.get('enable') == 'on'
            current_app.config['SETTINGS']['base']['logging']['WEBHOOK'] = request.form['webhook']
            write_config(app.config['SETTINGS'])
            flash("Settings have been successfully updated!", "success")
            return render_template('settings.html', config=app.config['SETTINGS'])
        else:
            flash("Invalid or unknown resource!", "error")
            return redirect(url_for("index"))

@app.route('/user/<username>')
@app.route('/user/<username>/<option>')
@login_required
def user(username, option=''):
    user = User.query.filter_by(username=username).first_or_404()
    if option == '':
        return render_template('user.html', user=user, data=view_bookings(user.username))
    elif option == 'refresh':
        if current_user.username == username:
            profile = get_profile(current_user.username)
            if profile != current_user.profile:
                current_user.profile = profile
                db.session.commit()
                flash("Profile image has been updated from mittkonto.hv.se", "success")
            else:
                flash("There is no newer image on mittkonto.hv.se, profile not changed!", "warning")
        else:
            flash("Invalid update request!", "error")
        return redirect(url_for('user', username=username, option='', data=view_bookings(user.username)).rstrip('/'))

@app.template_filter('mobile_table')
def mobile_table(html):
    """
    Transforms the provided HTML string to be more mobile-friendly. Modifies
    an <a> tag, replacing its text with a Bootstrap icon and removing any 
    siblings and subsequent content within the <td> tag. The modified HTML 
    string is returned.

    Parameters:
    html (str): A string of HTML representing a table cell. It's expected to
    contain an <a> tag, which may have siblings and subsequent content.

    Returns:
    str: The modified HTML string, where the <a> tag's text has been replaced
    by a Bootstrap icon and any siblings and subsequent content are removed.
    """
    soup = bs(html, 'html.parser')
    td_tag = soup.find('td')
    del td_tag['style']
    a_tag = soup.find('a')
    if a_tag is not None:
        # check if the <a> tag contains an <i> tag
        if a_tag.find('i') is None:
            # replace the username text with a small icon
            a_tag.clear()
            new_tag = soup.new_tag('i')
            new_tag['class'] = 'bi bi-person-lines-fill'
            a_tag.append(new_tag)

            # remove labb-partner and eventual comment
            for sibling in a_tag.find_next_siblings():
                sibling.decompose()

    output = str(soup)
    a_tag_i = output.find('</a>')
    if a_tag_i != -1:
        a_endtag_i = a_tag_i + 4
        output = output[:a_endtag_i] + '</td>'

    return output

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

# TODO: #3 Split application into smaller modules - easy peasy