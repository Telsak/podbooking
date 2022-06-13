from asyncio.format_helpers import _format_args_and_kwargs
from contextlib import redirect_stdout
from encodings import CodecRegistryError
from multiprocessing.spawn import old_main_modules
import os
from wsgiref.validate import validator
from flask import Flask, render_template, abort, redirect, request, flash, url_for
from flask_admin import Admin, AdminIndexView, expose, menu
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, HiddenField, SelectField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from datemagic import sec_to_date, date_to_sec, init_dates, date_to_str


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite') 
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SECRET_KEY'] = 'thisisasecretkeyoncethisgoeslivenoreallyipromise'
app.config['FLASK_ADMIN_SWATCH'] = 'lumen'

def get_rooms():
    return Rooms.query.all()

def get_users():
    return User.query.all()

app.jinja_env.globals.update(get_rooms=get_rooms)
app.jinja_env.globals.update(get_users=get_users)

login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"

db = SQLAlchemy(app)
bcrypt = Bcrypt()

login_manager.init_app(app)
bcrypt.init_app(app)

class LoginForm(FlaskForm):
    name = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
#    create = BooleanField("Create user?")
    next = HiddenField("Hidden")
    submit = SubmitField("Submit")

class BookForm(FlaskForm):
    name = StringField("Användarnamn", validators=[DataRequired()], render_kw={'readonly': True})
    partner = StringField("Labbpartner")
    comment = StringField("Kommentar")
    next = HiddenField("Hidden")
    submit = SubmitField("Submit")

class DeleteUserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()], render_kw={'readonly': True})
    username_confirm = StringField("Confirm username for deletion", validators=[
        DataRequired(),
        EqualTo("username", message="Username must match") 
    ])
    delete_bool = BooleanField("Yes I want to delete this user")

class CreateUserForm(FlaskForm):
    username = StringField("Username", validators=[
        DataRequired(),
        Length(min=3, max=64)
        ])
    password = PasswordField("Password", validators=[
        DataRequired(), 
        EqualTo('password_confirm', message='Passwords must match'),
        Length(min=8, message="Password has to be least 8 characters")
        ])
    password_confirm = PasswordField("Confirm password", validators=[
        Length(min=8)
        ])
    role = SelectField("Role", choices=[
        ('1', 'Admin'), 
        ('3', 'Teacher'), 
        ('2', 'Student')], 
        coerce=int)
    next = HiddenField("Hidden")
    type = HiddenField("POST-type")
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

    def __init__(self, room, time, pod, duration, name1, name2, comment, flag):
        self.room = room
        self.time = time
        self.pod = pod
        self.duration = duration
        self.name1 = name1
        self.name2 = name2
        self.comment = comment
        self.flag = flag

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

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role.name == "Admin"

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

    @expose('/')
    def index(self):
        if not current_user.is_authenticated and current_user.role.name == "Admin":
            return redirect(url_for('login'))
        return super(MyAdminIndexView, self).index()

admin = Admin(app, name='Podbokning', template_mode='bootstrap4', index_view=MyAdminIndexView())
admin.add_view(RoomsModelView(Rooms, db.session))
admin.add_view(UserModelView(User, db.session))
admin.add_link(menu.MenuLink(name='Logout', category='', url='/logout?next=/'))

def get_bookings(roomdata, epoch):
    booking_data = {}
    hours = [8,10,13,15,17,19,21]
    for hour in hours:
        booking_data[hour] = {}
        for pod in range(1, roomdata.pods+1):
            data = Bookings.query.filter(Bookings.time==(epoch+(hour*3600))).filter(Bookings.room==roomdata.id).filter(Bookings.pod==pod).all()
            if len(data) >= 1:
                showstring = f'{data[0].name1}</a><br>'
                if len(data[0].name2) > 0:
                    showstring += f'{data[0].name2}</a><br>'
                if len(data[0].comment) > 0:
                    showstring += f'{data[0].comment}'                    
                if data[0].flag != 'AVAILABLE':
                    if current_user.is_authenticated:
                        booking_data[hour][pod] = f'<td style="border-radius:10px" class="align-middle table-danger"><a href="/delete/{roomdata.name}/{sec_to_date(epoch+(hour*3600))}/{hour}/{chr(pod+64)}"> \
                            {showstring}</td>'
                    else:
                        booking_data[hour][pod] = f'<td style="border-radius:10px" class="align-middle table-danger">Reserved<br>&nbsp;</td>'
                else:
                    booking_data[hour][pod] = f'<td style="border-radius:10px" class="align-middle"><a href="/delete/{roomdata.name}/{sec_to_date(epoch+(hour*3600))}/{hour}/{chr(pod+64)}"> \
                            {showstring}</td>'
            else:
                booking_data[hour][pod] = f'<td style="border-radius:10px" class="align-middle table-success"><a href="/book/{roomdata.name}/{sec_to_date(epoch+(hour*3600))}/{hour}/{chr(pod+64)}">Get POD!</a><br>&nbsp;</td>'
    return booking_data

def set_booking(roomdata, epoch, pod):
    if current_user.role.name == "Admin" or current_user.role.name == "Teacher":
        roomflag = 'UNAVAILABLE'
        booking = Bookings(
            room=roomdata.id,
            time=epoch,
            pod=ord(pod.upper())-64,
            duration=2,
            name1=current_user.username,
            name2='',
            comment='',
            flag=roomflag
        )
    else:
        roomflag = 'AVAILABLE'

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/show/<room>')
@app.route('/show/<room>/<caldate>')
def show(room, caldate='Null'):
    if room.upper() not in [x.name for x in Rooms.query.all()]:
        flash("No such resource, check room name!", "danger")
        abort(404, description="Resource not found")
    if caldate == 'Null':
        return redirect(f'/show/{room.upper()}/{date_to_str()}')
    else:
        today_d = caldate
    dates = init_dates(today_d)
    show = {}
    roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
    show['room'] = {'name': roomdata.name.upper(), 'pods': [chr(x+65) for x in range(roomdata.pods)]}
    show['dates'] = dates
    show['clocks'] = [8,10,13,15,17,19,21]
    show['query'] = get_bookings(roomdata, dates['today']['string'])
    return render_template('show.html', show=show)

@app.route('/book')
@app.route('/book/<room>')
@app.route('/book/<room>/<caldate>')
@app.route('/book/<room>/<caldate>/<hr>/<pod>', methods=('GET', 'POST'))
@login_required
def book(room='Null', caldate='Null', hr='Null', pod='Null'):
    if request.method == 'POST':
        namn1 = request.form['booker']
        namn2 = request.form['partner']
        comment = request.form['comment']
        roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
        book_time = date_to_sec(caldate) + (3600 * int(hr))
        roomflag = request.form['status']

        # TODO: Add concurrency check to make sure the pod slot is still available before booking
        bi = Bookings(
                room=roomdata.id,
                time=book_time,
                pod=ord(pod.upper())-64,
                duration=2,
                name1=namn1,
                name2=namn2,
                comment=comment,
                flag=roomflag
                )
        db.session.add(bi)
        db.session.commit()
        return redirect(f"/show/{roomdata.name.upper()}/{caldate}", code=302)
    else:
        if 'Null' in locals().values():
            return redirect(f"/show/B112/{date_to_str()}", code=302)
        else:
            roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
            # if this is a valid book url...
            if int(hr) in [8,10,13,15,17,19,21]:
                roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
                book_time = date_to_sec(caldate) + (3600 * int(hr))
                # result = get_bookings(roomdata, book_time, pod)
                return render_template('book.html', data=locals())
            else:
                return redirect(f"/show/{roomdata.name.upper()}", code=302)

@app.route('/delete/<room>/<caldate>/<hr>/<pod>')
def delete(room, caldate, hr, pod):
    epoch = date_to_sec(caldate)
    roomdata = Rooms.query.filter(Rooms.name==room.upper()).all()[0]
    Bookings.query.filter(Bookings.time==(epoch+(int(hr)*3600))).filter(Bookings.room==roomdata.id).filter(Bookings.pod==ord(pod)-64).delete()
    db.session.commit()
    return redirect(f'/show/{roomdata.name.upper()}/{caldate}', code=302)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # validating form
    if form.validate_on_submit():
        name = form.name.data
        password = form.password.data
        form.name.data = ''
        form.password.data = ''
        next = form.next.data
        '''if form.create.data == True:
            new_user = User(
                username=name,
                role_id = 1,
                password=password,
                flag='CAN_BOOK',
                last_login=0
            )
            db.session.add(new_user)
            try:
                db.session.commit()
                flash(f'Account successfully created', 'success')
            except Exception as e:
                db.session.rollback()
                if 'UNIQUE constraint failed' in str(e):
                    message = f'Unable to create user: {new_user.username}. A user with that name already exists!'
                    flash(message, 'warning')
                else:
                    flash(e, "danger")
            finally:
                db.session.close()
        else:'''
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

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

'''
@app.route("/admin/")
@app.route("/admin/<view>", methods=['GET', 'POST'])
@login_required
def admin(view='Null'):
    if current_user.role.name == "Admin":
        if view == 'Null':
            return render_template("admin.html", view='base')
        elif view == 'user':
            if request.method == 'POST':
                if request.form['type'] == 'CREATE':
                    cform = CreateUserForm()
                    if cform.validate_on_submit():
                        new_user = User(
                            username=cform.username.data,
                            role_id = cform.role.data,
                            password=bcrypt.generate_password_hash(cform.password.data),
                            flag='CAN_BOOK',
                            last_login=0
                        )
                        try:
                            db.session.add(new_user)
                            db.session.commit()
                            flash(f'Account successfully created', 'success')
                        except Exception as error:
                            flash(error, "danger")
                        return render_template("admin.html", view=view, form=cform)
                elif request.form['type'] == 'MODIFY':
                    pass

            elif request.method == 'GET':
                cform = CreateUserForm()
                return render_template("admin.html", view=view, form=cform)
    else:
        flash("You are not authorized to view this resource.", "danger")
        return redirect(url_for("index"))
'''

@app.route('/')
def index():
    # TODO: Set up a landing page for the booking system. Don't overdo it though.
    return redirect("/show/B112", code=302)

@app.route("/debug")
@login_required
def debug():
    return render_template('debug.html')

if __name__ == "__main__":
    app.run(debug=True)

# TODO: #3 Split application into smaller modules - easy peasy