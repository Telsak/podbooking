# podbooking
Written in Python using Flask as a framework to deliver a web application for a more robust and updated interface for booking of network equipment.

A number of tables in a database using SQLITE and Flask/SQLAlchemy use the rough layout as follows:


*getapod_rooms*
id = int, primary key
name = string(64)
pods = int

*getapod_bookings*
id = int, primary key
room = int
time = int
pod = int
duration = int
name1 = string(64)
name2 = string(64)
comment = string(64)
flag = string(64)

*roles*
id = int, primary
name = string(64)
users = relationship -> users table

*users*
id = int, primary
username = string(64), unique
role_id = int, foreignkey -> roles table (roles.id)
password = string(300) hash&salt, unique
flag = string(64) set various user flags
last_login = int, last time user logged in in unixtime

---
There are still plenty of things to do here, this is not even close to finished - but base functionality works right now.
A number of rooms have a number of pods (stations) that can be booked

