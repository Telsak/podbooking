from icalendar import Calendar, Event, vCalAddress, vText
from datemagic import unixtime
import pytz

def generate_ical(booking_time, username, room, pod, comment):
    sweden_tz = pytz.timezone('Europe/Stockholm')
    
    start_time = sweden_tz.localize(unixtime(booking_time))
    end_time = sweden_tz.localize(unixtime(booking_time + 7200))

    description = f'Labbpass: {room} Pod {pod}'
    summary = f'Labbpass: {room} Pod {pod}'

    event = Event()
    event.add('uid', f'getapod//{room}//start_time')
    event.add('dtstart', start_time)
    event.add('dtend', end_time)
    event.add('summary', summary)
    event.add('description', description)

    organizer = vCalAddress('MAILTO:noreply@cnap.hv.se')
    organizer.params['name'] = vText('Podbooking')
    event['organizer'] = organizer
    event['location'] = vText(room.upper())

    attendee = vCalAddress(f'MAILTO:{username}@student.hv.se')
    attendee.params['name'] = vText(username)
    attendee.params['role'] = vText('REQ-PARTICIPANT')
    event.add('attendee', attendee, encode=0)
  
    cal = Calendar()
    cal.add_component(event)
    ical_data = cal.to_ical()
    return ical_data