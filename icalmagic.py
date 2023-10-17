from icalendar import Calendar, Event, vCalAddress, vText
from datemagic import unixtime, datetime
import pytz

def generate_ical(booking_time, username, room, pod):
    """
    Generate an iCalendar (ics) file containing a single event with the given booking information.

    :param booking_time: The UNIX timestamp for the start time of the booking.
    :param username: The username of the person making the booking.
    :param room: The room being booked.
    :param pod: The pod being booked within the room.
    :return: A bytes object containing the ics data.
    """
    sweden_tz = pytz.timezone('Europe/Stockholm')
    utc_tz = pytz.UTC
    
    # Convert the start and end times to UTC to avoid issues with daylight saving time or incorrect timezone handling
    start_time = sweden_tz.localize(unixtime(booking_time)).astimezone(utc_tz)
    end_time = sweden_tz.localize(unixtime(booking_time + 7200)).astimezone(utc_tz)

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