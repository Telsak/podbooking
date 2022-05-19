from time import localtime, mktime
from datetime import datetime , date
from flask import Flask, render_template

app = Flask(__name__)

def sec_to_date(sec):
    '''str_date returns in the format YY-M-D'''
    ds = localtime(sec)
    str_date = f'{str(ds.tm_year)[2:]}-{ds.tm_mon}-{ds.tm_mday}'
    return str_date

def date_to_sec(str_date):
    '''str_date should always be in the format YY-M-D
       returns the current yy-m-d in unix epoch seconds since 1970'''

    ld = [int(n) for n in str_date.split('-')]
    '''adds 2000 to fix year-trimming in date-format to avoid mktime() crash'''
    date = datetime(2000 + ld[0], ld[1], ld[2])
    sec = int(mktime(date.timetuple()))
    return sec

def init_dates(today_d):
    '''Returns a dictionary with todays date +/- returned as string and epoch_s'''
    today_s = date_to_sec(today_d)
    yday_s = today_s-86400
    yday_d = sec_to_date(yday_s)
    morrow_s = today_s+86400
    morrow_d = sec_to_date(morrow_s)
    
    return { 'today': { 'string': today_s, 'date': today_d },
             'yesterday': { 'string': yday_s, 'date': yday_d },
             'tomorrow': { 'string': morrow_s, 'date': morrow_d } 
           }

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/show/<room>')
@app.route('/show/<room>/<caldate>')
def show(room, caldate=None):
    
    if room.upper() not in ['B112', 'B113', 'B114', 'B118', 'B123', 'B125']:
        abort(404, description="Resource not found")
    
    if caldate == None:
        today_d = str(date.today())[2:]
    else:
        today_d = caldate
    
    dates = init_dates(today_d)
    
    show = {}
    show['room'] = room.upper()
    show['dates'] = dates
    show['clocks'] = [8,10,13,15,17,19,21]

    return render_template('show.html', show=show)

if __name__ == "__main__":
    app.run(debug=True)