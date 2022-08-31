from re import X
from flask_ldap3_login import LDAP3LoginManager
from requests import head, ConnectionError
from time import sleep
from datemagic import unixtime, date_to_str, ics_date
from jicson import fromWeb

def get_bind_creds():
    with open('bind.crd') as file:
        return file.read().strip().split('|')

def ldap_settings():
    userdata = get_bind_creds()
    config = dict()
    config['LDAP_HOST'] = '193.10.199.104'
    config['LDAP_BASE_DN'] = 'ou=edu,dc=wad,dc=hv,dc=se'
    config['LDAP_USER_DN'] = 'ou=users'
    config['LDAP_USER_SEARCH_SCOPE'] = 'SUBTREE'
    config['LDAP_USER_RDN_ATTR'] = 'cn'
    config['LDAP_USER_LOGIN_ATTR'] = 'userPrincipalName'
    config['LDAP_BIND_USER_DN'] = userdata[0]
    config['LDAP_BIND_USER_PASSWORD'] = userdata[1]
    return config

def scrape_user_info(cname, role):
    config = ldap_settings()
    ldap_manager = LDAP3LoginManager()
    ldap_manager.init_config(config)

    if role == 'Student':
        subd = 'student.'
    else:
        subd = ''
    
    info = ldap_manager.get_user_info_for_username(f'{cname}@{subd}hv.se')
    display_name = info['displayName'].replace('(HV)','').rstrip("123456789 ")
    mail = info['mail']
    profile = get_profile(cname)
    return display_name, mail, profile

def test_ldap_auth(cname, password):
    config = ldap_settings()
    ldap_manager = LDAP3LoginManager()
    ldap_manager.init_config(config)
    response = ldap_manager.authenticate(f'{cname}@student.hv.se', password)
    if 'success' in str(response.status):
        return True
    else:
        return False

def get_profile(cname):
    n = 1
    linkhit = False
    while n > 0:
        try:
            loc = f'https://mittkonto.hv.se/public/bilder/{cname}_portrait_{n}.jpg'
            r = head(loc)
            if r.status_code == 200:
                n += 1
                linkhit = True
            elif r.status_code == 404:
                if linkhit:
                    return f'{cname}_portrait_{n-1}.jpg'
                else:
                    return 'no_image_portrait.jpg'
            else:
                return 'no_image_portrait.jpg'
        except ConnectionError:
            return 'no_image_portrait.jpg'
        sleep(0.02)

def pull_ics_data():
    domain = 'https://schema.hv.se/'
    path = 'setup/jsp/SchemaICAL.ics?startDatum='
    querydate = f'20{date_to_str()}'
    intervall = '&intervallTyp=v&intervallAntal=3'
    extra = '&sokMedAND=false&sprak=SV&'
    resurser = 'resurser=l.B112%2Cl.B114%2Cl.B118%2Cl.B123%2Cl.B125%2C'
    url = f'{domain}{path}{querydate}{intervall}{extra}{resurser}'
    
    result = fromWeb(url, 'Basic')
    timestamp = unixtime()

    if 'VEVENT' in result['VCALENDAR'][0]:   
        x = 0
        for event in result['VCALENDAR'][0]['VEVENT']:
            x += 1
            showsum = ics_date(event['DTSTART'], event['DTEND'])
            event['SHOWDATE'] = showsum
            showsum = event['SUMMARY'].split('Kurs.grp: ')[1].split(' Sign:')[0]

            sumspl = showsum.split()
            if len(sumspl) % 2 == 0:
                sumlen = (len(sumspl)//2)
                p1 = sumspl[0:sumlen]
                p2 = sumspl[sumlen:]
                if p1 == p2:
                    showsum = ' '.join(p1)
            event['SHOWCOURSE'] = showsum
            showsum = event['SUMMARY'].split('Moment: ')[1].split(' Program:')[0]        
            event['SHOWSUMMARY'] = showsum
            event['ACCNUM'] = str(x)
        return result, timestamp
    else:
        result = {}
        return result, timestamp