import shodan
"""show credits info"""

SHODAN_API_KEY = raw_input('input your Shodan key')

api = shodan.Shodan(SHODAN_API_KEY)


try:
    info_dict = api.info()
    for key in info_dict:
        print "key: " + key + ' =>', info_dict[key]
    print "++++++++++++++++++++++++++++++++++++++++"
    protocol_dict = api.protocols()
    for key in protocol_dict:
        print "ptotocal_key: " + key + ' =>', protocol_dict[key]
except shodan.APIError, e:
    print 'Error: %s' % e