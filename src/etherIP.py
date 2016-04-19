#!/usr/bin/python
# -*- coding: utf-8 -*-

import shodan
import math
"""find vulnerability in EtherNet/IP"""

SHODAN_API_KEY = raw_input('input your Shodan key')

api = shodan.Shodan(SHODAN_API_KEY)

query = 'port:44818'


out = open('EtherNet.txt', 'w')

out.writelines('This text file contains all device data for EtherNet/IP \n')
out.writelines('The result will be shown in a format as:\n*\neach device\'s attributes => \ndescription\n* \none by one \n')
out.write('\n')

print 'This console shows all device data for EtherNet/IP '
print 'The result will be shown in a format as:\n*\neach device\'s attributes => \ndescription\n* \none by one'

plc = 'Programmable Logic Controller'
cd = 'Communications Adapter'
hmi = 'Human-Machine Interface'

device_dict = {
               u'Programmable Logic Controller' : 0,
               u'Human-Machine Interface' : 0,
               u'Communications Adapter' : 0
               }


try:
    pre = api.count(query)
    total_page = math.ceil(pre['total']/100.0)
    
    print total_page
    
    total_page = int(total_page)
    
    print 'total pages are ' , total_page
    
    out.write('total pages are ' + str(total_page) + '\n')
    
    curr_page = 1
    count = 0
    
    
    while curr_page <= total_page:
#         if curr_page > 1:
#             break
        print 'current page is in page ' , curr_page
        out.write('current page is in page ' + str(curr_page) + '\n')
        
        results = api.search(query, page=curr_page)
        
        for key in results.keys():
            print 'Below is the result for key : ' + key
            out.writelines('Below is the result for key : ' + str(key) + '\n')
            print "+++++++++++++++++++++++++++++++++++"
            out.write("+++++++++++++++++++++++++++++++++++\n")     
            value = results[key]
            if type(value) is list:
                for v in value:              
                    print '----------------------------------'
                    print "device number: " + str(count)
                    out.write('----------------------------------\n')
                    out.write("device number: " + str(count) + '\n')              
                    count += 1
                    for k1 in v :                       
                        print k1 + ' => '
                        if type(k1) is unicode:
                            s = k1.encode('ascii', 'ignore')
                            s = s + ' => \n'
                            out.write(s)
                        else:
                            out.write(str(k1) + ' => \n')
                        if k1 == 'data':
                            s_pos = v[k1].find('Device type: ')
                            e_pos = v[k1].find('\nDevice IP')
                            if s_pos > 0 and e_pos > 0:
                                dev_str = v[k1][s_pos + len('Device type: ') : e_pos]
                                if device_dict.has_key(dev_str):
                                    device_dict[dev_str] += 1
                                else:
                                    device_dict[dev_str] = 1
                            
                        if type(v[k1]) is dict:
                            print '{'
                            out.write('{\n')
                            for k2 in v[k1]:
                                print k2, ' => ', v[k1][k2]
                                if type(k2) is unicode or type(v[k1][k2]) is unicode:
                                    if type(k2) is unicode and type(v[k1][k2]) is unicode:
                                        s = k2.encode('ascii', 'ignore') + ' => ' + v[k1][k2].encode('ascii', 'ignore') + '\n'
                                        out.write(s)
                                    elif type(k2) is unicode:
                                        s = k2.encode('ascii', 'ignore') + ' => ' + str(v[k1][k2]) + '\n'
                                        out.write(s)
                                    elif type(v[k1][k2]) is unicode:
                                        s = str(k2) + ' => ' + v[k1][k2].encode('ascii', 'ignore') + '\n'
                                        out.write(s)
                                else:
                                    out.write(str(k2) + ' => ' + str(v[k1][k2]) + '\n')
                            print '}'
                            out.write('}\n')
                        else:
                            print v[k1]
                            s = ''
                            if type(v[k1]) is unicode:
                                s = v[k1].encode('ascii', 'ignore')
                                s = s + '\n'
                            else:
                                s = str(v[k1]) + '\n'
                            out.write(s)
                        print '*'
                        out.write('*\n')
                    print '----------------------------------'
                    out.write('----------------------------------\n')
            elif type(value) is dict:
                for k in value:
                    print '*'
                    out.write('*\n')
                    print "Key: " + k + " => ", value[k]
                    if type(k) is unicode or type(value[k]) is unicode:
                        s = k.encode('ascii', 'ignore') + ' => ' + value[k].encode('ascii', 'ignore') + '\n'
                        out.write(s)
                    else:
                        out.write('Key: ' + str(k) + ' => ' + str(value[k]) + '\n')
            else:
                print value
                if type(value) is unicode:
                    s = value.encode('ascii', 'ignore') + '\n'
                    out.write(s + '\n')
                else:
                    out.write(str(value) + '\n')
            print "+++++++++++++++++++++++++++++++++++"
            out.write("+++++++++++++++++++++++++++++++++++\n")
        curr_page += 1

    

    
    print 'A list of device type: '
    out.write('A list of device type\n')
    print device_dict
    out.write(str(device_dict))
    
    
    out.close()
except shodan.APIError, e:
    print 'Error: %s' % e
    
    print 'error happen. current result: analyse devices number: ', count
    out.write('analyse devices number: ' + str(count) + '\n')
    
    print 'A list of device type: '
    out.write('A list of device type\n')
    print device_dict
    out.write(str(device_dict))
    
    
    out.close()