#!/usr/bin/python
# -*- coding: utf-8 -*-

import shodan
import math
"""find vulnerability in BacNet"""

SHODAN_API_KEY = raw_input('input your Shodan key')

api = shodan.Shodan(SHODAN_API_KEY)

query = 'port:47808'


out = open('bacnet.txt', 'w')

out.writelines('This text file contains all device data for BACnet \n')
out.writelines('The result will be shown in a format as:\n*\neach device\'s attributes => \ndescription\n* \none by one \n')
out.write('\n')

print 'This console shows all device data for BACnet '
print 'The result will be shown in a format as:\n*\neach device\'s attributes => \ndescription\n* \none by one'

bbmd = 'BACnet Broadcast Management Device'
bbmd_num = 0
udp_num = 0
other = []


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
                            if v[k1].find(bbmd) > 0 or v[k1].find('BBMD') > 0:
                                bbmd_num += 1
                        if k1 == 'transport' :
                            if v[k1] == 'udp':
                                udp_num += 1
                            else:
                                other.append(v[k1])
                            
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

    
    print 'analyse devices number: ', count
    out.write('analyse devices number: ' + str(count) + '\n')
    
    print 'broadcast management device found: ', bbmd_num
    out.write('broadcast management device found: ' + str(bbmd_num) + '\n')
    print 'transportation layer is udp: ', udp_num
    out.write('transportation layer is udp: ' + str(udp_num))
    print 'other protocol:', other
    
    out.close()
except shodan.APIError, e:
    print 'Error: %s' % e
    
    print 'error happen. current result: analyse devices number: ', count
    out.write('analyse devices number: ' + str(count) + '\n')
    
    print 'broadcast management device found: ', bbmd_num
    out.write('broadcast management device found: ' + str(bbmd_num) + '\n')
    print 'transportation layer is udp: ', udp_num
    out.write('transportation layer is udp: ' + str(udp_num))
    print 'other protocol:', other
    
    out.close()