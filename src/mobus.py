#!/usr/bin/python
# -*- coding: utf-8 -*-

import shodan
import math
"""find vulnerability in modbus protocol"""

SHODAN_API_KEY = raw_input('input your Shodan key')

api = shodan.Shodan(SHODAN_API_KEY)

query = 'port:502'

def find_all(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1: return
        yield start
        start += len(sub) # use start += 1 to find overlapping matches

out = open('modbus.txt', 'w')

out.writelines('This text file contains all device data for modbus protocol \n')
out.writelines('The result will be shown in a format as:\n*\neach device\'s attributes => \ndescription\n* \none by one \n')
out.write('\n')

print 'This console shows all device data for modbus protocol '
print 'The result will be shown in a format as:\n*\neach device\'s attributes => \ndescription\n* \none by one'

str_err = 'Error'

str_ill = 'Illegal Function'
str_sl_df = 'Slave Device Failure'
str_gat_f_r = 'Gateway Target Device Failed To Respond'
str_gat_p_un = 'Gateway Path Unavailable'

str_u_id = 'Unit ID'

master_vul = 0
slave_vul = 0

c_ill = 0
c_sl_df = 0
c_gat_f_r = 0
c_gat_p_un = 0

master_ok = 0
slave_ok = 0


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
                            num = len(list(find_all(a_str = v[k1], sub = str_err)))
                            if num == 0:
                                master_ok += 1
                                slave_ok += len(list(find_all(a_str = v[k1], sub = str_u_id)))
                            else:
                                """there are problems!"""
                                master_vul += 1
                                slave_vul += len(list(find_all(a_str = v[k1], sub = str_u_id)))
                                c_ill += len(list(find_all(a_str = v[k1], sub = str_ill)))
                                c_sl_df += len(list(find_all(a_str = v[k1], sub = str_sl_df)))
                                c_gat_f_r += len(list(find_all(a_str = v[k1], sub = str_gat_f_r)))
                                c_gat_p_un += len(list(find_all(a_str = v[k1], sub = str_gat_p_un)))
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
    
    print 'ok master device: ', master_ok
    out.write('ok master device: ' + str(master_ok) + '\n')
    
    print 'ok slave device: ', slave_ok
    out.write('ok slave device: ' + str(slave_ok) + '\n')
    
    print 'weak master: ', master_vul
    out.write('weak master: ' + str(master_vul) + '\n')
    
    print 'weak slave: ', master_vul
    out.write('weak slave: ' + str(master_vul) + '\n')
    
    print str_gat_f_r + ': ' , str(c_gat_f_r)
    out.write(str_gat_f_r + ': ' + str(c_gat_f_r) + '\n')
    
    print str_gat_p_un + ': ' , str(c_gat_p_un)
    out.write(str_gat_p_un + ': '  + str(c_gat_p_un) + '\n')
    
    print str_ill + ': ' , c_ill
    out.write(str_ill + ': ' + str(c_ill) + '\n')
    
    print str_sl_df + ': ' , c_sl_df
    out.write(str_sl_df + ': ' + str(c_sl_df))
    
    out.close()
except shodan.APIError, e:
    print 'Error: %s' % e
    
    print 'error happen. current result: analyse devices number: ', count
    out.write('analyse devices number: ' + str(count) + '\n')
    
    print 'ok master device: ', master_ok
    out.write('ok master device: ' + str(master_ok) + '\n')
    
    print 'ok slave device: ', slave_ok
    out.write('ok slave device: ' + str(slave_ok) + '\n')
    
    print 'weak master: ', master_vul
    out.write('weak master: ' + str(master_vul) + '\n')
    
    print 'weak slave: ', master_vul
    out.write('weak slave: ' + str(master_vul) + '\n')
    
    print str_gat_f_r + ': ' , str(c_gat_f_r)
    out.write(str_gat_f_r + ': ' + str(c_gat_f_r) + '\n')
    
    print str_gat_p_un + ': ' , str(c_gat_p_un)
    out.write(str_gat_p_un + ': '  + str(c_gat_p_un) + '\n')
    
    print str_ill + ': ' , c_ill
    out.write(str_ill + ': ' + str(c_ill) + '\n')
    
    print str_sl_df + ': ' , c_sl_df
    out.write(str_sl_df + ': ' + str(c_sl_df))
    
    out.close()