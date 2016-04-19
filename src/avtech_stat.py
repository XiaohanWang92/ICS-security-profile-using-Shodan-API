import shodan
"""generate profile for avtech camera"""

SHODAN_API_KEY = raw_input('input your Shodan key')

stat = shodan.Shodan(SHODAN_API_KEY)

banners = [('country', 10), ('org', 10), ('os', 10 ), ('port', 10), ('product', 10)]

banner_descr = {
    'country' : 'The country code that device is located \n' ,               
    'org' : 'organization (company) that uses the device \n',
    'os' : 'operation system that device is using (If os can be detected)\n',
    'port' : 'port number that device is used \n',
    'product' : 'The major product/device (camera) \n'
    }

query = 'linux upnp avtech'

out = open('avtech_vulnerability_stat.txt', 'w')

out.writelines('This text file contains statistical result for searching Avtech exposed camera \n')
out.writelines('The result will be shown as attributes : amount format \n')
out.write('\n')

print 'This console contains statistical result for searching Avtech exposed camera'
print 'The result will be shown as attributes : amount format'

try:
    results = stat.count(query, facets=banners)
    
    print 'Total Result is : %s \n' % results['total']
    
    out.writelines('Total Result is : ' + str(results['total']) + '\n')
    
    for f in results['facets']:
        
        print banner_descr[f]
        
        out.writelines(banner_descr[f] + '\n')
        
        for term in results['facets'][f]:
            
            print '%s: %s' % (term['value'], term['count'])
            
            s = str(term['value']) + ' : ' + str(term['count']) + '\n'
            out.write(s)
            
        print ''
        out.writelines(' \n')
    out.close()
    
except shodan.APIError, e:
        print 'Error: %s' % e
        out.close()