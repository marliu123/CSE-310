import dns.rdataclass
import dns.rdatatype
import dns.message
import dns.query
import datetime

print('Enter domain name: ')
domain = input()
# I used Verisign as the root server
server = '198.41.0.4'
server2 = '8.8.8.8'
# We will only be querying for the A datatype
rdatatype = dns.rdatatype.A

# this function recursively calls itself until an answer is found. We will be using udp to query the dns. 
def dig(domain_name, server):
    try:
        if("www." in domain_name):
            domain_name = domain_name[4:]
        query = dns.message.make_query(domain_name, rdatatype)
        response = dns.query.udp(query, server) 
        print(response)
        server = str(response.additional[0][0])
        
        if len(response.answer) == 0 and len(response.additional) > 0:
            return dig(domain_name, server)
    except:
        print("error")
    return(response)
# this is the time of before the do_query function is called
before = datetime.datetime.now()

response = dig(domain, server)

# this is the time of after the do_query function is called
after = datetime.datetime.now()
# we find the total time it took to resolve the query by subtracting the before and after times 
time = after - before

seconds = time.total_seconds()
currDate = datetime.datetime.now()
formattedCurrDate = currDate.strftime("%A %B %d %Y, %I:%M %p")

# formatting of the output
print("QUESTION SECTION:")
print(response.question[0])
print("ANSWER SECTION:")
for set in response.answer:
    print(set)

print("QUERY TIME: {} seconds".format(seconds))
print('WHEN: {}'.format(formattedCurrDate))



