import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.message
import dns.query
import datetime

print('Enter domain name: ')
domain = input()
server = '198.41.0.4'
rdatatype = dns.rdatatype.A

def do_query(domain_name, server):
    query = dns.message.make_query(domain_name, rdatatype)
    response = dns.query.udp(query, server) 
    if len(response.answer) == 0 and len(response.additional) > 0:
        server = str(response.additional[0][0])
        return do_query(domain_name, server)

    return(response)

before = datetime.datetime.now()
response = do_query(domain, server)
after = datetime.datetime.now()
time = after - before
seconds = time.total_seconds()
currDate = datetime.datetime.now()
formattedCurrDate = currDate.strftime("%A %B %d %Y, %I:%M %p")

print("QUESTION SECTION:")
print(response.question[0])
print("ANSWER SECTION:")
for set in response.answer:
    print(set)

print("QUERY TIME: {} seconds".format(seconds))
print('WHEN: {}'.format(formattedCurrDate))












