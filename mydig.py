import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.message
import dns.query

domain = "www.cnn.com"
nameserver = "8.8.8.8"


#print(dns.name.from_text('www.cnn.com'))
#print(dns.rdataclass.from_text('IN'))
#print(dns.rdatatype.from_text('A'))


query = dns.message.make_query(domain, dns.rdatatype.from_text('A'))
print(query)
response = dns.query.udp(query, nameserver)
for rrset in response.answer:
    for rdata in rrset:
        print(rdata)

#print(response)
#rrset = response.answer[0]
#for rdata in rrset:
#    print(rdata)
