import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.message
import dns.query

domain = 'www.netflix.com'
server = '198.41.0.4'
rdatatype = dns.rdatatype.from_text('A')

query = dns.message.make_query(domain, rdatatype)
response = dns.query.udp(query, server)
print(1)
print(response)

server = str(response.additional[0][0])
query = dns.message.make_query(domain, rdatatype)
response = dns.query.udp(query, server)
print(2)
print(response)

server = str(response.additional[0][0])
query = dns.message.make_query(domain, rdatatype)
response = dns.query.udp(query, server)
print(3)
print(response)














