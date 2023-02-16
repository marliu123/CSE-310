import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.message
import dns.query

domain = 'www.cnn.com'
server = '198.41.0.4'
rdatatype = dns.rdatatype.from_text('A')



def do_query(domain_name, server):
    query = dns.message.make_query(domain, rdatatype)
    response = dns.query.udp(query, server) 
    if len(response.answer) == 0:
        server = str(response.additional[0][0])
        return do_query(domain_name, server)
    return(response)

result = do_query(domain, server)
print(result)














