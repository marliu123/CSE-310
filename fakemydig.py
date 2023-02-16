import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.message
import dns.resolver

def query_dns(domain, nameserver):
    query = dns.message.make_query(domain, dns.rdatatype.from_text('A'))
    response = dns.query.tcp(query, nameserver)

    if response.answer:
        # If the response has an answer section, return it
        return response.answer

    elif response.authority:
        # If the response has an authority section, follow the chain
        # by querying the first authority server listed
        authority = response.authority[0][0]
        nameserver = str(authority)
        return query_dns(domain, nameserver)

    else:
        # If the response has no answer or authority sections, return None
        return None

domain = "www.cnn.com"
nameserver = "198.41.0.4"

answer = query_dns(domain, nameserver)

if answer:
    for rrset in answer:
        for rdata in rrset:
            print(rdata)
else:
    print("No answer found")
