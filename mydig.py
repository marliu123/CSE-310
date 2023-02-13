import dns.resolver
import time

def resolve_dns(domain_name):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    query_start_time = time.time()

    try:
        answers = resolver.query(domain_name, 'A')
    except dns.exception.DNSException as e:
        print(f'Error: {e}')
        return

    query_end_time = time.time()
    
    print(f'\nQUESTION SECTION:')
    print(f'{domain_name}. IN A')
    print(f'\nANSWER SECTION:')
    for answer in answers:
        print(f'{domain_name}. IN A {answer}')

    print(f'\nQuery time: {query_end_time - query_start_time} seconds')
    print(f'WHEN: {time.asctime()}')

domain_name = input('Enter the domain name: ')
resolve_dns(domain_name)

