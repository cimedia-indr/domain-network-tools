from django.shortcuts import render, redirect
from django.http import HttpResponse
import os
import dns
from dns import resolver
import requests
# import dns.resolver


def index(request):
    return render(request,'index.html')

def get_client_location(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')

    response = requests.get(f'https://ipinfo.io/{ip}')
    data = response.json()

    return render(request, 'index.html', {'location_data': data})

def ping_test(request):
    
    context = {}
    if request.GET.get('pinghost', False) == '':
        context['ping_output'] = 'Please enter a domain name Or IP Address!'
    
    elif 'pinghost' in request.GET:
        ping_output = os.popen('ping ' + request.GET['pinghost']).read()
        context['ping_output'] = ping_output
    
    return render(request,'index.html',context)

# Function for DNS lookup 

def dns_lookup(request):
    if request.method == 'GET':
        domain_name = request.GET.get('domain_name')

        if not domain_name:
            # Handle the case where no domain name is provided
            return render(request, 'index.html', {'error_message': 'Please enter a domain name'})

        

        try:
            answers = resolver.query(domain_name)
            ip_addresses = [answer.address for answer in answers]

            # Render a template with the results
            return render(request, 'index.html', {'domain_name': domain_name, 'ip_addresses': ip_addresses})

        except resolver.NXDOMAIN:
            # Handle the case where the domain doesn't exist
            return render(request, 'index.html', {'error_message': 'Domain not found'})

        except resolver.Timeout:
            # Handle the case where the query timed out
            return render(request, 'index.html', {'error_message': 'DNS query timed out'})

    # Render the form if it's a GET request or there was an error
    return render(request, 'index.html')
    # return redirect('index.html')

# Function for MX record  Check 

def mx_check_view(request):
    if request.method == 'GET':
        domain_name = request.GET.get('mxdomain_name')

        if not domain_name:
            # Handle the case where no domain name is provided
            return render(request, 'index.html', {'error_message': 'Please enter a domain name'})
        

        try:
            mx_records = resolver.query(domain_name, 'MX')
            print(mx_records)
            return render(request, 'index.html', {'mxdomain_name': domain_name, 'mx_records': mx_records})
                    
        except resolver.NXDOMAIN:
            return render(request, 'index.html', {'error_message': 'Domain not found'})
        except resolver.Timeout:
            return render(request, 'index.html', {'error_message': 'DNS query timed out'})
        
    
    return render(request, 'index.html')

# IPv4 reverse check function
def reverse_ip(ip_address):
    """Reverses an IPv4 address.

    Args:
        ip_address: The IPv4 address to reverse.

    Returns:
        The reversed IPv4 address.
    """

    octets = ip_address.split('.')
    octets.reverse()
    reversed_ip = '.'.join(octets)
    return reversed_ip

def reverse_ip_lookup(request):
    if request.method == 'GET':
        ip_address = request.GET.get('ip_address')
        # Reverse the IP address
        reversed_ip = reverse_ip(ip_address)


        # print(ip_address)

        try:
            # reversed_dns = str(resolver.query(ip_address + ".in-addr.arpa", "PTR")[0])
            reversed_dns = resolver.query(reversed_ip + ".in-addr.arpa", "PTR")[0]
            
            return render(request, 'index.html', {'ip_address': ip_address, 'reversed_dns': reversed_dns})
        except resolver.NXDOMAIN:
            return render(request, 'index.html', {'ip_address': ip_address, 'error_message': 'Reverse DNS lookup failed: Domain not found'})
        except resolver.Timeout:
            return render(request, 'index.html', {'ip_address': ip_address, 'error_message': 'Reverse DNS lookup failed: Timeout'})
        except Exception as e:
            return render(request, 'index.html', {'ip_address': ip_address, 'error_message': f'Reverse DNS lookup failed: {str(e)}'})

    return render(request, 'index.html')

# SPF check function 

def spf_check(request):
    if request.method == 'GET':
        spf_domain_name = request.GET.get('spf_domain')

        if not spf_domain_name:
            return render(request, 'index.html', {'error_message': 'Please provide a domain name.'})

        try:
            txt_records = resolver.query(spf_domain_name, 'TXT')

            for txt_record in txt_records:
                if 'v=spf1' in txt_record.to_text().lower():
                    spf_record = txt_record.to_text()
                    # print(spf_record)
                    return render(request, 'index.html', {'spf_domain_name': spf_domain_name, 'spf_record': spf_record})
                    break
            else:
                spf_record = 'SPF record not found'

                # return render(request, 'index.html', {'spf_domain_name': spf_domain_name, 'spf_record': spf_record})
                # return render(request, 'index.html', {spf_record})

        except resolver.NXDOMAIN:
            return render(request, 'index.html', {'spf_domain_name': spf_domain_name, 'error_message': 'Domain not found'})
        except resolver.Timeout:
            return render(request, 'index.html', {'spf_domain_name': spf_domain_name, 'error_message': 'DNS query timed out'})
        except Exception as e:
            return render(request, 'index.html', {'spf_domain_name': spf_domain_name, 'error_message': f'An error occurred: {str(e)}'})

    return render(request, 'index.html')


    # Function for DKIM check

 
def dkim_check(request):
    if request.method == 'GET':
        dkim_domain_name = request.GET.get('dkim_domain')
        selector = request.GET.get('dkim_selector')

        if not dkim_domain_name or not selector:
            return render(request, 'index.html', {'error_message': 'Please provide both domain name and selector.'})

        try:
            dkim_key_query = f"{selector}._domainkey.{dkim_domain_name}"
            dkim_key_records = resolver.query(dkim_key_query, 'TXT')

            for key_record in dkim_key_records:
                dkim_public_key = key_record.to_text()
                # print(dkim_public_key)

                # Now you can validate the DKIM signature using the public key
                # ... (Implement DKIM signature validation logic here)

                return render(request, 'index.html', {'dkim_domain_name': dkim_domain_name, 'selector': selector, 'dkim_public_key': dkim_public_key})

        except resolver.NXDOMAIN:
            return render(request, 'index.html', {'dkim_domain_name': dkim_domain_name, 'selector': selector, 'error_message': 'DKIM record not found'})
        except resolver.Timeout:
            return render(request, 'index.html', {'dkim_domain_name': dkim_domain_name, 'selector': selector, 'error_message': 'DNS query timed out'})
        except Exception as e:
            return render(request, 'index.html', {'dkim_domain_name': dkim_domain_name, 'selector': selector, 'error_message': f'An error occurred: {str(e)}'})

    return render(request, 'index.html')