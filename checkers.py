from __future__ import print_function
import tldextract
import re
import whitelist

def checkip(ipadd):
    parts=ipadd.split(":")
    if len(parts) >1:
        ipadd=parts[0]

    reIPv4=r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    reIPv6=r'^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$'
    try:
        if bool(re.match(reIPv4, ipadd)):
            return 1
        elif bool(re.match(reIPv6, ipadd)):
            return 1
        else:
            return 0
    except Exception as e:
        print(str(e))
        return -1

def checkdomain(domain):
    """This function checks whether a domain name is valid. The following
    checks are used:
        1. Only allowed characters are a-z, 0-9 and "-"
        2. Each label can atmost be 63 chars long
        3. The domain name must belong to a valid TLD
        """
    try:
        for char in domain:
            if char !="." and char!= "-" and char not in string.lowercase \
                and int(char) not in range(0,10):
                return 0
    except:
        return 0
    parts=tldextract.extract(domain)
    if parts.suffix=='' or len(parts.domain)>63:
        return 0
    for subpart in parts.subdomain.split('.'):
        if len(subpart)>63:
            return 0

    #if the domain is in the hard coded whitelist, reject
    e2LD = ".".join([parts.domain, parts.suffix])
    if e2LD in whitelist.websites:
        return 0
    if domain in whitelist.emailProviders or domain in whitelist.contentProviders:
        return 0
    if e2LD in whitelist.emailProviders or e2LD in whitelist.contentProviders:
        es = Elasticsearch()
        q1 = {'match': {'dm.category':'whitelisted'}}
        q2 = {'range': {'rank': {'gte':'0', 'lt': '100000'}}}
        q3 = {'term': {'ind.domain':domain}}
        q = {'bool': {'must': [q1, q2, q3]}}
        res = es.search(index="threatintel", body={"query":q })
        if res['hits']['total'] >0:
            return 0
        else:
            return 1
    #if domain is in Alexa top 100,000, reject
    es = Elasticsearch()
    q1 = {'match': {'dm.category':'whitelisted'}}
    q2 = {'range': {'rank': {'gte':'0', 'lt': '100000'}}}
    q3 = {'term': {'ind.domain':e2LD}}
    q = {'bool': {'must': [q1, q2, q3]}}
    res = es.search(index="threatintel", body={"query":q })
    if res['hits']['total'] >0:
        return 0
    return 1

def checkurl(url):
    """This function checks if a URL is valid"""

    url=url.replace("http://", "")
    url=url.replace("https://", "")

    if '/' in url:
        parts=url.split('/')
        if len(parts)>=2 and len(parts[0])!=0:
            #print parts[0], checkdomain(parts[0])
            if not checkdomain(parts[0]) and not checkip(parts[0]):
                return 0

    return 1

def checkmd5(md5str):
    reMD5 = r"^([A-F]|[0-9]){32}$"
    try:
        if bool(re.match(reMD5, md5str)):
            return 1
        else:
            return 0

    except:
        return -1


def checkemailadd(emailstr):
    if emailstr in whitelist.emailAddresses:
        return 0
    try:
        user, domain = emailstr.split('@')
    except:
        return 0
    parts=tldextract.extract(domain)
    e2LD = ".".join([parts.domain, parts.suffix])
    if e2LD in whitelist.websites:
        return 0
    return 1
