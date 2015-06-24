from urlparse import urlparse, urlunparse


def extract_auth_from_url(url):
    parse_result = urlparse(url)
    if parse_result.username:
        auth = (parse_result.username, parse_result.password)
        url = urlunparse(
            (parse_result.scheme,
                ('%s:%s' % (parse_result.hostname, parse_result.port)
                    if parse_result.port
                    else parse_result.hostname),
                parse_result.path,
                parse_result.params,
                parse_result.query,
             parse_result.fragment))
        return auth, url
    return None, url
