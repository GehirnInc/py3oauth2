# -*- coding: utf-8 -*-

import itertools
from urllib.parse import (
    urlparse,
    urlunparse,
)


__all__ = ['normalize_url']

URL_UNRESERVED = {hex(i)[2:].upper(): chr(i) for i in itertools.chain(
    range(65, 91), range(97, 123), range(48, 58), (45, 46, 95, 126)
)}


def normalize_url(url):
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    if scheme not in ('http', 'https'):
        raise ValueError()
    netloc = normalize_netloc(parsed.netloc, 80 if scheme == 'http' else 443)
    path = normalize_path(parsed.path)
    if len(parsed.fragment) > 0:
        raise ValueError()
    query = normalize_query(parsed.query)

    return urlunparse((scheme, netloc, path, '', query, ''))


def normalize_netloc(netloc, default_port):
    if '@' in netloc:
        grant, netloc = netloc.split('@', 1)
    else:
        grant, netloc = '', netloc

    if ':' in grant:
        username, password = grant.split(':', 1)
    else:
        username, password = grant, ''

    if ':' in netloc:
        hostname, port = netloc.split(':', 1)
        if port.isdigit():
            port = int(port)
        elif len(port) < 1:
            port = default_port
        else:
            raise ValueError()
    else:
        hostname, port = netloc, default_port

    result = ''
    if password:
        result += '{0}:{1}'.format(username, password)
    elif username:
        result += username

    if username or password:
        result += '@'

    if hostname and port != default_port:
        result += '{0}:{1}'.format(hostname.lower(), port)
    else:
        result += hostname.lower()

    return result


def normalize_query(query):
    if query == '':
        return query

    result = []
    for param in query.split('&'):
        if '=' not in param:
            continue

        key, value = param.split('=')
        if key and value:
            result.append('{0}={1}'.format(
                normalize_quote(key), normalize_quote(value)
            ))
    else:
        result.sort()

    return '&'.join(result)


def normalize_path(path):
    if path in ['', '//']:
        path = '/'
    assert path.startswith('/')

    path = normalize_quote(path)

    result = ['']
    for directory in path[1:].split('/'):
        if directory == '..' and len(result) > 1:
            result.pop()
        elif directory not in ('', '.', '..'):
            result.append(directory)
    else:
        result.append('')

    return '/'.join(result)


def normalize_quote(quoted):
    quotes = quoted.split('%')
    result = [quotes[0]]
    for quote in quotes[1:]:
        if len(quote) < 2:
            result.append('%' + quote)
        else:
            _quote = quote[:2].upper()
            result.append(
                URL_UNRESERVED.get(_quote, '%' + _quote) + quote[2:]
            )

    return ''.join(result)
