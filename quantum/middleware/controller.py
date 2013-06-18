import functools
import collections


def provision_attributes():

    return None


def flatten(d, parent_key=''):
    if d == None:
        return {}
    items = []
    for k, v in d.items():
        new_key = parent_key + '.' + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key).items())
        else:
            items.append((new_key, v))
    return dict(items)


def protected(action='None'):
    """Wraps API calls with attribute based access controls (ABAC)."""
    def decorator(f):
       @functools.wraps(f)
       def wrapper(self, request):
           method = request.headers['Enforce']
           kwargs = provision_attributes()
           authorization = method(request, action, flatten(kwargs))
           if  authorization != None:
               return authorization
           return f(self, request)
       return wrapper
    return decorator
