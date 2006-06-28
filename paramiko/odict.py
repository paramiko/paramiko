#
# This file and source code are in the public domain.
#

class odict (dict):
    """
    A dictionary with ordered keys.  Based on the cookbook recipe at:
        http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/107747
    """
    
    def __init__(self, *larg, **kwarg):
        self._keys = []
        dict.__init__(self, *larg, **kwarg)
    
    def __delitem__(self, key):
        dict.__delitem__(self, key)
        self._keys.remove(key)
    
    def __setitem__(self, key, item):
        dict.__setitem__(self, key, item)
        if key not in self._keys:
            self._keys.append(key)
    
    def clear(self):
        dict.clear(self)
        self._keys = []
    
    def copy(self):
        od = odict(self)
        return od

    def items(self):
        return zip(self._keys, self.values())
    
    def iteritems(self):
        for k in self._keys:
            yield k, self[k]
    
    def keys(self):
        return self._keys[:]
    
    def popitem(self):
        try:
            key = self._keys[-1]
        except IndexError:
            raise KeyError('dictionary is empty')
        
        val = self[key]
        del self[key]
        
        return (key, val)

    def setdefault(self, key, failobj=None):
        if key not in self._keys:
            self._keys.append(key)
        dict.setdefault(self, key, failobj)
    
    def update(self, d):
        for key, item in d.items():
            self.__setitem__(key, item)
    
    def values(self):
        return map(self.get, self._keys)
