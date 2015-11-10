#!/usr/bin/python
import ctypes

RESPONSE_ERROR = int(-1)
RESPONSE_INVALID = int(0)
RESPONSE_VALID = int(1)
RESPONSE_ABSTAIN = int(2)

INIT_SUCCESS = int(0)
INIT_FAIL = int(1)

class TrustHubPlugin(object):
    async = False
    
    def is_async(self):
        return self.async
    
    #The following functions should be overridden by the implementing class
    def initialize(self):
        pass
    
    def query(self, host, cert_chain):
        pass
    
    def finalize(self):
        pass
    
    #The following wrap the 3 overridden functions 
    ## The initialize called by the load_function method in python_plugins.c
    # It will setup our plugin as synchronous or asynchronous
    def _initialize(self, plugin_id, lib_file, callback):
        if plugin_id is not None and callback is not None and lib_file is not None:
            self.plugin_ID = plugin_id
            self.async = True
            lib = ctypes.cdll.LoadLibrary(lib_file) #load the shared object with the function
            cb_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int) #describe the function type of our callback
            self.cb_func = cb_type(callback) #create the callable function for callback
        else:
            self.plugin_ID = None
            self.async = False
            self.cb_func = None
        
        return self.initialize()
    
    def _query(self, host, cert_chain, query_id):
        return_value = self.query(host, cert_chain)
        if self.async:
            self.cb_func(return_value, self.plugin_ID, query_id)
            return 0
        else:
            return return_value

    def _finalize(self):
        return self.finalize()
    
    

## The following functions should be imported directly
# (for example with from <this file> import *)
# That way they can be run directly from the plugin script
_plugin = TrustHubPlugin()
def setPlugin(pluginobject):
    global _plugin
    _plugin = pluginobject
def initialize(plugin_id=None, lib_file=None, callback=None):
    #print "::Got callback address ", callback
    #print "::Got lib_file ", lib_file
    #print "::Got plugin_id ", plugin_id
    return _plugin._initialize(plugin_id, lib_file, callback)
def query(host, cert_chain, query_id=None):
    return _plugin._query(host, cert_chain, query_id)
def finalize():
    _plugin._finalize()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
