#include <Python.h>
#include "../trustbase_plugin.h"
#include "python_plugins.h"

PyObject **plugin_functions;
PyObject **plugin_final_functions;
static int plugin_count;
static int init_plugin(PyObject* pFunc, int id, int is_async);
static void log_PyErr(void);

// The function name to be called in the python plugin scripts
const char *plugin_query_func_name = "query";
const char *plugin_init_func_name = "initialize";
const char *plugin_final_func_name = "finalize";
//the compiled this file
const char *this_file = "python_plugins.o";

int (*async_callback)(int,int,int);

#include "../tb_logging.h"
int (*plog)(tblog_level_t level, const char* format, ... );

int initialize(int count, char *plugin_dir, int (*callback)(int,int,int), const char *lib_file, int (*log_func)(tblog_level_t level, const char* format, ... )) {
	char python_stmt[128];
	char *argv_path[] = {""};
	Py_Initialize();
	plugin_count = count;

	plog = log_func;
	
	async_callback = callback;
	this_file = lib_file;
	
	// Set the python module search path to plugin_dir
	PySys_SetArgvEx(0, argv_path, 0);
	if (sprintf(python_stmt, "import sys; import signal; signal.signal(signal.SIGINT, signal.SIG_DFL)") < 0) {
		plog(LOG_ERROR, "Failed to set default signal handling");
		return 1;
	}
	if (PyRun_SimpleString(python_stmt) < 0) {
		plog(LOG_ERROR, "Exception raised while running '%s'", python_stmt);
		return 1;
	}
	
	// Allocate plugin fuctions
	plugin_functions = (PyObject**)calloc(plugin_count, sizeof(PyObject*));
	if (plugin_functions == NULL) {
		plog(LOG_ERROR, "Failed to allocate memory for %d plugins", plugin_count);
		return 1;
	}
	plugin_final_functions = (PyObject**)calloc(plugin_count, sizeof(PyObject*));
	if (plugin_final_functions == NULL) {
		plog(LOG_ERROR, "Failed to allovate memory for %d plugins", plugin_count);
		return 1;
	}

	return 0;
}

int finalize(void) {
	int i;
	for(i = 0; i < plugin_count; i++) {
		if (plugin_functions[i] != NULL) {
			Py_DECREF(plugin_functions[i]);
			plugin_functions[i] = NULL;
		}
	}
	
	for(i = 0; i < plugin_count; i++) {
		if (plugin_final_functions[i] != NULL) {
			Py_DECREF(plugin_final_functions[i]);
			plugin_final_functions[i] = NULL;
		}
	}

	Py_Finalize();
	free(plugin_functions);
	free(plugin_final_functions);

	return 0;
}

/** puts a reference to the plugin's query function in pluginfunctions
 * @param id The plugin id, and it's query function's index in pluginfunctions
 * @param file_name The path to the file, must have at least one / and end in .py
 */
int load_plugin(int id, char* file_name, int is_async) {
	PyObject* pName;
	PyObject* pModule;
	PyObject* pFunc;
	char path[128];
	char python_stmt[128];
	char* module_name;
	char* dot_ptr;
	char* slash_ptr;

	// Cut off extension .py
	module_name = path;
	snprintf(path, 128, "%s", file_name);
	dot_ptr = strrchr(path, '.');
	if (dot_ptr != NULL) {
		*dot_ptr = '\0';
	}
	slash_ptr = strrchr(path, '/');
	if (slash_ptr != NULL) {
		*slash_ptr = '\0';
		module_name = slash_ptr + 1;
	}

	if (snprintf(python_stmt, 128, "sys.path.insert(0,'%s')", path) < 0) {
		plog(LOG_ERROR, "Path too long '%s'", path);
		return 1;
	}
	if (PyRun_SimpleString(python_stmt) < 0) {
		plog(LOG_ERROR, "Exception raised while running '%s'", python_stmt);
		return 1;
	}

	if (id < 0) {
		plog(LOG_ERROR, "Invalid id");
		return 1;
	}

	if(module_name == NULL) {
		plog(LOG_ERROR, "Module name cannot be NULL");
		return 1;
	}

	pName = PyString_FromString(module_name);
	if(pName == NULL) {
		if(PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to construct PyString from module name");
		return 1;
	}

	pModule = PyImport_Import(pName);
	Py_DECREF(pName);
	if (pModule == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to import module '%s'", module_name);
		return 1; 
	}
	//call init function
	pFunc = PyObject_GetAttrString(pModule, plugin_init_func_name);
	if (init_plugin(pFunc, id, is_async) != 0) {	
		plog(LOG_ERROR, "Init_plugin failed");
		return 1;
	}
	//store query function
	pFunc = PyObject_GetAttrString(pModule, plugin_query_func_name);
	if (pFunc && PyCallable_Check(pFunc)) {
		plugin_functions[id] = pFunc;
	}
	else {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to get function '%s'", plugin_query_func_name);
		return 1;
	}
	//store finalize function	
	pFunc = PyObject_GetAttrString(pModule, plugin_final_func_name);
	if (pFunc && PyCallable_Check(pFunc)) {
		plugin_final_functions[id] = pFunc;
	}
	else {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to get function '%s'", plugin_final_func_name);
		return 1;
	}
	Py_DECREF(pModule);

	return 0;
}

static int init_plugin(PyObject* pFunc, int id, int is_async) {
	PyObject* pArgs;
	PyObject* pValue;
	int (*cb_func_ptr)(int,int,int);
	int set_arg;
	int result;
	
	
	if (is_async == 1) {
		pArgs = PyTuple_New(3);	
		if (pArgs == NULL) {
			if (PyErr_Occurred()) {
				log_PyErr();
			}
			plog(LOG_ERROR, "Failed to create new python tuple");
			return 1;
		}
		//set id
		pValue = PyInt_FromLong((long) id);
		if(pValue == NULL) {
			if (PyErr_Occurred()) {
				log_PyErr();
			}
			plog(LOG_ERROR, "Failed to parse id argument");
			Py_DECREF(pArgs);
			return 1;
		}
		set_arg = PyTuple_SetItem(pArgs, 0, pValue);
		if (set_arg != 0) {
			if (PyErr_Occurred()) {
				log_PyErr();
			}
			plog(LOG_ERROR, "Failed to set id argument in tuple");
			Py_DECREF(pArgs);
			return 1;
		}
		
		//set lib_file
		pValue = PyString_FromString(this_file);
		if(pValue == NULL) {
			if (PyErr_Occurred()) {
				log_PyErr();
			}
			plog(LOG_ERROR, "Failed to parse file argument");
			Py_DECREF(pArgs);
			return -1;
		}
		set_arg = PyTuple_SetItem(pArgs, 1, pValue);
		if (set_arg != 0) {
			if (PyErr_Occurred()) {
				log_PyErr();
			}
			plog(LOG_ERROR, "Failed to set file argument in tuple");
			Py_DECREF(pArgs);
			return 1;
		}
		
		//set callback pointer
		cb_func_ptr = &callback;
		pValue = PyInt_FromLong((long) (void *)cb_func_ptr);
		if(pValue == NULL) {
			if (PyErr_Occurred()) {
				log_PyErr();
			}
			plog(LOG_ERROR, "Failed to parse pointer argument");
			Py_DECREF(pArgs);
			return -1;
		}
		set_arg = PyTuple_SetItem(pArgs, 2, pValue);
		if (set_arg != 0) {
			if (PyErr_Occurred()) {
				log_PyErr();
			}
			plog(LOG_ERROR, "Failed to set pointer argument in tuple");
			Py_DECREF(pArgs);
			return 1;
		}
		//call with arguments
		pValue = PyObject_CallObject(pFunc, pArgs);
		Py_DECREF(pArgs);
	} else {
		//call with no arguments
		pValue = PyObject_CallObject(pFunc, NULL);
	}
	
	if (pValue == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to call plugin init function");
		return -1;
	}
	result = (int)PyInt_AsLong(pValue);
	Py_DECREF(pValue);
	if (result == -1) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to parse return value");
		return -1;
	}
	
	return result;
}

/** Sets up the function call to the python plugin
 * @param id The plugin id
 * @param host The hostname associated with the leaf certificate
 * @param cert_chain A character representation of the certificate chain
 * @param length The length of cert_chain
 */
int query_plugin(int id, query_data_t* data) {
	int result;
	int set_arg;
	PyObject* pFunc;
	PyObject* pArgs;
	PyObject* pValue;
	if (id < 0) {
		plog(LOG_ERROR, "Invalid id");
		return -1;
	}

	if (data->hostname == NULL) {
		plog(LOG_ERROR, "host cannot be NULL");
		return -1;
	}

	if (data->raw_chain == NULL) {
		plog(LOG_ERROR, "cert_chain cannot be NULL");
		return -1;
	}

	result = 0;
	pFunc = plugin_functions[id];
	pArgs = PyTuple_New(3);
	if (pArgs == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to create new python tuple");
		return -1;
	}
	// set host argument
	pValue = PyString_FromString(data->hostname);
	if(pValue == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to parse host argument");
		Py_DECREF(pArgs);
		return -1;
	}

	set_arg = PyTuple_SetItem(pArgs, 0, pValue);
	if (set_arg != 0) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to set host argument in tuple");
		Py_DECREF(pArgs);
		return -1;
	}

	// set port argument
	pValue = PyInt_FromLong((long) data->port);
	if (pValue == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to parse port argument");
		Py_DECREF(pArgs);
		return -1;
	}

	set_arg = PyTuple_SetItem(pArgs, 1, pValue);
	if (set_arg != 0) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to set port argument in tuple");
		Py_DECREF(pArgs);
		return -1;
	}

	// set cert chain argument
	pValue = PyByteArray_FromStringAndSize((const char*)data->raw_chain, data->raw_chain_len);
	if (pValue == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to parse cert chain argument");
		Py_DECREF(pArgs);
		return -1;
	}

	set_arg = PyTuple_SetItem(pArgs, 2, pValue);
	if (set_arg != 0) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to set cert chain argument in tuple");
		Py_DECREF(pArgs);
		return -1;
	}

	pValue = PyObject_CallObject(pFunc, pArgs);
	Py_DECREF(pArgs);

	if (pValue == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to call plugin function");
		return -1;
	}
	result = (int)PyInt_AsLong(pValue);
	Py_DECREF(pValue);
	if (result == -1) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to parse return value");
		return -1;
	}

	return result;
}

/** Sets up the function call to the python plugin
 * @param id The plugin id
 * @param host The hostname associated with the leaf certificate
 * @param cert_chain A character representation of the certificate chain
 * @param length The length of cert_chain
 */
int query_plugin_async(int id, query_data_t* data) {
	int result;
	int set_arg;
	PyObject* pFunc;
	PyObject* pArgs;
	PyObject* pValue;
	if (id < 0) {
		plog(LOG_ERROR, "Invalid id");
		return -1;
	}

	if (data->hostname == NULL) {
		plog(LOG_ERROR, "host cannot be NULL");
		return -1;
	}

	if (data->raw_chain == NULL) {
		plog(LOG_ERROR, "cert_chain cannot be NULL");
		return -1;
	}

	result = 0;
	pFunc = plugin_functions[id];
	pArgs = PyTuple_New(4);
	if (pArgs == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to create new python tuple");
		return -1;
	}
	// set host argument
	pValue = PyString_FromString(data->hostname);
	if(pValue == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to parse host argument");
		Py_DECREF(pArgs);
		return -1;
	}

	set_arg = PyTuple_SetItem(pArgs, 0, pValue);
	if (set_arg != 0) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to set host argument in tuple");
		Py_DECREF(pArgs);
		return -1;
	}

	// set port argument
	pValue = PyInt_FromLong((long) data->port);
	if (pValue == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to parse port argument");
		Py_DECREF(pArgs);
		return -1;
	}

	set_arg = PyTuple_SetItem(pArgs, 1, pValue);
	if (set_arg != 0) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to set port argument in tuple");
		Py_DECREF(pArgs);
		return -1;
	}

	// set cert chain argument
	pValue = PyByteArray_FromStringAndSize((const char*)data->raw_chain, data->raw_chain_len);
	if (pValue == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to parse cert_chain argument");
		Py_DECREF(pArgs);
		return -1;
	}

	set_arg = PyTuple_SetItem(pArgs, 2, pValue);
	if (set_arg != 0) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to set cert_chain argument in tuple");
		Py_DECREF(pArgs);
		return -1;
	}
	
	// set query_id
	pValue = PyInt_FromLong((long) data->id);
	if(pValue == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to parse query id argument");
		Py_DECREF(pArgs);
		return 1;
	}
	set_arg = PyTuple_SetItem(pArgs, 3, pValue);
	if (set_arg != 0) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to set query id argument in tuple");
		Py_DECREF(pArgs);
		return 1;
	} 

	pValue = PyObject_CallObject(pFunc, pArgs);
	Py_DECREF(pArgs);

	if (pValue == NULL) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to call plugin function");
		return -1;
	}
	result = (int)PyInt_AsLong(pValue);
	Py_DECREF(pValue);
	if (result == -1) {
		if (PyErr_Occurred()) {
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to parse return value");
		return -1;
	}

	return result;
}

int callback(int result, int plugin_id, int query_id) {
	async_callback(plugin_id, query_id, result);
	return 0;
}

int finalize_plugin(int id) {
	PyObject* pValue;
	PyObject* pFunc;
	// Call finalize functions
	pFunc = plugin_final_functions[id];
	if (pFunc == NULL) {
		plog(LOG_ERROR, "Failed to find a finalize function for plugin %d", id);
		return 0;
	}
	pValue = PyObject_CallObject(pFunc, NULL);
	if (pValue == NULL) {
		if (PyErr_Occurred()) {
			plog(LOG_ERROR, "Python sees an error");
			log_PyErr();
		}
		plog(LOG_ERROR, "Failed to call plugin finalize function");
	}
	return 0;
}

void log_PyErr() {

	PyObject *ptype, *pvalue, *ptraceback;
	PyErr_Fetch(&ptype, &pvalue, &ptraceback);
	//pvalue contains error message
	//ptraceback contains stack snapshot and many other information
	//(see python traceback structure)

	//Get error message
	plog(LOG_ERROR, "%s", PyString_AsString(pvalue));
	return;
}
