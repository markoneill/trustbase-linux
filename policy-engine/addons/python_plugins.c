#include <Python.h>
#include "python_plugins.h"

PyObject **plugin_functions;
static int plugin_count;

int initialize(int count, char *plugin_dir) {
	char python_path_stmt[128];
	char *argv_path[] = {""};
	Py_Initialize();
	plugin_count = count;

	// Set the python module search path to plugin_dir
	PySys_SetArgvEx(0, argv_path, 0);
	if (sprintf(python_path_stmt, "import sys; sys.path.insert(0,'%s')", plugin_dir) < 0) {
		return 1;
	}
	if (PyRun_SimpleString(python_path_stmt) < 0) {
		fprintf(stderr, "Exception raised while running '%s'\n", python_path_stmt);
		return 1;
	}
	
	plugin_functions = (PyObject**)malloc(plugin_count * sizeof(PyObject*));
	if (plugin_functions == NULL) {
		fprintf(stderr, "Failed to allocate memory for %d plugins\n", plugin_count);
		return 1;
	}

	return 0;
}

int finalize() {
	int i;
	
	for(i = 0; i < plugin_count; i++) {
		Py_DECREF(plugin_functions[i]);
	}

	Py_Finalize();
	free(plugin_functions);

	return 0;
}

int load_plugin(int id, char* module_name) {
	PyObject* pName;
	PyObject* pModule;
	PyObject* pFunc;
	if (id < 0) {
		fprintf(stderr, "Invalid id\n");
		return 1;
	}

	if(module_name == NULL) {
		fprintf(stderr, "Module name cannot be NULL\n");
		return 1;
	}

	pName = PyString_FromString(module_name);
	if(pName == NULL) {
		if(PyErr_Occurred()) {
			PyErr_Print();
		}
		fprintf(stderr, "Failed to construct PyString from module name\n");
		return 1;
	}

	pModule = PyImport_Import(pName);
	Py_DECREF(pName);
	if (pModule == NULL) {
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		fprintf(stderr, "Failed to import module '%s'\n", module_name);
		return 1; 
	}

	pFunc = PyObject_GetAttrString(pModule, plugin_func_name);
	if (pFunc && PyCallable_Check(pFunc)) {
		plugin_functions[id] = pFunc;
	}
	else {
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		fprintf(stderr, "Failed to get function '%s'\n", plugin_func_name);
		return 1;
	}
	Py_DECREF(pModule);

	return 0;
}

int query(int id, char *host, const unsigned char *cert_chain, size_t length) {
	int result;
	int set_arg;
	PyObject* pFunc;
	PyObject* pArgs;
	PyObject* pValue;
	if (id < 0) {
		fprintf(stderr, "Invalid id\n");
		return -1;
	}

	if (host == NULL) {
		fprintf(stderr, "host cannot be NULL\n");
		return -1;
	}

	if (cert_chain == NULL) {
		fprintf(stderr, "cert_chain cannot be NULL\n");
		return -1;
	}

	result = 0;
	pFunc = plugin_functions[id];
	pArgs = PyTuple_New(2);
	if (pArgs == NULL) {
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		fprintf(stderr, "Failed to create new python tuple\n");
		return -1;
	}
	// set host argument
	pValue = PyString_FromString(host);
	if(pValue == NULL) {
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		fprintf(stderr, "Failed to parse host argument\n");
		Py_DECREF(pArgs);
		return -1;
	}

	set_arg = PyTuple_SetItem(pArgs, 0, pValue);
	if (set_arg != 0) {
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		fprintf(stderr, "Failed to set host argument in tuple\n");
		Py_DECREF(pArgs);
		return -1;
	}

	// set cert chain argument
	pValue = PyString_FromStringAndSize((const char*)cert_chain, length);
	if (pValue == NULL) {
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		fprintf(stderr, "Failed to parse cert_chain argument\n");
		Py_DECREF(pArgs);
		return -1;
	}

	set_arg = PyTuple_SetItem(pArgs, 1, pValue);
	if (set_arg != 0) {
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		fprintf(stderr, "Failed to set cert_chain argument in tuple\n");
		Py_DECREF(pArgs);
		return -1;
	}

	pValue = PyObject_CallObject(pFunc, pArgs);
	Py_DECREF(pArgs);

	if (pValue == NULL) {
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		fprintf(stderr, "Failed to call plugin function\n");
		return -1;
	}
	result = (int)PyInt_AsLong(pValue);
	Py_DECREF(pValue);
	if (result == -1) {
		if (PyErr_Occurred()) {
			PyErr_Print();
		}
		fprintf(stderr, "Failed to parse return value\n");
		return -1;
	}

	return result;
}
