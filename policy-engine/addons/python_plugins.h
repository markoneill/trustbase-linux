#ifndef PYTHON_PLUGINS_H_
#define PYTHON_PLUGINS_H_

// The function name to be called in the python plugin scripts
const char *plugin_func_name = "query";

/*
*	Begin using this library with the initialize() function.
*	Dynamically load python scripts as plugins with load_plugins().
*	Query a loaded plugin with query().
*	Finally, unload plugins and free memory with finalize().
*/

/**** API ****/

/* 
*	Initializes the Python Interpreter and allocates memory for plugin pointers.
*	Must be called before any other functions.
*
*	plugin_count: the number of plugins that will be loaded into memory. Used
*					for allocating memory
*	plugin_directory: the directory that the python interpreter will use to
*						begin searching for modules
*	returns EXIT_SUCCESS on success and EXIT_FAILURE on failure
*/
int initialize(int plugin_count, char *plugin_directory);

/*
*	Finalizes the Python Interpreter and frees memory from plugin pointers.
*	Do not call any other functions after this function.
*
*	returns EXIT_SUCCESS
*/
int finalize(void);

/*
*	Loads a specified python module into memory as a plugin, which remains in
*	memory until finalize() is called.
*	
*	id: a non-negative integer that will be used as an index in an array
*		containing pointers to plugin functions; also used as an identifier
*		for which plugin to query using the query() function	
*
*	module_name: the name of the Python file to be imported into the Python 
*				interpreter. The search for this module begins in the 
*				plugin_directory parameter of the initialize() function.
*/
int load_plugin(int id, char *file_name);


/*
*	id: a non-negative integer that is used as an index in an array
*		containing pointers to plugin functions; it is the identifier
*		for which plugin to query as assigned by the load_plugin() function
*
*	host: the domain name
*	cert_chain: the cert chain to test for validity
*	length: the length of cert_chain
*/
int query(int id, char *host, const unsigned char *cert_chain, size_t length);


#endif

