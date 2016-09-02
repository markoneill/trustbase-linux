#ifndef PYTHON_PLUGINS_H_
#define PYTHON_PLUGINS_H_

#include <stddef.h>
#include "../trusthub_plugin.h"


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
//int initialize(int plugin_count, char *plugin_directory, int (*callback_pointer)(int,int,int), const char *lib_file);
int initialize(int count, char *plugin_dir, int (*callback)(int,int,int), const char *lib_file, int (*log_func)(thlog_level_t level, const char* format, ... ));

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
*	
*	is_async: 0 if not async, 1 if is async
*/
int load_plugin(int id, char *file_name, int is_async);


/*
*	id: a non-negative integer that is used as an index in an array
*		containing pointers to plugin functions; it is the identifier
*		for which plugin to query as assigned by the load_plugin() function
*
*	host: the domain name
*	cert_chain: the cert chain to test for validity
*	length: the length of cert_chain
*/
int query_plugin(int id, query_data_t* data);

/*
*	id: a non-negative integer that is used as an index in an array
*		containing pointers to plugin functions; it is the identifier
*		for which plugin to query as assigned by the load_plugin() function
*
*	host: the domain name
*	cert_chain: the cert chain to test for validity
*	length: the length of cert_chain
*	query_id: the async query
*/
int query_plugin_async(int id, query_data_t* data);

/**	The callback function for asynchronous python plugins
 *
 *	result: the plugin's opinion on the certificate
 *		PLUGIN_RESPONSE_ERROR  -1
 *		PLUGIN_RESPONSE_INVALID 0
 *		PLUGIN_RESPONSE_VALID   1
 *		PLUGIN_RESPONSE_ABSTAIN 2
 *	plugin_id: the plugin's assigned id
 *	query_id: the id of the async query
 */
int callback(int result, int plugin_id, int query_id);

/**	
 *	id: a non-negative integer that is used as an index in an array
 *		containing pointers to plugin functions; it is the identifier
 *		for which plugin to query as assigned by the load_plugin() function
 *
 */ 
int finalize_plugin(int id);

#endif
