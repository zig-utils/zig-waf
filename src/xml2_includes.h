/* The libxml2 surface the XPath/XSD/DTD adapter needs (#28).
 *
 * One header for translate-C to start from, rather than several translated
 * separately: the types are shared (xmlDoc, xmlNode, xmlParserCtxt), and separate
 * translations would produce distinct Zig types for them that cannot be passed
 * between the resulting modules.
 */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlschemas.h>
#include <libxml/valid.h>
#include <libxml/xmlerror.h>
