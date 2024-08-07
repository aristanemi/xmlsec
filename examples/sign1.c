/**
 * XML Security Library example: Signing a template file.
 *
 * Signs a template file using a key from PEM file
 *
 * Usage:
 *      ./sign1 <xml-tmpl> <pem-key>
 *
 * Example:
 *      ./sign1 sign1-tmpl.xml rsakey.pem > sign1-res.xml
 *
 * The result signature could be validated using verify1 example:
 *      ./verify1 sign1-res.xml rsapub.pem
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2024 Aleksey Sanin <aleksey@aleksey.com>. All Rights Reserved.
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>

// using xpath to get all signature nodes
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>



/**
 * register_namespaces:
 * @xpathCtx:		the pointer to an XPath context.
 * @nsList:		the list of known namespaces in 
 *			"<prefix1>=<href1> <prefix2>=href2> ..." format.
 *
 * Registers namespaces from @nsList in @xpathCtx.
 *
 * Returns 0 on success and a negative value otherwise.
 */
int 
register_namespaces(xmlXPathContextPtr xpathCtx, const xmlChar* nsList) {
    xmlChar* nsListDup;
    xmlChar* prefix;
    xmlChar* href;
    xmlChar* next;
    
    assert(xpathCtx);
    assert(nsList);

    nsListDup = xmlStrdup(nsList);
    if(nsListDup == NULL) {
	fprintf(stderr, "Error: unable to strdup namespaces list\n");
	return(-1);	
    }
    
    next = nsListDup; 
    while(next != NULL) {
	/* skip spaces */
	while((*next) == ' ') next++;
	if((*next) == '\0') break;

	/* find prefix */
	prefix = next;
	next = (xmlChar*)xmlStrchr(next, '=');
	if(next == NULL) {
	    fprintf(stderr,"Error: invalid namespaces list format\n");
	    xmlFree(nsListDup);
	    return(-1);	
	}
	*(next++) = '\0';	
	
	/* find href */
	href = next;
	next = (xmlChar*)xmlStrchr(next, ' ');
	if(next != NULL) {
	    *(next++) = '\0';	
	}

	/* do register namespace */
	if(xmlXPathRegisterNs(xpathCtx, prefix, href) != 0) {
	    fprintf(stderr,"Error: unable to register NS with prefix=\"%s\" and href=\"%s\"\n", prefix, href);
	    xmlFree(nsListDup);
	    return(-1);	
	}
    }
    
    xmlFree(nsListDup);
    return(0);
}

/**
 * print_xpath_nodes:
 * @nodes:		the nodes set.
 * @output:		the output file handle.
 *
 * Prints the @nodes content to @output.
 */
void
print_xpath_nodes(xmlNodeSetPtr nodes, FILE* output) {
    xmlNodePtr cur;
    int size;
    int i;
    
    assert(output);
    size = (nodes) ? nodes->nodeNr : 0;
    
    fprintf(output, "Result (%d nodes):\n", size);
    for(i = 0; i < size; ++i) {
	assert(nodes->nodeTab[i]);
	
	if(nodes->nodeTab[i]->type == XML_NAMESPACE_DECL) {
	    xmlNsPtr ns;
	    
	    ns = (xmlNsPtr)nodes->nodeTab[i];
	    cur = (xmlNodePtr)ns->next;
	    if(cur->ns) { 
	        fprintf(output, "= namespace \"%s\"=\"%s\" for node %s:%s\n", 
		    ns->prefix, ns->href, cur->ns->href, cur->name);
	    } else {
	        fprintf(output, "= namespace \"%s\"=\"%s\" for node %s\n", 
		    ns->prefix, ns->href, cur->name);
	    }
	} else if(nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
	    cur = nodes->nodeTab[i];   	    
	    if(cur->ns) { 
    	        fprintf(output, "= element node \"%s:%s\"\n", 
		    cur->ns->href, cur->name);
	    } else {
    	        fprintf(output, "= element node \"%s\"\n", 
		    cur->name);
	    }
	} else {
	    cur = nodes->nodeTab[i];    
	    fprintf(output, "= node \"%s\": type %d\n", cur->name, cur->type);
	}
    }
}


int sign_file(const char* tmpl_file, const char* key_file);

int
main(int argc, char **argv) {
#ifndef XMLSEC_NO_XSLT
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */

    assert(argv);

    if(argc != 3) {
        fprintf(stderr, "Error: wrong number of arguments.\n");
        fprintf(stderr, "Usage: %s <tmpl-file> <key-file>\n", argv[0]);
        return(1);
    }

    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1;
#endif /* XMLSEC_NO_XSLT */

    /* Init libxslt */
#ifndef XMLSEC_NO_XSLT
    /* disable everything */
    xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
        fprintf(stderr, "Error: xmlsec initialization failed.\n");
        return(-1);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
        return(-1);
    }

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(NULL) < 0) {
        fprintf(stderr, "Error: unable to load default xmlsec-crypto library. Make sure\n"
                        "that you have it installed and check shared libraries path\n"
                        "(LD_LIBRARY_PATH and/or LTDL_LIBRARY_PATH) environment variables.\n");
        return(-1);
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
        fprintf(stderr, "Error: crypto initialization failed.\n");
        return(-1);
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        return(-1);
    }

    if(sign_file(argv[1], argv[2]) < 0) {
        return(-1);
    }

    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();

    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();

    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();

    return(0);
}
int RegisterID(xmlNodePtr node, const xmlChar* idName)
{
    xmlAttrPtr attr;
    // xmlAttrPtr tmp;
    xmlChar* name;
       
    assert(node);
    assert(node->doc);
    assert(idName);

    /* find pointer to id attribute */
    attr = xmlHasProp(node, idName);
    if((attr == NULL) || (attr->children == NULL)) {
        fprintf(stderr, "Error: failed to get \"%s\" attribute\n", idName);
        return(-1);
    }
   
    /* get the attribute (id) value */
    name = xmlNodeListGetString(node->doc, attr->children, 1);
    if(name == NULL) {
        fprintf(stderr, "Error: failed to get \"%s\" attribute value\n", idName);
        return(-1);   
    }
   
    /* check that we don't have that id already registered */
    // tmp = xmlGetID(node->doc, name);
    // if(tmp == NULL) {
    //     fprintf(stderr, "Error: id \"%s\" not found\n", name);
    //     xmlFree(name);
    //     return(-1);
    // }
   
    /* finally register id */
    xmlAddID(NULL, node->doc, name, attr);

    /* and do not forget to cleanup */
    xmlFree(name);

    return(0);
}

int do_sign_node(xmlNodePtr node, const char * key_file)
{
    int ret = -1;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* load private key, assuming that there is not password */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoadEx(key_file, xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPkcs8Pem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", key_file);
        goto done;
    }
    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(dsigCtx->signKey, BAD_CAST key_file) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
        goto done;
    }
        /* sign the template */
        if (xmlSecDSigCtxSign(dsigCtx, node) < 0)
        {
            fprintf(stderr, "Error: signature failed\n");
            goto done;
        }

    ret = 0;

     xmlSecDSigCtxDebugDump(dsigCtx, stdout);
done:
    /* cleanup */
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }
    return ret;
}

/**
 * sign_file:
 * @tmpl_file:          the signature template file name.
 * @key_file:           the PEM private key file name.
 *
 * Signs the #tmpl_file using private key from #key_file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
sign_file(const char* tmpl_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    int res = -1;

    assert(tmpl_file);
    assert(key_file);

    /* load template */
    doc = xmlReadFile(tmpl_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", tmpl_file);
        goto done;
    }

    const xmlChar xmlSecNodeCertificates[] = "certificates";
    const xmlChar xmlSecNodeCertificatesNS[] = "http://vde.com/fnn/stb/certificates/1.4.0";
    xmlNodePtr certsNode = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeCertificates, xmlSecNodeCertificatesNS);
    if (certsNode == NULL) {
        fprintf(stderr, "Error: unable to find node \"%s\"\n", xmlSecNodeCertificates);
        goto done;
    }
    if (RegisterID(certsNode, BAD_CAST "id") < 0) {
        fprintf(stderr, "Error: unable to register id for certsNode\n");
        goto done;
    }
    xmlNodePtr certNode = xmlSecFindNode(xmlDocGetRootElement(doc), BAD_CAST "certificate", xmlSecNodeCertificatesNS);
    if (certNode == NULL) {
        fprintf(stderr, "Error: unable to find node \"%s\"\n", xmlSecNodeCertificates);
        goto done;
    }
    if (RegisterID(certNode, BAD_CAST "id") < 0) {
        fprintf(stderr, "Error: unable to register id for certNode\n");
        goto done;
    }

    // xpath evaluation
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        fprintf(stderr,"Error: unable to create new XPath context\n");
        goto done;
    }
    
    /* Register namespaces from list (if any) */
    const xmlChar* nsList = BAD_CAST "sig=http://www.w3.org/2000/09/xmldsig#";
    if((nsList != NULL) && (register_namespaces(xpathCtx, nsList) < 0)) {
        fprintf(stderr,"Error: failed to register namespaces list \"%s\"\n", nsList);
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return(-1);
    }

    /* Evaluate xpath expression */
    const xmlChar* xpathExpr = BAD_CAST "//sig:Signature";
    xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
    if(xpathObj == NULL) {
        fprintf(stderr,"Error: unable to evaluate xpath expression \"%s\"\n", xpathExpr);
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return(-1);
    }

    /* Print results */
    print_xpath_nodes(xpathObj->nodesetval, stdout);

    /* signa all nodes */
    xmlNodePtr node = xmlDocGetRootElement(doc);
    // while (true)
    // {
        node = xmlSecFindNode(node, xmlSecNodeSignature, xmlSecDSigNs);
        if (node == NULL)
        {
            fprintf(stderr, "Error: start node not found in \"%s\"\n", tmpl_file);
            goto done;
        }

    xmlNodeSetPtr nodes = xpathObj->nodesetval;
    int size = (nodes) ? nodes->nodeNr : 0;
    for(int i = 0; i < size; ++i) {
        assert(nodes->nodeTab[i]);
        
        xmlNodePtr cur;
        if(nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
            cur = nodes->nodeTab[i];
            if (do_sign_node(cur, key_file) < 0)
            {
                fprintf(stderr, "Error: failed to sign node\n");
                goto done;
            }
        }
    }
    // }

    /* print signed document to stdout */
    xmlDocDump(stdout, doc);

    /* success */
    res = 0;

done:
    /* Cleanup */
    if (xpathObj)
        xmlXPathFreeObject(xpathObj);
    if (xpathCtx)
        xmlXPathFreeContext(xpathCtx); 
    if(doc != NULL) {
        xmlFreeDoc(doc);
    }
    return(res);
}
