from arango import ArangoClient

# ArangoDB connection parameters
arango_url = "http://localhost:8529" 
arango_user = "root"
arango_password = "root"
arango_db_name = "cve_v2"

arango_client = ArangoClient(hosts=arango_url)
# Connect to the database
arango_db = arango_client.db(arango_db_name, username=arango_user, password=arango_password)
cve_collection = arango_db.collection("cve_collection")

def get_cve_by_id(id):
    cursor = arango_db.aql.execute("""
    FOR cve IN cve_collection
        FILTER cve._key == @id
        RETURN cve
    """, bind_vars={'id': id})

    cve = cursor.next()
    if cve:
        return {
            "id": cve["_key"],
            "name": cve["name"],
            "description": cve["Description"],
            "publishedDate": cve["Published Date"],
            "lastModifiedDate": cve["Last Modified Date"]
        }
    else:
        return None

def get_search_cve(limit,page,search):
    if page is None:
        page = 1
    if limit is None:
        limit = 10 

    offset = (page - 1) * limit

    cursor = arango_db.aql.execute("""
    FOR cve IN cve_collection
        FILTER cve.name LIKE @search OR cve.Description LIKE @search OR cve.`Base Metric` LIKE @search
        SORT cve.name ASC
        LIMIT @offset, @limit
        RETURN cve
    """, bind_vars={'search': f"%{search}%", 'limit': limit, 'offset':offset})
    
    if not search:
        cursor = arango_db.aql.execute("""
        FOR cve IN cve_collection
            SORT cve.name ASC
            LIMIT @offset, @limit
            RETURN cve
        """, bind_vars={'limit': limit, 'offset':offset})
    
    cve_list = []
    for cve in cursor:
        cve_list.append({
            "id": cve["_key"],
            "name": cve["name"],
            "description": cve["Description"],
            "publishedDate": cve["Published Date"],
            "lastModifiedDate": cve["Last Modified Date"]
            })

    return cve_list if cve_list else None

def get_metric_by_cve_id(id):
    cursor = arango_db.aql.execute("""
    FOR cve IN cve_collection
        FILTER cve._key == @id
        RETURN cve.`Base Metric`
    """, bind_vars={'id': id})

    metric_data = cursor.next()

    if metric_data:
        formatted_metrics = []
        for metric in metric_data:
            formatted_metrics.append({
                "versionBaseMetric": metric["Version Base Metric"],
                "vectorString": metric["Vector String"],
                "baseScore": metric["Base Score"],
                "baseSeverity": metric["Base Severity"],
                "exploitabilityScore": metric["Exploitability Score"],
                "impactScore": metric["Impact Score"]
            })
        return formatted_metrics

    return []

def get_cwe_by_cve_id(id):
    cursor = arango_db.aql.execute("""
    FOR x IN cve_collection
        FILTER x.name == @id
        FOR v, e, p IN 1..1 OUTBOUND x cve_to_cwe
            RETURN DISTINCT v
    """, bind_vars={'id': id})

    cwe_data = []
    for cwe in cursor:
        cwe_data.append({
            "id": cwe["CWE_ID"],
            "cwe": cwe["CWE_NAME"]
        })

    return cwe_data if cwe_data else None

def get_product_by_cve_id(id):
    cursor = arango_db.aql.execute("""
    FOR x IN cve_collection
    FILTER x._key == @id
    FOR v,e,p IN 1..1 OUTBOUND x cve_to_product
        RETURN DISTINCT MERGE(v, {cve: x._key})
    """, bind_vars={'id': id})

    product_data = []
    for product in cursor:
        product_data.append({
            "id": product["_key"],
            "cve":product["cve"],
            "product": product["product"]
        })

    return product_data if product_data else None

def get_vendor_by_product_id(id):
    cursor = arango_db.aql.execute("""
    FOR x IN product_collection
    FILTER x._key == @id
    FOR v,e,p IN 1..1 INBOUND x vendor_to_product
        RETURN DISTINCT v
    """, bind_vars={'id': id})

    vendor = cursor.next()
    if vendor:
        return {
            "id": vendor["_key"],
            "vendor": vendor["vendor"]
        }
    else:
        return None
    
def get_cpe_by_product_cve_id(cveID,productID):
    cursor = arango_db.aql.execute("""
    FOR x IN cve_collection
        FILTER x.name == @cveID
        FOR v, e, p IN 1..1 OUTBOUND x cve_to_product
            FILTER v._key == @productID
            RETURN e
    """, bind_vars={'cveID': cveID, 'productID':productID})

    cpe = []
    for cpe_data in cursor:
        cpe.append({
        'id': cpe_data['_key'],
        'part': cpe_data['part'],
        'version': cpe_data['version'],
        'update_version': cpe_data['update_version'],
        'edition': cpe_data['edition'],
        'version_start': cpe_data['version_start'],
        'version_end': cpe_data['version_end'],
        'sw_edition': cpe_data['sw_edition'],
        'target': cpe_data['target']
        })

    return cpe if cpe else None

def get_product_by_id(id):
    cursor = arango_db.aql.execute("""
    FOR x IN product_collection
        FILTER x._key == @id
        RETURN x
    """, bind_vars={'id': id})

    product = cursor.next()
    if product:
        return {
            "id": product["_key"],
            "product": product["product"],
        }
    else:
        return None
    
def get_search_product(limit,page,search):
    if page is None:
        page = 1
    if limit is None:
        limit = 10 

    offset = (page - 1) * limit

    cursor = arango_db.aql.execute("""
    FOR product IN product_collection
        FILTER product.product LIKE @search 
        SORT product.product ASC
        LIMIT @offset, @limit
        RETURN product
    """, bind_vars={'search': f"%{search}%", 'limit': limit, 'offset':offset})
    
    if not search:
        cursor = arango_db.aql.execute("""
        FOR product IN product_collection
            SORT product.product ASC
            LIMIT @offset, @limit
            RETURN product
        """, bind_vars={'limit': limit, 'offset':offset})
    
    product_list = []
    for product in cursor:
        product_list.append({
            "id": product["_key"],
            "product": product["product"]
        })

    return product_list if product_list else None

def get_cve_by_product(id):
    cursor = arango_db.aql.execute("""
    FOR x IN product_collection
        FILTER x._key == @id
        FOR v,e,p IN 1..1 INBOUND x cve_to_product
            RETURN DISTINCT MERGE(v, {product: x._key})
    """, bind_vars={'id':id})
    
    cve_data = []
    for cve in cursor:
        cve_data.append({
            "id": cve["_key"],
            "product": cve["product"],
            "name": cve["name"],
            "description": cve["Description"],
            "publishedDate": cve["Published Date"],
            "lastModifiedDate": cve["Last Modified Date"]
        })

    return cve_data if cve_data else None

def get_vendor_by_id (id):
    cursor = arango_db.aql.execute("""
    FOR x IN vendor_collection
        FILTER x._key == @id
        RETURN x
    """, bind_vars={'id': id})

    vendor = cursor.next()
    if vendor:
        return {
            "id": vendor["_key"],
            "vendor": vendor["vendor"]
        }
    else:
        return None
    
def get_product_by_vendor(id):
    cursor = arango_db.aql.execute("""
    FOR x IN vendor_collection
        FILTER x._key == @id
        FOR v,e,p IN 1..1 OUTBOUND x vendor_to_product
            RETURN DISTINCT v
    """, bind_vars={'id':id})
    
    product_list = []
    for product in cursor:
        product_list.append({
            "id": product["_key"],
            "product": product["product"]
        })

    return product_list if product_list else None

def get_search_vendor(limit,page,search):
    if page is None:
        page = 1
    if limit is None:
        limit = 10 

    offset = (page - 1) * limit

    cursor = arango_db.aql.execute("""
    FOR x IN vendor_collection
        FILTER x.vendor LIKE @search 
        SORT x.vendor ASC
        LIMIT @offset, @limit
        RETURN x
    """, bind_vars={'search': f"%{search}%", 'limit': limit, 'offset':offset})
    
    if not search:
        cursor = arango_db.aql.execute("""
        FOR x IN vendor_collection
            SORT x.vendor ASC
            LIMIT @offset, @limit
            RETURN x
        """, bind_vars={'limit': limit, 'offset':offset})
    
    vendor_list = []
    for vendor in cursor:
        vendor_list.append({
            "id": vendor["_key"],
            "vendor": vendor["vendor"]
        })

    return vendor_list if vendor_list else None