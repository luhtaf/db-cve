import re
from arango import DocumentInsertError
from ariadne import QueryType, ObjectType
from dataloader import *

query = QueryType()
cveID = ObjectType("cveParent")
productChild = ObjectType("productChild")
productParent = ObjectType("productParent")
cveChild = ObjectType("cveChild")
vendorParent = ObjectType("vendorParent")
productVendor = ObjectType("productVendor")

#RESOLVER CVE AS PARENT
@query.field("cveById")
def resolve_cve_by_id(_, info, id):
    return get_cve_by_id(id)

@query.field("searchCve")
def resolve_cve_by_id(_, info, limit=None, page=None, search=None):
    return get_search_cve(limit,page,search)

@cveID.field("cwe")
def resolve_cwe_by_cwe_id(cveParent, info):
    return get_cwe_by_cve_id(cveParent["id"])

@cveID.field("baseMetric")
def resolve_base_metric_by_cve_id(cveParent, info):
    return get_metric_by_cve_id(cveParent["id"])

@cveID.field("product")
def resolve_product_by_cve_id(cveParent, info):
    return get_product_by_cve_id(cveParent["id"])

@productChild.field("vendor")
def resolve_vendor_by_product_id(productChild, info):
    return get_vendor_by_product_id(productChild["id"])

@productChild.field("cpe")
def resolve_cpe_by_product_id(productChild, info):
    return get_cpe_by_product_cve_id(productChild["cve"],productChild["id"])


#RESOLVER PRODUCT AS PARENT
@query.field("productById")
def resolver_product_id(_, info,id):
    return get_product_by_id(id)

@query.field("searchProduct")
def resolver_search_product(_, info, limit=None, page=None, search=None):
    return get_search_product(limit,page,search)

@productParent.field("vendor")
def resolve_vendor_by_product(productParent, info):
    return get_vendor_by_product_id(productParent["id"])

@productParent.field("cve")
def resolve_cve_by_product(productParent, info):
    return get_cve_by_product(productParent["id"])

@cveChild.field("cwe")
def resolve_cwe_by_cwe_id(cveChild, info):
    return get_cwe_by_cve_id(cveChild["id"])

@cveChild.field("baseMetric")
def resolve_base_metric_by_cve_id(cveChild, info):
    return get_metric_by_cve_id(cveChild["id"])

@cveChild.field("cpe")
def resolve_cpe_by_product_id(cveChild, info):
    return get_cpe_by_product_cve_id(cveChild["id"],cveChild["product"])


#RESOLVER VENDOR AS PARENT
@query.field("vendorById")
def resolver_vendor_by_id(_, info, id):
    return get_vendor_by_id(id)

@query.field("searchVendor")
def resolver_vendor_by_id(_, info, limit=None, page=None, search=None):
    return get_search_vendor(limit,page,search)

@vendorParent.field("product")
def resolver_product_by_vendor(vendorParent,info):
    return get_product_by_vendor(vendorParent["id"])

@productVendor.field("cve")
def resolver_cve_by_product(productVendor,info):
    return get_cve_by_product(productVendor["id"])

