from ariadne import load_schema_from_path, make_executable_schema
from ariadne.asgi import GraphQL
from resolver import *

# 1. Memuat Skema GraphQL
type_defs = load_schema_from_path("schema.graphql")

# 2. Membuat Skema Eksekusi
<<<<<<< HEAD
schema = make_executable_schema(type_defs, query, cve, product, vendor)
=======
schema = make_executable_schema(type_defs, query, cveID, productChild, 
                                productParent, cveChild, vendorParent, productVendor)
>>>>>>> 0918d02fbc8289cbd198688e6f6a5187bf561170

# 3. Membuat Aplikasi GraphQL ASGI
app = GraphQL(schema, debug=True)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=3000)
