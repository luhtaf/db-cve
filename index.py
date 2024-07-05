from ariadne import load_schema_from_path, make_executable_schema
from ariadne.asgi import GraphQL
from resolver import *

# 1. Memuat Skema GraphQL
type_defs = load_schema_from_path("schema.graphql")

# 2. Membuat Skema Eksekusi
schema = make_executable_schema(type_defs, query, cve, product, vendor)

# 3. Membuat Aplikasi GraphQL ASGI
app = GraphQL(schema, debug=True)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=3000)
