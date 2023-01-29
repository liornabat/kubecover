trivy k8s cluster --report all -f json -o hoocus-production.json --timeout 12h
trivy k8s cluster --report all -f json -o hoocus--alias-headers.json --timeout 12h
trivy k8s cluster --report all -f json -o hoocus--design-pack-builder.json --timeout 12h
bq show --schema kubesecops.triviy_raw >trivy_raw_schema.json
bq load --source_format=NEWLINE_DELIMITED_JSON kubesecops.triviy_raw ./hoocus-production-jsonl.txt ./trivy_raw_schema.json
bq load --source_format=NEWLINE_DELIMITED_JSON kubesecops.triviy_raw ./hoocus--alias-headers-jsonl.txt ./trivy_raw_schema.json
bq load --source_format=NEWLINE_DELIMITED_JSON kubesecops.triviy_raw ./hoocus--design-pack-builder-jsonl.txt ./trivy_raw_schema.json
