TAG          = $(wildcard *spdx*.tag)
JSON         = $(wildcard *spdx*.json)
TAG_AS_JSON  = $(TAG:%.tag=%.json)
JSON_AS_TAG  = $(JSON:%.json=%.tag)
TAG_MISSING  = $(filter-out $(TAG) , $(JSON_AS_TAG))
JSON_MISSING = $(filter-out $(JSON), $(TAG_AS_JSON))
TTL          = $(JSON:%.json=%.ttl)

ttl: $(TTL) ALL-spdx-2.3.zip

missing: $(TAG_MISSING) $(JSON_MISSING)

echo:
	@echo TAG_MISSING: $(TAG_MISSING)
	@echo JSON_MISSING: $(JSON_MISSING)
	@echo TTL: $(TTL)

%.tag: %.json
	spdx Convert $^ $@ JSON TAG

%.json: %.tag
	spdx Convert $^ $@ TAG JSON

%.ttl: %.json
	spdx Convert $^ $@ JSON RDFTTL

ALL-spdx-2.3.zip: $(TTL)
	zip $@ $^ 
