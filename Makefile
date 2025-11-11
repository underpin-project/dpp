TAG         = $(wildcard *spdx*.tag)
TAG_AS_JSON = $(TAG:%.tag=%.json)
JSON        = $(filter-out $(TAG_AS_JSON), $(wildcard *spdx*.json))
TTL         = $(TAG:%.tag=%.ttl) $(JSON:%.json=%.ttl)

all: $(TTL) ALL-spdx-2.3.zip

echo:
	@echo $(TAG)
	@echo $(JSON)
	@echo $(TTL)

%.ttl: %.tag
	spdx Convert $^ $@ TAG RDFTTL

%.ttl: %.json
	spdx Convert $^ $@ JSON RDFTTL

ALL-spdx-2.3.zip: $(TTL)
	zip $@ $^ 
