# UNDERPIN Software DPPs

<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-refresh-toc -->
**Table of Contents**

- [UNDERPIN Software DPPs](#underpin-software-dpps)
- [UNDERPIN Software](#underpin-software)
- [Trivy SPDX 2.3 and Cyclone .6](#trivy-spdx-23-and-cyclone-6)
- [SPDX Tools](#spdx-tools)
- [SPDX Semantic Conversion](#spdx-semantic-conversion)
    - [Makefile](#makefile)
    - [Exploring SPDX RDF](#exploring-spdx-rdf)
    - [SPDX RDF Basic Structure](#spdx-rdf-basic-structure)
- [SPDX Ontology](#spdx-ontology)
- [Sample Queries](#sample-queries)
    - [List all softwares with name, root package, download location](#list-all-softwares-with-name-root-package-download-location)
    - [List softwares with count of packages they contain or depend on](#list-softwares-with-count-of-packages-they-contain-or-depend-on)

<!-- markdown-toc end -->

# UNDERPIN Software
This folder includes sofware DPPs for the following UNDERPIN sofware:
- datavault
- effector
- knowds
- metadata-sync-service
- predictive-analytics-windfarm
- refinery-uc
- semantic-search
- vocabulary-hub

DPPs for more software will be added in the near future, eg GraphDB.

# Trivy SPDX 2.3 and Cyclone .6

The software DPPs were made by [Trivy](https://trivy.dev/) and use the following formats:
- license-report.txt: license report generated from SPDX
- spdx-2.3.tag: [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) plain text (TAG)
- spdx-2.3.json: [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) JSON
- cyclonedx-1.6.json: [CycloneDX 1.6 JSON](https://cyclonedx.org/docs/1.6/json/)

# SPDX Tools

For the operations described below, we use [SPDX tools](https://spdx.dev/use/spdx-tools/):
- For trials and low-volume conversions we can use the [SPDX OnLine Tools](https://tools.spdx.org/app/)
- For automated conversion we used the [SPDX Java Libraries and Tools](https://github.com/spdx/tools-java), [release 2.0.2](https://github.com/spdx/tools-java/releases/tag/v2.0.2) of Oct 2025
  - Unzip `tools-java-2.0.2-jar-with-dependencies.jar` (and optionally add it to your jarpath)
  - Windows: make a batch file `spdx.bat` like this (or a similar shell script on Linux):
```cmd
@echo off
java -jar c:\prog\bin\tools-java-2.0.2-jar-with-dependencies.jar %*
```

The first thing we'll try is verification:
```
spdx Verify semantic-search-spdx-2.3.json > semantic-search-spdx-2.3-err.txt
```
This returns 920 lines of errors (730kB), all of which seem to be due to an incomplete download location (doesn't specify the host):
```
Invalid download location git+app-search-reference-ui-react. 
```

# SPDX Semantic Conversion
We want to convert SPDX to RDF (a knowledge graph) so that we can use SPARQL queries and KG visualization (VizGraph).

SPDX 3.0.1 has a [Semantic Serialization](https://spdx.github.io/spdx-spec/v3.0.1/serializations/). 
It is based on a JSON-LD mapping of the SPDX terms.
Although it is not officially specified for SPDX 2.3, we can use the SPDX `Convert` tool to convert even older 
- Run `spdx Convert --help` for command-line help
- The tool supports the following input/output formats: `JSON, XLS, XLSX, TAG, RDFXML, RDFTTL, YAML, XML JSONLD`
- Normally it recognizes the format from the input/output file name. 
  However, it doesn't recognize `.ttl` (see [spdx/tools-java#252](https://github.com/spdx/tools-java/issues/252)) so we have to provide the input/output formats explicitly

## Makefile
The [Makefile](Makefile) has some neat logic to convert all SPDX files (TAG and JSON) to TTL while preferring TAG:
```make
TAG         = $(wildcard *spdx*.tag)
TAG_AS_JSON = $(TAG:%.tag=%.json)
JSON        = $(filter-out $(TAG_AS_JSON), $(wildcard *spdx*.json))
TTL         = $(TAG:%.tag=%.ttl) $(JSON:%.json=%.ttl)

all: $(TTL)

%.ttl: %.tag
	spdx Convert $^ $@ TAG RDFTTL

%.ttl: %.json
	spdx Convert $^ $@ JSON RDFTTL
```
- The variable `TAG_AS_JSON` takes all `.tag` filenames but renames them to `.json`
- The variable `JSON` takes all `*spdx*.json` files but filters out those that have `.tag` counterparts
- Finally, the variable `TTL` is a union of all `TAG` and `JSON` files, where both extensions are renamed to `.ttl`

To debug this logic, we can run `make echo` to see the names of all input and output files:
```make
echo:
	@echo $(TAG)
	@echo $(JSON)
	@echo $(TTL)
```

Running `make` does the actual conversion:
```
spdx Convert effector-spdx-2.3.tag effector-spdx-2.3.ttl TAG RDFTTL
spdx Convert knowds-spdx-2.3.tag knowds-spdx-2.3.ttl TAG RDFTTL
spdx Convert metadata-sync-service-spdx-2.3.tag metadata-sync-service-spdx-2.3.ttl TAG RDFTTL
spdx Convert predictive-analytics-windfarm-spdx-2.3.tag predictive-analytics-windfarm-spdx-2.3.ttl TAG RDFTTL
spdx Convert refinery-uc-spdx-2.3.tag refinery-uc-spdx-2.3.ttl TAG RDFTTL
spdx Convert datavault-spdx-2.3.json datavault-spdx-2.3.ttl JSON RDFTTL
spdx Convert semantic-search-spdx-2.3.json semantic-search-spdx-2.3.ttl JSON RDFTTL
spdx Convert vocabulary-hub-spdx-2.3.json vocabulary-hub-spdx-2.3.ttl JSON RDFTTL
```

## Exploring SPDX RDF

SPDX describes packages, their licenses and dependencies.
In addition to the root package, most UNDERPIN software includes a bunch of packages:
```
$ grep -c spdx:Package *.ttl
datavault-spdx-2.3.ttl:232
effector-spdx-2.3.ttl:445
knowds-spdx-2.3.ttl:605
metadata-sync-service-spdx-2.3.ttl:352
predictive-analytics-windfarm-spdx-2.3.ttl:913
refinery-uc-spdx-2.3.ttl:1
semantic-search-spdx-2.3.ttl:2626
vocabulary-hub-spdx-2.3.ttl:1
```
So how do we find the root package? It's described in the sole `SpdxDocument` per software:
```
$ grep -c spdx:SpdxDocument *.ttl
datavault-spdx-2.3.ttl:1
effector-spdx-2.3.ttl:1
knowds-spdx-2.3.ttl:1
metadata-sync-service-spdx-2.3.ttl:1
predictive-analytics-windfarm-spdx-2.3.ttl:1
refinery-uc-spdx-2.3.ttl:1
semantic-search-spdx-2.3.ttl:1
vocabulary-hub-spdx-2.3.ttl:1
```

Here is a count of all relation types appearing in our SPDX.
- As you see the root relation is `SpdxDocument-describes-Package`: there's only one per file
- There are also relations between packages: `contains` and `dependsOn`
```
grep -h spdx:relationshipType *.ttl|perl -pe 's{ +}{ }g'|sort|uniq -c
   1417  spdx:relationshipType spdx:relationshipType_contains
   9529  spdx:relationshipType spdx:relationshipType_dependsOn
      8  spdx:relationshipType spdx:relationshipType_describes
```

For easier loading, we concat all individual SPDX files to `ALL-spdx-2.3.zip`.
After loading to GraphDB, we perform a basic exploration of classes and properties:
```sparql
select ?x (count(*) as ?c) {
  {[] a ?x}
  union {[] ?x []}
} group by ?x order by ?x
```
TODO: paste table of results

## SPDX RDF Basic Structure
The structure of the simplest SPDX of UNDERPIN software is like this:
```ttl
BASE <http://trivy.dev/repository/vocabulary-hub-edc-8c610de9-1a27-4c7e-be99-a5f2c6547ddb#>
PREFIX doap: <http://usefulinc.com/ns/doap#>
PREFIX ptr:  <http://www.w3.org/2009/pointers#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX spdx: <http://spdx.org/rdf/terms#>
PREFIX xsd:  <http://www.w3.org/2001/XMLSchema#>


<SPDXRef-DOCUMENT>
        a                  spdx:SpdxDocument;
        spdx:creationInfo  [ a             spdx:CreationInfo;
                             spdx:created  "2025-10-21T10:21:04Z";
                             spdx:creator  "Tool: trivy-0.65.0" , "Organization: aquasecurity"
                           ];
        spdx:dataLicense   <http://spdx.org/licenses/CC0-1.0>;
        spdx:name          "vocabulary-hub-edc";
        spdx:relationship  [ a                        spdx:Relationship;
                             spdx:relatedSpdxElement  <SPDXRef-Repository-2967ac88b3b67da3>;
                             spdx:relationshipType    spdx:relationshipType_describes
                           ];
        spdx:specVersion   "SPDX-2.3" .

<SPDXRef-Repository-2967ac88b3b67da3>
        a                           spdx:Package;
        spdx:annotation             [ a                    spdx:Annotation;
                                      rdfs:comment         "SchemaVersion: 2";
                                      spdx:annotationDate  "2025-10-21T10:21:04Z";
                                      spdx:annotationType  spdx:annotationType_other;
                                      spdx:annotator       "Tool: trivy-0.65.0"
                                    ];
        spdx:downloadLocation       "git+vocabulary-hub-edc";
        spdx:filesAnalyzed          false;
        spdx:name                   "vocabulary-hub-edc";
        spdx:primaryPackagePurpose  spdx:purpose_source .

<http://spdx.org/licenses/CC0-1.0>
        a                             spdx:ListedLicense;
        rdfs:seeAlso                  "https://creativecommons.org/publicdomain/zero/1.0/legalcode";
        spdx:crossRef                 [ a                   spdx:CrossRef;
                                        spdx:isLive         true;
                                        spdx:isValid        true;
                                        spdx:isWayBackLink  false;
                                        spdx:match          "true";
                                        spdx:order          "0"^^xsd:int;
                                        spdx:timestamp      "2025-07-01T14:58:05Z";
                                        spdx:url            "https://creativecommons.org/publicdomain/zero/1.0/legalcode"
                                      ];
        spdx:isDeprecatedLicenseId    false;
        spdx:isFsfLibre               true;
        spdx:isOsiApproved            false;
        spdx:licenseId                "CC0-1.0";
        spdx:licenseName              "Creative Commons Zero v1.0 Universal";
        spdx:licenseText              "Creative Commons Legal Code\n\n...";
        spdx:licenseTextHtml          "\n      <div class=\"optional-license-text\">...";
        spdx:name                     "Creative Commons Zero v1.0 Universal";
        spdx:standardLicenseTemplate  "<<beginOptional>><<beginOptional>>Creative Commons...".
```

# SPDX Ontology
The [SPDX 3.0.1 ontology](https://spdx.org/rdf/3.0.1/spdx-model.ttl) describes SPDX terms and includes SHACL shapes for validating SPDX data.
However, it doesn't fit our purposes since the data model has changed too much from 2.3 to 3.0.1
- Namespace is versioned, eg
```ttl
@prefix ns1: <https://spdx.org/rdf/3.0.1/terms/Core/> .
```
- Namespace is broken up into sub-namespaces: `Core, Security, Sofware, AI, ExpandedLicensing`
  (`spdx:` itself is used only for the ontology record).
  Eg `SpdxDocument, Relationship, RelationshipType` live in `Core` but `Package` lives in `Software`.
- Relationship representation has changed from this:

```ttl
<source> spdx:relationship 
  [a spdx:Relationship;
   spdx:relatedSpdxElement <target>;
   spdx:relationshipType spdx:relationshipType_foo]
```

To this:

```ttl
[] a spdx:Relationship;
   spdx:from <source>;
   spdx:to <target>;
   spdx:relationshipType <Core/RelationshipType/foo>]
```

So for now we don't load and use an ontology.
In the future we may retrofit a SPDX 2.3 ontology by "downgrading" the 3.0.1 ontology.

# Sample Queries
- We load the SPDX ontology
- We also load all DPPs as turlte (`*.ttl`)

## List all softwares with name, root package, download location
```sparql
select ?root ?name ?download {
  ?doc a spdx:SpdxDocument;
     spdx:relationship [spdx:relationshipType spdx:relationshipType_describes; spdx:relatedSpdxElement ?root].
  ?root spdx:name ?name.
  optional {?root spdx:downloadLocation ?download}
}
```

## List softwares with count of packages they contain or depend on
The count of packages is an indication of the complexity of the software:
```sparql
select ?root ?name (count(distinct ?pkg) as ?c) {
  [] spdx:relationshipType spdx:relationshipType_describes; spdx:relatedSpdxElement ?root.
  ?root spdx:name ?name.
    (spdx:relationship/spdx:relatedSpdxElement)+ ?pkg
} group by ?root ?name
```
- The query relies on the fact that out of the root, all relations are either `contains` or `dependsOn`, so we can disregard the relation type
- On the other hand, it's common for a low-level package to be included multiple times through different packages, 
  so we don't just count the number of relations and we take `distinct ?pkg`.
  
