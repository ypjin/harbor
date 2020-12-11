
# Overview

* Design
  * https://techweb.axway.com/confluence/display/cls/Harbor+1.10.1+Integration

* Tickets
  * https://jira.axway.com/browse/ARS-4435
  * https://jira.axway.com/browse/ARS-4543



# Build docker image for harbor-core

## Build the base image for harbor-core

    make build_base_docker_core -e BASEIMAGETAG=4435

Note: Specify BASEIMAGETAG as appropriate

## Build harbor-core image

    make compile_core
    make build_core -e BASEIMAGETAG=4435 -e VERSIONTAG=3a1d857

## Push harbor-core image

    make pushimage_core -e VERSIONTAG=3a1d857 -e REGISTRYUSER=xxx -e REGISTRYPASSWORD=xxx

Note: You can push it manually.

Note: git commit for the custom build targets: https://github.com/appcelerator/harbor/commit/f4c16ff341edc94f1af4e3b557f051ba1522880e


# Build docker image for harbor-jobservice

## Build the base image for harbor-core

    make build_base_docker_jobservice -e BASEIMAGETAG=4543

Note: Specify BASEIMAGETAG as appropriate

## Build harbor-core image

    make compile_jobservice
    make build_jobservice -e BASEIMAGETAG=4543 -e VERSIONTAG=d3c25c3

## Push harbor-core image

    make pushimage_jobservice -e VERSIONTAG=d3c25c3 -e REGISTRYUSER=xxx -e REGISTRYPASSWORD=xxx

Note: You can push it manually.

Note: git commit for the custom build targets: https://github.com/appcelerator/harbor/commit/7cdd0e1f5dea616e91af08faa318a97ab384a68d
