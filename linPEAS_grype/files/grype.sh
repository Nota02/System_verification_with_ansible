#!/bin/bash
docker pull anchore/grype:v0.38.0
docker run --rm anchore/grype:v0.38.0 -o json python:slim > grype.json
