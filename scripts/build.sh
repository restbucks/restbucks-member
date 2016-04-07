#!/usr/bin/env bash -e

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. "$script_dir"/common.sh #use quote here to compliant with space in dir

docker run --rm \
           -t \
           -v "$user_home"/.gradle:/root/.gradle \
           -v "$project_home":/project \
           -w /project \
           -e "BUILD_NUM=$BUILD_NUM" \
           java:8 \
           ./gradlew clean build
