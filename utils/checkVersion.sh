#!/bin/bash

GIT_TAG=$(git tag)
REPO_VERSION=$(git tag | tr -d "v" | grep "${VERSION}")

if [[ -z "${VERSION}" ]];then
    echo "Abort Version is null !!!!!!"
    echo "Add version in package.json"
    exit 1
fi

if [[ ! -z "${REPO_VERSION}" ]] && [[ ! -z "${GIT_TAG}" ]] && [[ "${VERSION}" == "${REPO_VERSION}"  ]];then
    echo "Abort Version: ${VERSION} exist !!!!!!"
    echo "Change version in package.json"
    exit 1
fi