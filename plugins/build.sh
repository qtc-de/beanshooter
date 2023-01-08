#!/bin/bash

# This build script only works for simple plugins that consist our of a single file.
# It is just an example to demonstrate the general plugin structure.

if [[ $# -lt 3 ]]; then
    echo "${0} <BEANSHOOTER-FILE> <PLUGIN-FILE> <OUTPUT>"
    exit 1
fi

set -e

TEMP=$(mktemp -d)
SOURCE="${TEMP}/${2}"
COMPILED="${TEMP}/comp/"
MANIFEST="${TEMP}/MANIFEST.MF"

mkdir "${COMPILED}"
cp "${2}" "${SOURCE}"

javac -cp "${1}" -d "${COMPILED}" "${SOURCE}"
CLASSNAME=$(find "${COMPILED}" -type f | grep ${2%.java} | sed "s@${COMPILED}@@" | sed "s@/@.@g")
echo "BeanshooterPluginClass: ${CLASSNAME%.class}" > "${MANIFEST}"
jar -cfm "${3}" "${MANIFEST}" -C "${COMPILED}" .

rm -r "${TEMP}"
