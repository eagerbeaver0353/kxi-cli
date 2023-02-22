#!/usr/bin/env bash

# Runs pytest and coverage to output test metrics
# Argument can be either unit / integration
#  - Affects naming of the files generated by coverage
#  - Affects whether the tests/integration folder is included / excluded

main(){
    # store coverage data for combining later on
    data_file=".coverage.$1"
    # store junit xml results
    report="report.$1.xml"
    # store coverage xml results
    coverage_xml="coverage.$1.xml"

    pytest_arg="tests/integration"
    if [[ "$1" == "unit" ]]
    then
        pytest_arg="--ignore=$pytest_arg"
    elif [[ "$1" != "integration" ]]
    then
        echo "Error: Expected with 'unit' or 'integration' as an argument'"
        exit 1
    fi

    coverage run --data-file="$data_file" -m pytest --junitxml="$report" $pytest_arg || exit 1
    coverage report --data-file="$data_file"
    coverage html --data-file="$data_file"
    coverage xml --data-file="$data_file" -o "$coverage_xml"
    }

main "$@"
