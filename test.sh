#!/bin/sh

run_command() {
    pw_gen="$1"
    command="$2"
    expected_output="$3"
    output=$($pw_gen $command 2>/dev/null)
    if [ "$output" != "$expected_output" ]; then
        echo "Test to fail: $command"
        echo "expected output: $expected_output"
        echo "actual output: $output"
        exit 1
    fi
}

if [ -z "$1" ]; then
    echo "no command path"
    exit 1
fi

pw_gen="$1"

run_command "$pw_gen" "tEsT@x KeY -a sha256 -l 32 -c none" "ZjQwMTVhNDM2MDQ4Y2IyNWEwNDUxMTI4"
run_command "$pw_gen" "tEsT@x KeY -a sha256 -l 32 -c lower" "MjRjODRkNzYzMmJhZTFjZWNjZDgzNzI4"
run_command "$pw_gen" "tEsT@x KeY -a sha256 -l 32 -c upper" "OTU0OWU2YjdjMjE0MjlkMjY0NDk5NGEx"
run_command "$pw_gen" "tEsT@x KeY -a sha512 -l 32 -c none" "MDViZjYyZDRkNDE3NzBkOGUwOWJkZjBl"
run_command "$pw_gen" "tEsT@x KeY -a sha512 -l 32 -c lower" "NTNiZTE5NGNjYjg1ZGNlNDJiNDZiOTUz"
run_command "$pw_gen" "tEsT@x KeY -a sha512 -l 32 -c upper" "MmI1MzIxODc5NmViYTU0NmZkODFlNmYx"

echo "ovo"
