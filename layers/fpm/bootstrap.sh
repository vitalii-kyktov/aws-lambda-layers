#!/bin/sh

# Fail on error
set -e

# check if the RUNTIME_CLASS is already set
if [ -z "${RUNTIME_CLASS}" ]; then
  export RUNTIME_CLASS="Bref\FpmRuntime\Main"
fi

while true
do
    if [ -z "${EXPERIMENTAL_AWS_LAMBDA_EXEC_WRAPPER}" ]; then
        # Default behavior

        # We redirect stderr to stdout so that everything
        # written on the output ends up in Cloudwatch automatically
        php "/opt/bref/bootstrap.php" 2>&1
    else
        # A wrapper script is configured
        # See https://docs.aws.amazon.com/lambda/latest/dg/runtimes-modify.html#runtime-wrapper
        # NOTE: EXPERIMENTAL FEATURE, DO NOT USE!!!
        # Note: If you do use it, open an issue or GitHub discussion or Slack thread
        # and let us know why it's useful to you, we might turn it into an official feature
        "${EXPERIMENTAL_AWS_LAMBDA_EXEC_WRAPPER}" php "/opt/bref/bootstrap.php" 2>&1
    fi
done
