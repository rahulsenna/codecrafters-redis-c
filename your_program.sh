#!/bin/sh
#
# Use this script to run your program LOCALLY.
#
# Note: Changing this script WILL NOT affect how CodeCrafters runs your program.
#
# Learn more: https://codecrafters.io/program-interface

set -e # Exit early if any commands fail

# Copied from .codecrafters/compile.sh
#
# - Edit this to change how your program compiles locally
# - Edit .codecrafters/compile.sh to change how your program compiles remotely
(
  cd "$(dirname "$0")" # Ensure compile steps are run within the repository directory
  /opt/homebrew/bin/gcc-15 -g -o /tmp/codecrafters-build-redis-c /Users/agentofchaos/dev/codecrafters-projects/redis-c/app/server.c
)

# Copied from .codecrafters/run.sh
#
# - Edit this to change how your program runs locally
# - Edit .codecrafters/run.sh to change how your program runs remotely
exec /tmp/codecrafters-build-redis-c "$@"
# exec /Users/agentofchaos/dev/codecrafters-projects/codecrafters-redis-c/build/redis "$@"
# exec osascript -e 'tell application "System Events" to key code 100'
# lldb -o "source list" -o "run"   -- /tmp/codecrafters-build-redis-c "$@"
# exec osascript -e 'tell application "Visual Studio Code" to activate' -e 'tell application "System Events" to key code 100'
# echo "Done Running"


	# import("time")
	# time.Sleep(5 * time.Second)
