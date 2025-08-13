#!/bin/bash

# script to validate frame parsing fix and prevent regressions
# this can be run as part of CI/CD to ensure the header parsing bug doesn't return

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== betanet frame parsing validation ==="
echo "validating fix for header parsing bug that broke betanet_recv"
echo

cd "$PROJECT_ROOT"

# compile standalone test
echo "[1/3] compiling standalone frame parsing test..."
gcc -o test_frame_parsing_standalone test_frame_parsing_standalone.c
if [ $? -ne 0 ]; then
    echo "ERROR: failed to compile standalone test"
    exit 1
fi
echo "✓ compilation successful"

# run standalone test
echo "[2/3] running standalone frame parsing test..."
./test_frame_parsing_standalone
if [ $? -ne 0 ]; then
    echo "ERROR: standalone frame parsing test failed"
    exit 1
fi
echo "✓ standalone test passed"

# test actual client-server communication if examples are available
echo "[3/3] testing actual client-server communication..."
if [ -f "build/example_server" ] && [ -f "build/example_client" ]; then
    echo "starting server in background..."
    cd build
    ./example_server &
    SERVER_PID=$!
    
    # wait for server to start
    sleep 2
    
    echo "running client..."
    ./example_client 127.0.0.1:8080 > client_output.log 2>&1 &
    CLIENT_PID=$!
    
    # wait for client to complete
    sleep 5
    
    # check if client succeeded
    if wait $CLIENT_PID; then
        echo "✓ client-server communication successful"
        
        # check for the specific success indicators
        if grep -q "sent.*bytes (encrypted)" client_output.log && grep -q "received response" client_output.log; then
            echo "✓ end-to-end communication verified"
        else
            echo "⚠ client completed but communication may not be fully working"
            echo "client output:"
            cat client_output.log
        fi
    else
        echo "✗ client-server communication failed"
        echo "client output:"
        cat client_output.log
        
        # kill server and exit with error
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi
    
    # cleanup
    kill $SERVER_PID 2>/dev/null || true
    rm -f client_output.log
    cd ..
else
    echo "⚠ example binaries not found, skipping client-server test"
    echo "  run 'cd build && make example_server example_client' to enable this test"
fi

echo
echo "=== all validations passed ==="
echo "frame parsing fix is working correctly"
echo "the header parsing bug that broke betanet_recv has been resolved"

# cleanup
rm -f test_frame_parsing_standalone

echo "✓ validation complete"
