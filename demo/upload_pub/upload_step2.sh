ref=$1

curl -v -X PUT -H "X-Project-Id: 12345" \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/octet-stream' \
        --data-binary @rsa_pub.pem \
        http://127.0.0.1:9311/v1/secrets/$ref
