curl -v -H "X-Project-Id: 12345" \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/json' \
        -d '{ "name": "RSA Public Key",
              "secret_type": "public",
              "algorithm": "RSA"}' \
        http://127.0.0.1:9311/v1/secrets | python -m json.tool
