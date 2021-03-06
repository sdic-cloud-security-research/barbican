curl -v -H "X-Project-Id: 12345" \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/json' \
        -d '{ "name": "rsa-secret",
              "secret_type": "private",
              "algorithm": "RSA",
              "protected": "RSA:OAEP:76a64c53-4028-4b32-8bab-77e1700f0d2b",
              "inner_encryption": "kpt:AES-128-GCM"}' \
        http://127.0.0.1:9311/v1/secrets | python -m json.tool
