ref=$1
file=$2

curl -v -H "X-Project-Id: 12345" \
        -H 'Accept: application/octet-stream' \
        -o $file \
        http://127.0.0.1:9311/v1/secrets/$ref/payload
