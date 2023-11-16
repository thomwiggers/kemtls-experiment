#!/bin/bash

# First list already existing files

BUCKET=kemtls

existing_files=$(aws s3 ls s3://$BUCKET/archived-results/ | grep -o ".*data-.*.tar.*")

echo "#!/bin/sh" > ./download.sh

for file in *.tar.*; do
    if [[ ! "${existing_files}" =~ "${file}" ]]; then
        echo "$file not already uploaded"
        aws s3 cp "$file" "s3://$BUCKET/archived-results/"
    else
        echo "$file already exists"
    fi
    echo "wget 'https://kemtls.s3.amazonaws.com/archived-results/$file'" >> ./download.sh
done
