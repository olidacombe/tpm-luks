#!/bin/bash

set -xeuo pipefail

#curl -X GET \
#-H "Content-Type: application/json" \
#-H "X-Auth-Token: <fillme> \
#"https://api.equinix.com/metal/v1/operating-systems"

hw_id="$1"
project=${PROJECT:-"c4cb8ea2-12aa-4dc4-ad8d-aa559aafe7d5"}

curl -X POST \
-H "Content-Type: application/json" \
-H "X-Auth-Token: $(mvault internal kv get -field=auth-token kv/equinix/metal)" \
"https://api.equinix.com/metal/v1/projects/${project}/devices" \
-d "{
  \"hardware_reservation_id\":\"${hw_id}\",
  \"hostname\": \"tipi\",
  \"operating_system\": \"ubuntu_22_04\",
  \"storage\": {
  \"disks\": [
    {
      \"device\": \"/dev/sda\",
      \"wipeTable\": true,
      \"partitions\": [
        {
          \"label\": \"BIOS\",
          \"number\": 1,
          \"size\": \"512M\"
        },
        {
          \"label\": \"SWAP\",
          \"number\": 2,
          \"size\": \"3993600\"
        },
        {
          \"label\": \"ROOT\",
          \"number\": 3,
          \"size\": 0
        }
      ]
    }
  ],
  \"filesystems\": [
    {
      \"mount\": {
        \"device\": \"/dev/sda1\",
        \"format\": \"vfat\",
        \"point\": \"/boot/efi\",
        \"create\": {
          \"options\": [
            \"32\",
            \"-n\",
            \"EFI\"
          ]
        }
      }
    },
    {
      \"mount\": {
        \"device\": \"/dev/sda3\",
        \"format\": \"ext4\",
        \"point\": \"/\",
        \"create\": {
          \"options\": [
            \"-L\",
            \"ROOT\"
          ]
        }
      }
    },
    {
      \"mount\": {
        \"device\": \"/dev/sda2\",
        \"format\": \"swap\",
        \"point\": \"none\",
        \"create\": {
          \"options\": [
            \"-L\",
            \"SWAP\"
          ]
        }
      }
    }
  ]
}
  }"
