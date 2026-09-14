#!/bin/bash

echo
mkdir -p files/gstatic/v3
wget -nv -N https://www.gstatic.com/ct/log_list/v3/all_logs_list.json
if [ $? -eq 0 ]; then
  wget -nv -N https://www.gstatic.com/ct/log_list/v3/all_logs_list.sig
  if [ $? -eq 0 ]; then
    openssl pkeyutl -verify -rawin -pubin -inkey files/gstatic/log_list_pubkey.pem -in all_logs_list.json -sigfile all_logs_list.sig
    if [ $? -eq 0 ]; then
      mv all_logs_list.json files/gstatic/v3/all_logs_list.json
      mv all_logs_list.sig files/gstatic/v3/all_logs_list.sig
    else
      echo "Signature verification failed for https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
    fi
  else
    echo "Failed to download signature file"
  fi
else
  echo "Failed to download log list"
fi

echo
mkdir -p files/apple
wget -nv -N https://valid.apple.com/ct/log_list/current_log_list.json
if [ $? -eq 0 ]; then
  mv current_log_list.json files/apple/current_log_list.json
else
  echo "Failed to download log list"
fi

echo
mkdir -p files/crtsh/v3/all
wget -nv -N http://crt.sh/v3/logs.json?include=all
if [ $? -eq 0 ]; then
  mv "logs.json?include=all" files/crtsh/v3/all/all_logs_list.json
else
  echo "Failed to download log list"
fi

echo
mkdir -p files/crtsh/v3/active
wget -nv -N http://crt.sh/v3/logs.json?include=active
if [ $? -eq 0 ]; then
  mv "logs.json?include=active" files/crtsh/v3/active/active_logs_list.json
else
  echo "Failed to download log list"
fi

echo
cmd/mozillactknownlogs/check_for_ctknownlogs_changes.sh

echo
