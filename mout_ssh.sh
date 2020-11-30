#!/bin/bash

if [[ -d /block/cipher/$USER ]]; then
    ssh-add -l >/dev/null 2>/dev/null
    if [[ $? -eq 0 ]]; then
      mkdir -p $HOME/private
      screen -d -m ssh_mount --volume /block/cipher/$USER unlock --target $HOME/private
    fi
fi
