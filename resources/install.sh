#!/bin/bash

if ! [[ -f ~/.bash_completion ]]; then
	echo '[+] Creating local completion script ~/.bash_completion'
	cp ./bash_completion ~/.bash_completion
fi

if ! [[ -d ~/.bash_completion.d ]]; then
	echo '[+] Creating local completion folder ~/.bash_completion.d'
	mkdir ~/.bash_completion.d
fi

if ! [[ -f ~/.bash_completion.d/jmx-exploiter ]]; then
	echo '[+] Creating jmx-exploiter completion script ~/.bash_completion.d/jmx-exploiter'
	cp ./bash_completion.d/jmx-exploiter ~/.bash_completion.d/jmx-exploiter
fi

if ! [[ -d ~/.local/bin ]]; then
	echo '[+] Creating local bin folder ~/.local/bin'
	mkdir -p ~/.local/bin
fi

if ! [[ -f ~/.local/bin/jmx-exploiter ]]; then
	echo '[+] Creating symlink for jmx-exploiter'
	path="$(dirname $(pwd))/target/jmx-exploiter.jar"

	if ! [[ -f $path ]]; then
		echo "[-] jmx-exploiter.jar not found at $path"
	else
		chmod +x $path
		ln -s $path ~/.local/bin/jmx-exploiter
	fi
fi
