# vim: foldmethod=marker foldmarker={{{,}}}:
# vim: set ft=just:

set shell := ["bash", "-uc"]

# Justfile Help message {{{

gold:=`tput setaf 3`
reset:=`tput setaf 5`
format:="'%4s"+gold+"%-20s"+reset+"%s\\n' ''"

@default:
    printf "\n"
    tput setaf 5
    echo "Unknown Cyber - Threat Connect Integration"
    tput setaf 4
    echo "-----------------------------"
    just --list | grep -v '^\ *\(Avail.*\|default\)' | xargs -I {} printf {{format}} {}
    printf "\n"

# }}}

# Commands {{{

dev-format:="'%8s"+gold+"%-20s"+reset+"%s\\n' ''"

# Package TC into a .tcx file
package:
    tcex package --output-dir app/
