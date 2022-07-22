# shellcheck shell=sh
# Initialization script for bash, sh, mksh and ksh

case "$(basename $(readlink /proc/$$/exe))" in
*ksh*)
    which_declare=""
    which_opt=""
    ;;
zsh)
    which_declare="typeset -f"
    which_opt=""
    ;;
bash|sh)
    which_declare="declare -f"
    which_opt="-f"
    ;;
*)
    which_declare=""
    which_opt=""
    ;;
esac

which () {
    (alias; eval ${which_declare}) | /usr/bin/which --tty-only --read-alias --read-functions --show-tilde --show-dot $@
}

export which_declare
export ${which_opt} which
