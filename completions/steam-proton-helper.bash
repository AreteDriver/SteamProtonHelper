# Bash completion for steam-proton-helper
# Source this file or copy to /etc/bash_completion.d/

_steam_proton_helper() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # All available options
    opts="--help --version --json --no-color --verbose --fix --apply --dry-run --yes --game --search --list-proton --install-proton --remove-proton --check-updates --update-proton --force -h -V -v -y"

    # Handle options that take arguments
    case "${prev}" in
        --fix)
            # Complete with filenames for --fix
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0
            ;;
        --game|--search)
            # No completion for game name/AppID - user must enter it
            return 0
            ;;
        --install-proton)
            # Suggest common values for --install-proton
            COMPREPLY=( $(compgen -W "list latest" -- "${cur}") )
            return 0
            ;;
        --remove-proton)
            # Suggest 'list' to see removable versions
            COMPREPLY=( $(compgen -W "list" -- "${cur}") )
            return 0
            ;;
    esac

    # Complete options
    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi

    # Default to filename completion for --fix argument
    COMPREPLY=( $(compgen -f -- "${cur}") )
}

complete -F _steam_proton_helper steam-proton-helper
complete -F _steam_proton_helper steam_proton_helper.py
