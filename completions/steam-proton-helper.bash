# Bash completion for steam-proton-helper
# Source this file or copy to /etc/bash_completion.d/

_steam_proton_helper() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # All available options
    opts="--help --version --json --no-color --verbose --fix --apply --dry-run --yes --game --search --list-proton --install-proton --remove-proton --check-updates --update-proton --force --recommend --list-games --profile --profile-proton --profile-options --profile-mangohud --profile-gamemode --shader-cache --compatdata --backup-dir --perf-tools --logs --log-lines -h -V -v -y"

    # Handle options that take arguments
    case "${prev}" in
        --fix|--backup-dir)
            # Complete with filenames/directories
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0
            ;;
        --game|--search|--recommend|--profile-proton|--profile-options|--log-lines)
            # No completion - user must enter value
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
        --profile)
            # Profile actions
            COMPREPLY=( $(compgen -W "list get set delete" -- "${cur}") )
            return 0
            ;;
        --shader-cache)
            # Shader cache actions
            COMPREPLY=( $(compgen -W "list clear" -- "${cur}") )
            return 0
            ;;
        --compatdata)
            # Compatdata actions
            COMPREPLY=( $(compgen -W "list backup restore backups" -- "${cur}") )
            return 0
            ;;
        --logs)
            # Log types
            COMPREPLY=( $(compgen -W "all errors steam proton dxvk" -- "${cur}") )
            return 0
            ;;
    esac

    # Complete options
    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi

    # Default to filename completion
    COMPREPLY=( $(compgen -f -- "${cur}") )
}

complete -F _steam_proton_helper steam-proton-helper
complete -F _steam_proton_helper steam_proton_helper.py
