# Fish completion for steam-proton-helper
# Copy to ~/.config/fish/completions/

complete -c steam-proton-helper -f

# Options
complete -c steam-proton-helper -s h -l help -d 'Show help message and exit'
complete -c steam-proton-helper -s V -l version -d 'Show version and exit'
complete -c steam-proton-helper -l json -d 'Output results as JSON'
complete -c steam-proton-helper -l no-color -d 'Disable colored output'
complete -c steam-proton-helper -s v -l verbose -d 'Show verbose/debug output'
complete -c steam-proton-helper -l fix -d 'Generate fix script' -r -F
complete -c steam-proton-helper -l apply -d 'Auto-install missing packages'
complete -c steam-proton-helper -l dry-run -d 'Show what --apply would install'
complete -c steam-proton-helper -s y -l yes -d 'Skip confirmation prompt'

# Also complete for the .py script
complete -c steam_proton_helper.py -w steam-proton-helper
