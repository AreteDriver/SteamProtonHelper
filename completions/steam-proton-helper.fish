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
complete -c steam-proton-helper -l game -d 'Check ProtonDB compatibility by name or AppID' -r
complete -c steam-proton-helper -l search -d 'Search Steam for games by name' -r
complete -c steam-proton-helper -l list-proton -d 'List all detected Proton installations'
complete -c steam-proton-helper -l install-proton -d 'Install GE-Proton version' -r -a 'list latest'
complete -c steam-proton-helper -l remove-proton -d 'Remove a custom Proton version' -r -a 'list'
complete -c steam-proton-helper -l check-updates -d 'Check if newer GE-Proton versions are available'
complete -c steam-proton-helper -l update-proton -d 'Update to the latest GE-Proton version'
complete -c steam-proton-helper -l force -d 'Force reinstall if already installed'

# Also complete for the .py script
complete -c steam_proton_helper.py -w steam-proton-helper
