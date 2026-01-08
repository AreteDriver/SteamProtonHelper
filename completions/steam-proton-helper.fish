# Fish completion for steam-proton-helper
# Copy to ~/.config/fish/completions/

complete -c steam-proton-helper -f

# Core options
complete -c steam-proton-helper -s h -l help -d 'Show help message and exit'
complete -c steam-proton-helper -s V -l version -d 'Show version and exit'
complete -c steam-proton-helper -l json -d 'Output results as JSON'
complete -c steam-proton-helper -l no-color -d 'Disable colored output'
complete -c steam-proton-helper -s v -l verbose -d 'Show verbose/debug output'

# Fix & Install
complete -c steam-proton-helper -l fix -d 'Generate fix script' -r -F
complete -c steam-proton-helper -l apply -d 'Auto-install missing packages'
complete -c steam-proton-helper -l dry-run -d 'Show what --apply would install'
complete -c steam-proton-helper -s y -l yes -d 'Skip confirmation prompt'

# ProtonDB & Game Search
complete -c steam-proton-helper -l game -d 'Check ProtonDB compatibility by name or AppID' -r
complete -c steam-proton-helper -l search -d 'Search Steam for games by name' -r
complete -c steam-proton-helper -l recommend -d 'Recommend Proton version for a game' -r
complete -c steam-proton-helper -l list-games -d 'List installed Steam games with Proton versions'

# Proton Management
complete -c steam-proton-helper -l list-proton -d 'List all detected Proton installations'
complete -c steam-proton-helper -l install-proton -d 'Install GE-Proton version' -r -a 'list latest'
complete -c steam-proton-helper -l remove-proton -d 'Remove a custom Proton version' -r -a 'list'
complete -c steam-proton-helper -l check-updates -d 'Check if newer GE-Proton versions are available'
complete -c steam-proton-helper -l update-proton -d 'Update to the latest GE-Proton version'
complete -c steam-proton-helper -l force -d 'Force reinstall if already installed'

# Game Profiles
complete -c steam-proton-helper -l profile -d 'Manage launch profiles' -r -a 'list get set delete'
complete -c steam-proton-helper -l profile-proton -d 'Proton version for profile' -r
complete -c steam-proton-helper -l profile-options -d 'Launch options for profile' -r
complete -c steam-proton-helper -l profile-mangohud -d 'Enable MangoHud for profile'
complete -c steam-proton-helper -l profile-gamemode -d 'Enable GameMode for profile'

# Maintenance
complete -c steam-proton-helper -l shader-cache -d 'Manage shader caches' -r -a 'list clear'
complete -c steam-proton-helper -l compatdata -d 'Manage Wine prefixes' -r -a 'list backup restore backups'
complete -c steam-proton-helper -l backup-dir -d 'Directory for compatdata backups' -r -a '(__fish_complete_directories)'
complete -c steam-proton-helper -l perf-tools -d 'Check status of performance tools'
complete -c steam-proton-helper -l logs -d 'View Steam/Proton logs' -r -a 'all errors steam proton dxvk'
complete -c steam-proton-helper -l log-lines -d 'Number of log entries to show' -r

# Also complete for the .py script
complete -c steam_proton_helper.py -w steam-proton-helper
