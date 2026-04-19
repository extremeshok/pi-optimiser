# ======================================================================
# lib/util/fstab.sh — /etc/fstab helpers
#
# Functions: fstab_append_line, fstab_root_has_option
# ======================================================================

# Return success when /etc/fstab's root entry already declares an option.
# Matches option names as comma-delimited tokens in the 4th mount column.
fstab_root_has_option() {
  local opt=$1
  grep -E "^[[:space:]]*[^#[:space:]]+[[:space:]]+/[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]*${opt}([,[:space:]]|$)" /etc/fstab >/dev/null
}

# Append a complete fstab entry if not already present.
# Matches on the MNT (2nd column) to avoid duplicate mountpoints.
fstab_append_line() {
  local line=$1
  local mount
  mount=$(awk '{print $2}' <<<"$line")
  if grep -E "^[[:space:]]*[^#[:space:]]+[[:space:]]+${mount}[[:space:]]+" /etc/fstab >/dev/null 2>&1; then
    return 1
  fi
  echo "$line" >> /etc/fstab
  return 0
}
