# ======================================================================
# lib/util/model.sh — Pi model helpers
#
# Consolidates the scattered `*raspberry pi 500*` / `*raspberry pi 400*`
# string checks so tasks ask a single question.
#
# Functions: pi_is_generation, is_pi5, is_pi500, is_pi4, is_pi400,
#            is_pi3, is_pizero2, pi_supports_kms_overlays,
#            pi_supports_eeprom
# Globals (read): SYSTEM_PI_GEN, SYSTEM_MODEL
# ======================================================================

# Convenience helper to compare detected Pi generation.
pi_is_generation() {
  local target=$1
  [[ ${SYSTEM_PI_GEN:-unknown} == "$target" ]]
}

# Pi 5 / Pi 500 (generation 5 covers both).
is_pi5() {
  pi_is_generation 5
}

# Pi 500 specifically (the keyboard-form-factor Pi 5).
is_pi500() {
  local lower=${SYSTEM_MODEL,,}
  [[ $lower == *"raspberry pi 500"* ]]
}

# Pi 4 or Pi 400 (generation 4 covers both).
is_pi4() {
  pi_is_generation 4
}

# Pi 400 specifically (the keyboard-form-factor Pi 4).
is_pi400() {
  local lower=${SYSTEM_MODEL,,}
  [[ $lower == *"raspberry pi 400"* ]]
}

is_pi3() {
  pi_is_generation 3
}

is_pizero2() {
  pi_is_generation zero2
}

# Determine if display KMS tweaks are applicable (Pi 4/5).
pi_supports_kms_overlays() {
  case ${SYSTEM_PI_GEN:-unknown} in
    4|5) return 0 ;;
    *)   return 1 ;;
  esac
}

