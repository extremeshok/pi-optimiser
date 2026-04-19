# Integration-test harness for pi-optimiser.
#
# The goal is "runs end-to-end code paths on a real filesystem" without
# needing actual Pi hardware. We ship stubs for the Pi-specific
# binaries (vcgencmd, rpi-eeprom-*, rpi-update) so the runtime can
# reach preconditions and config-edit helpers without erroring out.
#
# Tests assume --dry-run / --diff / --self-test semantics — no
# destructive commands should run inside the container.
FROM debian:trixie-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      bash python3 coreutils util-linux tar curl ca-certificates \
      inotify-tools whiptail procps openssh-client diffutils \
      shellcheck git sed grep \
 && rm -rf /var/lib/apt/lists/*

# Stubs for Pi-specific binaries that tasks probe with `command -v`.
COPY tests/docker/stubs/ /usr/local/bin/
RUN chmod +x /usr/local/bin/vcgencmd \
             /usr/local/bin/rpi-eeprom-config \
             /usr/local/bin/rpi-update \
             /usr/local/bin/rpi-eeprom-update

# Fake /boot/firmware so config.txt / cmdline.txt edits have a target.
RUN mkdir -p /boot/firmware /var/log /etc/pi-optimiser \
 && printf '# pi-optimiser test fixture\narm_boost=1\ndtparam=audio=on\n' > /boot/firmware/config.txt \
 && printf 'console=serial0,115200 console=tty1 root=PARTUUID=abc rootwait\n' > /boot/firmware/cmdline.txt

WORKDIR /opt/pi-optimiser
COPY . /opt/pi-optimiser
RUN chmod +x pi-optimiser.sh scripts/build-bundle.sh tests/docker/run-tests.sh

ENTRYPOINT ["/bin/bash"]
CMD ["tests/docker/run-tests.sh"]
