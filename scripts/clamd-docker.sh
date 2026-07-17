#!/usr/bin/env bash
# Start or stop clamd inside Docker (clamav/clamav-debian) for diff testing.
#
# Usage:
#   scripts/clamd-docker.sh start   # start clamd in a container
#   scripts/clamd-docker.sh stop    # stop and remove the container
#   scripts/clamd-docker.sh status  # check if running
#
# The container uses host networking so clamdscan (on the host) can reach the
# clamd socket.  The socket itself lives on a host-mounted directory so both
# sides see the same file.
set -eu

IMAGE="clamav/clamav-debian:latest"
CONTAINER="clamd-diff"
DBDIR="${DBDIR:-/tmp/difdb_daily}"
SOCK_DIR="${SOCK_DIR:-/tmp/clamd_sock}"   # shared host dir for the socket
SOCK="${SOCK_DIR}/clamd.sock"
CONF="/tmp/clamd_docker.conf"
MEMORY="${MEMORY:-3g}"

usage() { echo "usage: $0 {start|stop|status}" >&2; exit 1; }
[ $# -ge 1 ] || usage

cmd_start() {
  if docker inspect "$CONTAINER" &>/dev/null; then
    echo "container '$CONTAINER' already exists (docker rm -f $CONTAINER to remove)"
    docker start "$CONTAINER" 2>/dev/null || true
    wait_for_socket
    return
  fi

  # Write clamd config — the container will see this path via mount.
  mkdir -p "$SOCK_DIR"
  cat > "$CONF" <<CONF
DatabaseDirectory /var/lib/clamav
LocalSocket /tmp/clamd.sock
LocalSocketMode 666
Foreground yes
MaxThreads 4
MaxScanSize 2000M
MaxFileSize 2000M
CONF

  # Run clamd directly (override the entrypoint) so the image's freshclam does
  # NOT download extra databases into $DBDIR — clamd loads only what we mounted,
  # keeping the DB set identical to exav's for a valid comparison.
  docker run -d \
    --name "$CONTAINER" \
    --network=host \
    --entrypoint clamd \
    -v "$DBDIR":/var/lib/clamav \
    -v "$SOCK_DIR":/tmp \
    -v "$CONF":/etc/clamav/clamd.conf:ro \
    --memory="$MEMORY" \
    "$IMAGE" --foreground --config-file=/etc/clamav/clamd.conf >/dev/null

  wait_for_socket

  # Write a clamdscan client config that points to the real socket, at the path
  # test-clamav-diff.sh expects ($CCONF defaults to /tmp/clamd_daily.conf).
  cat > /tmp/clamd_daily.conf <<CLIENTCONF
LocalSocket $SOCK
CLIENTCONF
  echo "clamdscan config written to /tmp/clamd_daily.conf"
}

wait_for_socket() {
  echo -n "waiting for clamd socket "
  for i in $(seq 1 60); do
    if [ -S "$SOCK" ]; then
      echo " ready (${i}s)"
      return 0
    fi
    # Check container is still alive
    if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
      echo " FAILED — container exited"
      docker logs "$CONTAINER" 2>&1 | tail -20
      return 1
    fi
    sleep 2
  done
  echo " TIMEOUT (60s)"
  docker logs "$CONTAINER" 2>&1 | tail -20
  return 1
}

cmd_stop() {
  docker rm -f "$CONTAINER" 2>/dev/null || true
  rm -f "$SOCK" 2>/dev/null || true
  echo "clamd container stopped and removed"
}

cmd_status() {
  if docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
    echo "running (pid $(docker inspect -f '{{.State.Pid}}' "$CONTAINER"))"
    [ -S "$SOCK" ] && echo "socket: $SOCK (ready)" || echo "socket: $SOCK (missing)"
  else
    echo "not running"
  fi
}

case "$1" in
  start)  cmd_start  ;;
  stop)   cmd_stop   ;;
  status) cmd_status ;;
  *)      usage      ;;
esac
