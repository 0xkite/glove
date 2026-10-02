#!/usr/bin/env bash
# docker-entrypoint.sh — container entrypoint for glove dev environment.
#
# Configures cgroup v2 controller delegation when the container is granted
# a private cgroup namespace.
set -e

if [ -d /sys/fs/cgroup ] && [ -w /sys/fs/cgroup ]; then
    if [ -f /sys/fs/cgroup/cgroup.subtree_control ]; then
        for ctrl in cpu memory pids; do
            if grep -qw "$ctrl" /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
                echo "+$ctrl" >/sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
            fi
        done
    fi
fi

exec "$@"
